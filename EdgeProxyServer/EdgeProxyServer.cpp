#include "EdgeProxyServer.h"
#include <iostream>
#include <fstream>
#include <cstdlib>
#include <stdexcept>
#include <algorithm>

// ==========================================
// 1. UTILITÁRIOS E CONFIGURAÇÃO
// ==========================================

void Logger::Info(const std::string& msg)
{
    std::cout << "[INFO] " << msg << std::endl;
}

void Logger::Error(const std::string& msg)
{
    std::cerr << "[ERRO] " << msg << std::endl;
}

void Logger::Debug(const std::string& msg)
{
    std::cout << "[DEBUG] " << msg << std::endl;
}

void Config::LoadFromEnvironment()
{
    const char* envKey = std::getenv("OPENAI_API_KEY");

    if (!envKey)
        throw std::runtime_error("OPENAI_API_KEY nao configurada no ambiente!");

    _apiKey = envKey;

    const char* envPort = std::getenv("PROXY_PORT");
    _port = envPort ? std::stoi(envPort) : 8080;

    const char* tempDir = std::getenv("TEMP");
    _vaultPath = tempDir ? std::string(tempDir) + "\\ip_vault_map.json" : "C:\\Temp\\ip_vault_map.json";
}

// ==========================================
// 2. DOMÍNIO: GERENCIAMENTO DE IP (VAULT)
// ==========================================

void IpVault::LoadFromFile(const std::string& filepath)
{
    std::ifstream file(filepath);

    if (!file.is_open())
    {
        Logger::Error("Vault JSON nao encontrado em: " + filepath);
        return;
    }

    nlohmann::json j;
    file >> j;

    for (auto& item : j.items())
    {
        _realToMask[item.key()] = item.value();
        _maskToReal[item.value()] = item.key();
        _sortedRealKeys.push_back(item.key());
        _sortedMaskKeys.push_back(item.value());
    }

    auto sortByLengthDesc = [](const std::string& a, const std::string& b)
        {
            return a.length() > b.length();
        };

    std::sort(_sortedRealKeys.begin(), _sortedRealKeys.end(), sortByLengthDesc);
    std::sort(_sortedMaskKeys.begin(), _sortedMaskKeys.end(), sortByLengthDesc);

    Logger::Info("Vault carregado. Total de entidades protegidas: " + std::to_string(_realToMask.size()));
}

// ==========================================
// 3. CORE: MOTOR DE SANITIZAÇÃO
// ==========================================

void Sanitizer::InitializeRules(const IpVault& vault)
{
    for (const std::string& realName : vault.GetSortedRealKeys())
        _sanitizeRules.push_back({ std::regex("\\b" + realName + "\\b"), vault.GetMasked(realName) });

    for (const std::string& maskName : vault.GetSortedMaskKeys())
        _restoreRules.push_back({ std::regex("\\b" + maskName + "\\b"), vault.GetReal(maskName) });
}

std::string Sanitizer::SanitizeString(const std::string& text) const
{
    std::string result = text;

    for (const auto& rule : _sanitizeRules)
        result = std::regex_replace(result, rule.pattern, rule.replacement);

    return result;
}

std::string Sanitizer::RestoreString(const std::string& text) const
{
    std::string result = text;

    for (const auto& rule : _restoreRules)
        result = std::regex_replace(result, rule.pattern, rule.replacement);

    return result;
}

void Sanitizer::SanitizeJsonPayload(nlohmann::json& payload) const
{
    if (payload.contains("messages") && payload["messages"].is_array())
    {
        for (auto& msg : payload["messages"])
        {
            if (msg.contains("content") && msg["content"].is_string())
                msg["content"] = SanitizeString(msg["content"].get<std::string>());

            if (msg.contains("tool_calls") && msg["tool_calls"].is_array())
            {
                for (auto& tool : msg["tool_calls"])
                {
                    if (tool.contains("function") && tool["function"].contains("arguments") && tool["function"]["arguments"].is_string())
                        tool["function"]["arguments"] = SanitizeString(tool["function"]["arguments"].get<std::string>());
                }
            }
        }
    }
}

void Sanitizer::RestoreJsonPayload(nlohmann::json& payload) const
{
    if (payload.contains("choices") && payload["choices"].is_array())
    {
        for (auto& choice : payload["choices"])
        {
            if (choice.contains("message"))
            {
                if (choice["message"].contains("content") && choice["message"]["content"].is_string())
                    choice["message"]["content"] = RestoreString(choice["message"]["content"].get<std::string>());

                if (choice["message"].contains("tool_calls") && choice["message"]["tool_calls"].is_array())
                {
                    for (auto& tool : choice["message"]["tool_calls"])
                    {
                        if (tool.contains("function") && tool["function"].contains("arguments") && tool["function"]["arguments"].is_string())
                            tool["function"]["arguments"] = RestoreString(tool["function"]["arguments"].get<std::string>());
                    }
                }
            }
        }
    }
}

// ==========================================
// 4. INFRAESTRUTURA: CLIENTE LLM E HANDLER
// ==========================================

OpenAiClient::OpenAiClient(const std::string& key) : _apiKey(key) {}

httplib::Result OpenAiClient::PostChatCompletion(const std::string& jsonBody) const
{
    httplib::SSLClient cli(_host);
    cli.set_bearer_token_auth(_apiKey);
    cli.set_read_timeout(120);

    // O GitHub Models atende na raiz do chat/completions (sem o /v1)
    return cli.Post("/chat/completions", jsonBody, "application/json");
}

CompletionHandler::CompletionHandler(const Sanitizer& s, const OpenAiClient& c) : _sanitizer(s), _llmClient(c) {}

std::string CompletionHandler::ReadAndSanitize(const httplib::Request& req) const
{
    nlohmann::json reqJson = nlohmann::json::parse(req.body);
    _sanitizer.SanitizeJsonPayload(reqJson);

    return reqJson.dump();
}

httplib::Result CompletionHandler::CommunicateWithCloud(const std::string& safePayload) const
{
    Logger::Debug("Enviando Payload seguro para nuvem...");

    return _llmClient.PostChatCompletion(safePayload);
}

void CompletionHandler::RestoreAndRespond(httplib::Result& apiRes, httplib::Response& res) const
{
    if (!apiRes)
    {
        Logger::Error("Falha de rede ao contatar OpenAI.");
        res.status = 502;
        res.set_content(R"({"error": "Falha no Upstream LLM"})", "application/json");
        return;
    }

    if (apiRes->status != 200)
    {
        Logger::Error("Erro da OpenAI API: HTTP " + std::to_string(apiRes->status));
        res.status = apiRes->status;
        res.set_content(apiRes->body, "application/json");
        return;
    }

    nlohmann::json resJson = nlohmann::json::parse(apiRes->body);
    _sanitizer.RestoreJsonPayload(resJson);

    res.status = 200;
    res.set_content(resJson.dump(), "application/json");
    Logger::Info("<- Resposta restaurada (Proxy -> Copilot)");
}

void CompletionHandler::HandleRequest(const httplib::Request& req, httplib::Response& res) const
{
    Logger::Info("-> Requisicao interceptada (Copilot -> Proxy)");

    try
    {
        std::string safePayload = ReadAndSanitize(req);
        auto apiRes = CommunicateWithCloud(safePayload);
        RestoreAndRespond(apiRes, res);
    }
    catch (const nlohmann::json::exception& e)
    {
        Logger::Error("Erro de Parser JSON: " + std::string(e.what()));
        res.status = 400;
        res.set_content(R"({"error": "JSON Invalido"})", "application/json");
    }
    catch (const std::exception& e)
    {
        Logger::Error("Erro Interno: " + std::string(e.what()));
        res.status = 500;
    }
}

// ==========================================
// 5. BOOTSTRAP: SERVIDOR APP
// ==========================================

ServerApp::ServerApp(int p, const CompletionHandler& handler) : _port(p)
{
    _svr.Post("/v1/chat/completions", [&handler](const httplib::Request& req, httplib::Response& res)
        {
            handler.HandleRequest(req, res);
        });
}

void ServerApp::Start()
{
    Logger::Info("Middleware Zero-Trust ativo e escutando na porta " + std::to_string(_port));
    _svr.listen("127.0.0.1", _port);
}

// ==========================================
// 6. ENTRY POINT
// ==========================================

int main()
{
    try
    {
        Config config;
        config.LoadFromEnvironment();

        IpVault vault;
        vault.LoadFromFile(config.GetVaultPath());

        Sanitizer sanitizer;
        sanitizer.InitializeRules(vault);

        OpenAiClient llmClient(config.GetApiKey());

        CompletionHandler handler(sanitizer, llmClient);

        ServerApp app(config.GetPort(), handler);
        app.Start();
    }
    catch (const std::exception& e)
    {
        Logger::Error("Falha critica na inicializacao: " + std::string(e.what()));
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}