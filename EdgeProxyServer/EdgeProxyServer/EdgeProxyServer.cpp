#define CPPHTTPLIB_OPENSSL_SUPPORT
#include "EdgeProxyServer.h"
#include <iostream>
#include <fstream>
#include <cstdlib>
#include <stdexcept>
#include <algorithm>
#include <thread>
#include <chrono>
#include <mutex>
#include <sstream>
#include <ctime>
#include <iomanip>

namespace {
  std::mutex g_logMutex;

  std::string func_token33(std::string value)
  {
    std::transform(value.begin(), value.end(), value.begin(), [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return value;
  }

  bool func_token34(const std::string& headerNameLower)
  {
    // Hop-by-hop or reconstructed headers that should not be forwarded manually.
    return headerNameLower == "host" ||
      headerNameLower == "content-length" ||
      headerNameLower == "accept-encoding" ||
      headerNameLower == "transfer-encoding" ||
      headerNameLower == "connection";
  }

  bool func_token35(const std::string& headerNameLower)
  {
    // Security/protocol-sensitive headers: keep values untouched.
    return headerNameLower == "authorization" ||
      headerNameLower == "proxy-authorization" ||
      headerNameLower == "cookie" ||
      headerNameLower == "set-cookie" ||
      headerNameLower == "content-type" ||
      headerNameLower == "content-length" ||
      headerNameLower == "content-encoding" ||
      headerNameLower == "user-agent";
  }

  bool func_token_is_regex(const std::string& s) {
    const std::string regexChars = R"(\[]{}()*+?.^$|)";
    for (char c : s) {
      if (regexChars.find(c) != std::string::npos) return true;
    }
    return false;
  }

  std::string func_token36(const std::string& input)
  {
    std::string result;
    const std::string specialChars = R"(\[]{}()*+?.^$|)";
    for (char c : input) {
      if (specialChars.find(c) != std::string::npos) {
        result += '\\';
      }
      result += c;
    }
    return result;
  }

  std::string func_token30()
  {
    const auto now = std::chrono::system_clock::now();
    const std::time_t nowTime = std::chrono::system_clock::to_time_t(now);
    std::tm localTm{};
    localtime_s(&localTm, &nowTime);
    std::ostringstream oss;
    oss << std::put_time(&localTm, "%Y-%m-%d %H:%M:%S");
    return oss.str();
  }

  std::string func_token31()
  {
    const char* envLogPath = std::getenv("PROXY_LOG_PATH");
    if (envLogPath && *envLogPath) return envLogPath;

    const char* tempDir = std::getenv("TEMP");
    return tempDir ? std::string(tempDir) + "\\copilot_proxy_traffic.log" : "C:\\Temp\\copilot_proxy_traffic.log";
  }

  void func_token32(const std::string& section, const std::string& method, const std::string& path, const std::string& content)
  {
    std::lock_guard<std::mutex> lock(g_logMutex);
    std::ofstream out(func_token31(), std::ios::app);
    if (!out.is_open()) return;

    out << "===== [" << func_token30() << "] " << section << " =====\n";
    out << "METHOD: " << method << "\n";
    out << "PATH: " << path << "\n";
    out << "CONTENT:\n";
    out << (content.empty() ? "<empty>" : content) << "\n\n";
  }
}

// ==========================================
// 1. UTILITÁRIOS E CONFIGURAÇÃO
// ==========================================

void Logger::Info(const std::string& msg) { std::cout << "[INFO] " << msg << std::endl; }
void Logger::Error(const std::string& msg) { std::cerr << "[ERRO] " << msg << std::endl; }
void Logger::Debug(const std::string& msg) { std::cout << "[DEBUG] " << msg << std::endl; }

void Config::LoadFromEnvironment()
{
  const char* envKey = std::getenv("OPENAI_API_KEY");
  if (!envKey) throw std::runtime_error("OPENAI_API_KEY (Token GitHub) nao configurada!");
  _apiKey = envKey;

  const char* envPort = std::getenv("PROXY_PORT");
  _port = envPort ? std::stoi(envPort) : 8080;

  const char* tempDir = std::getenv("TEMP");
  _vaultPath = tempDir ? std::string(tempDir) + "\\ip_vault_map.json" : "C:\\Temp\\ip_vault_map.json";

  const char* envModel = std::getenv("TARGET_MODEL");
  _targetModel = (envModel && *envModel) ? envModel : "";
}

// ==========================================
// 2. DOMÍNIO: GERENCIAMENTO DE IP (VAULT)
// ==========================================

void IpVault::LoadFromFile(const std::string& filepath)
{
  std::ifstream file(filepath);
  if (!file.is_open()) { Logger::Error("Vault nao encontrado em: " + filepath); return; }

  try {
    nlohmann::json j;
    file >> j;
    for (auto& item : j.items()) {
      _realToMask[item.key()] = item.value();
      _maskToReal[item.value()] = item.key();
      _sortedRealKeys.push_back(item.key());
      _sortedMaskKeys.push_back(item.value());
    }
    auto sortByLengthDesc = [](const std::string& a, const std::string& b) { return a.length() > b.length(); };
    std::sort(_sortedRealKeys.begin(), _sortedRealKeys.end(), sortByLengthDesc);
    std::sort(_sortedMaskKeys.begin(), _sortedMaskKeys.end(), sortByLengthDesc);
    Logger::Info("Vault carregado. Entidades: " + std::to_string(_realToMask.size()));
  }
  catch (const std::exception& e) { Logger::Error("Erro ao ler JSON do Vault: " + std::string(e.what())); }
}

// ==========================================
// 3. CORE: MOTOR DE SANITIZAÇÃO
// ==========================================

void Sanitizer::InitializeRules(const IpVault& vault)
{
  _sanitizeRules.clear();
  _restoreRules.clear();
  _literalSanitize.clear();
  _literalRestore.clear();
  
  static const std::vector<std::string> blacklist = { "generic_string", "generic_comment", "generic_identifier" };

  for (const std::string& realName : vault.GetSortedRealKeys()) {
    std::string maskedName = vault.GetMasked(realName);
    
    if (func_token_is_regex(realName)) {
      _sanitizeRules.push_back({ std::regex(realName), maskedName });
    } else {
      // For literals, we use both a faster string search and a regex for word boundaries
      _literalSanitize.push_back({ realName, maskedName });
      
      bool isBlacklisted = std::find(blacklist.begin(), blacklist.end(), maskedName) != blacklist.end();
      if (!isBlacklisted) {
        _literalRestore.push_back({ maskedName, realName });
      }
    }
  }
}

static bool IsWordBoundary(char c) {
  return !std::isalnum(static_cast<unsigned char>(c)) && c != '_';
}

std::string Sanitizer::SanitizeString(const std::string& text) const
{
  if (text.empty()) return text;
  std::string result = text;

  // 1. Literal replacements (Word-Boundary Aware & Stack-Safe)
  for (const auto& rule : _literalSanitize) {
    if (rule.first.length() < 3) continue; 
    
    size_t pos = 0;
    int limit = 0;
    while ((pos = result.find(rule.first, pos)) != std::string::npos && limit < 5000) {
      bool leftOk = (pos == 0) || IsWordBoundary(result[pos - 1]);
      bool rightOk = (pos + rule.first.length() == result.length()) || IsWordBoundary(result[pos + rule.first.length()]);

      if (leftOk && rightOk) {
        result.replace(pos, rule.first.length(), rule.second);
        pos += rule.second.length();
      } else {
        pos += 1;
      }
      limit++;
    }
  }

  return result;
}

std::string Sanitizer::RestoreString(const std::string& text) const
{
  if (text.empty()) return text;
  std::string result = text;

  // 1. Literal restorations
  for (const auto& rule : _literalRestore) {
    if (rule.first.length() < 3) continue; 
    size_t pos = 0;
    int limit = 0;
    while ((pos = result.find(rule.first, pos)) != std::string::npos && limit < 5000) {
      bool leftOk = (pos == 0) || IsWordBoundary(result[pos - 1]);
      bool rightOk = (pos + rule.first.length() == result.length()) || IsWordBoundary(result[pos + rule.first.length()]);

      if (leftOk && rightOk) {
        result.replace(pos, rule.first.length(), rule.second);
        pos += rule.second.length();
      } else {
        pos += 1;
      }
      limit++;
    }
  }
  return result;
}

void Sanitizer::SanitizeJsonPayload(nlohmann::json& payload, const std::string& targetModel) const
{
  if (!targetModel.empty()) {
    // Optional override: only enforce model if TARGET_MODEL was explicitly configured.
    payload["model"] = targetModel;
  }
  payload["stream"] = false;

  if (payload.contains("messages") && payload["messages"].is_array())
  {
    auto& msgs = payload["messages"];
    for (size_t i = 0; i < msgs.size(); ++i)
    {
      try {
        auto& msg = msgs[i];
        if (msg.contains("content") && msg["content"].is_string()) {
          msg["content"] = SanitizeString(msg["content"].get<std::string>());
        }
      } catch (...) {}
    }
  }
}

void Sanitizer::RestoreJsonPayload(nlohmann::json& payload) const
{
  if (payload.contains("choices") && payload["choices"].is_array())
  {
    for (auto& choice : payload["choices"])
    {
      if (choice.contains("message") && choice["message"].contains("content") && choice["message"]["content"].is_string())
        choice["message"]["content"] = RestoreString(choice["message"]["content"].get<std::string>());
    }
  }
}

// ==========================================
// 4. INFRAESTRUTURA: CLIENTE LLM E HANDLER
// ==========================================

OpenAiClient::OpenAiClient(const std::string& key) : _apiKey(key) {}

httplib::Result OpenAiClient::PostChatCompletion(const std::string& jsonBody) const
{
  httplib::SSLClient cli("models.inference.ai.azure.com");
  cli.set_bearer_token_auth(_apiKey);
  cli.set_read_timeout(120, 0);
  return cli.Post("/chat/completions", jsonBody, "application/json");
}

CompletionHandler::CompletionHandler(const Sanitizer& s, const OpenAiClient& c, const std::string& model)
  : _sanitizer(s), _llmClient(c), _targetModel(model) {
}

void CompletionHandler::HandleRequest(const httplib::Request& req, httplib::Response& res) const
{
  try
  {
    // Dump para debug se crashar
    {
       std::ofstream dump("last_request.json");
       dump << req.body;
    }

    nlohmann::json reqJson = nlohmann::json::parse(req.body);
    std::cout << "[INFO] JSON da requisicao parseado. Iniciando sanitizacao estruturada..." << std::endl;
    _sanitizer.SanitizeJsonPayload(reqJson, _targetModel);

    std::string cleanedBody = reqJson.dump();
    std::cout << "[OK] Sanitizacao concluida. Tamanho do payload: " << cleanedBody.length() << " bytes. Enviando para Azure..." << std::endl;

    auto apiRes = _llmClient.PostChatCompletion(cleanedBody);

    if (!apiRes || apiRes->status != 200)
    {
      Logger::Error("Erro Cloud: " + (apiRes ? std::to_string(apiRes->status) : "Timeout"));
      res.status = apiRes ? apiRes->status : 502;
      res.set_content(apiRes ? apiRes->body : R"({"error": "Cloud Timeout"})", "application/json");
      return;
    }

    try {
      nlohmann::json resJson = nlohmann::json::parse(apiRes->body);
      _sanitizer.RestoreJsonPayload(resJson);
      res.status = 200;
      res.set_content(resJson.dump(), "application/json");
      std::cout << "[OK] Resposta entregue com sucesso." << std::endl;
    } catch (const std::exception& je) {
      Logger::Error("Erro ao parsear resposta do Azure: " + std::string(je.what()));
      res.status = 200;
      res.set_content(_sanitizer.RestoreString(apiRes->body), "application/json");
    }
  }
  catch (const std::exception& e)
  {
    Logger::Error("Erro Interno no Handler: " + std::string(e.what()));
    res.status = 500;
  }
}

// ==========================================
// 5. MAIN COM SUPER DEBUGGER E GATEWAY
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
    CompletionHandler handler(sanitizer, llmClient, config.GetTargetModel());
    const std::string proxyLogPath = func_token31();

    httplib::Server svr;

    svr.set_logger([](const httplib::Request& req, const httplib::Response& res) {
      std::cout << "\n============================================\n";
      std::cout << "[RAW DETECT] ALGUEM BATEU NA PORTA!\n";
      std::cout << "Metodo: " << req.method << "\n";
      std::cout << "Caminho (Path): " << req.path << "\n";
      std::cout << "============================================\n";
      });

    // As rotas explícitas do Azure (se houver fallback)
    auto chatHandler = [&](const httplib::Request& req, httplib::Response& res) {
      handler.HandleRequest(req, res);
      };

    svr.Post("/v1/chat/completions", chatHandler);
    svr.Post("/chat/completions", chatHandler);

    // --- NOVO: Forwarder Transparente Universal (Trata a sanitização bruta) ---
    auto transparentForwarder = [&](const httplib::Request& req, httplib::Response& res) {
      std::cout << "\n[CLI TRANSPARENTE] Roteando " << req.method << " " << req.path << " direto para o GitHub...\n";

      httplib::SSLClient cli("api.githubcopilot.com");
      cli.set_read_timeout(120, 0);

      // Copia os headers, removendo interferências
      httplib::Headers headers;
      for (const auto& h : req.headers) {
        const std::string keyLower = func_token33(h.first);
        if (!func_token34(keyLower)) {
          // NUNCA sanitizar headers - eles devem ir puros para o backend
          headers.emplace(h.first, h.second);
        }
      }

      std::string body = req.body;

      // SANITIZAÇÃO ESTRUTURADA: Parse JSON e sanitiza apenas valores sensíveis
      if (req.method == "POST" && !body.empty()) {
        try {
          auto jsonPayload = nlohmann::json::parse(body);
          sanitizer.SanitizeJsonPayload(jsonPayload, config.GetTargetModel());
          body = jsonPayload.dump();
          std::cout << "     [->] Payload (JSON) mascarado com sucesso.\n";
        } catch (...) {
          // Se não for JSON válido, sanitiza como string
          body = sanitizer.SanitizeString(body);
          std::cout << "     [->] Payload (RAW STRING) mascarado com sucesso.\n";
        }
      }

      func_token32("OUTBOUND TO COPILOT", req.method, req.path, body);

      auto process_response = [&](auto& apiRes) {
        if (apiRes) {
          std::cout << "     [<-] Status da Nuvem: HTTP " << apiRes->status << "\n";
          std::string print_body = apiRes->body;
          if (print_body.length() > 300) print_body = print_body.substr(0, 300) + "... [truncado]";
          std::cout << "     [<-] Resposta da Nuvem: " << print_body << "\n";

          res.status = apiRes->status;
          std::string res_body = apiRes->body;

          func_token32("INBOUND FROM COPILOT", req.method, req.path, res_body);

          // RESTAURAÇÃO ESTRUTURADA
          if (!res_body.empty()) {
            try {
              auto jsonResponse = nlohmann::json::parse(res_body);
              sanitizer.RestoreJsonPayload(jsonResponse);
              res_body = jsonResponse.dump();
            } catch (const std::exception& e) {
              std::cout << "     [!] Aviso: Resposta nao eh JSON estruturado (" << e.what() << "). Usando restauracao bruta.\n";
              res_body = sanitizer.RestoreString(res_body);
            }
          }

          // DEVOLVE OS HEADERS ORIGINAIS PARA O CLI!
          for (auto& h : apiRes->headers) {
            const std::string keyLower = func_token33(h.first);

            // REMOVIDO "content-type" daqui para não duplicar com o res.set_content e crashar o Node.js do CLI
            if (!func_token34(keyLower) && keyLower != "content-type") {
              std::string value = h.second;
              if (!func_token35(keyLower)) {
                value = sanitizer.RestoreString(value);
              }
              res.set_header(h.first, value);
            }
          }

          std::string res_ctype = apiRes->has_header("Content-Type") ? apiRes->get_header_value("Content-Type") : "application/json";
          res.set_content(res_body, res_ctype.c_str());
        }
        else {
          std::cout << "     [ERRO DE REDE] Falha ao comunicar com a Nuvem. Codigo de erro httplib: " << static_cast<int>(apiRes.error()) << "\n";
          res.status = 502;
          res.set_content("{\"error\": \"Proxy Forwarding Failed\"}", "application/json");
        }
        };

      if (req.method == "GET") {
        auto apiRes = cli.Get(req.path.c_str(), headers);
        process_response(apiRes);
      }
      else if (req.method == "POST") {
        std::string ctype = req.has_header("Content-Type") ? req.get_header_value("Content-Type") : "application/json";
        auto apiRes = cli.Post(req.path.c_str(), headers, body, ctype.c_str());
        process_response(apiRes);
      }
      };

    // Regista explicitamente as rotas que descobrimos
    svr.Get("/models", transparentForwarder);
    svr.Post("/mcp/readonly", transparentForwarder);
    svr.Get("/agents/swe/internal/memory/v0/user/enabled", transparentForwarder);
    svr.Post("/responses", transparentForwarder);

    // O CATCH-ALL (Rede de Segurança Universal)
    svr.set_error_handler([&](const httplib::Request& req, httplib::Response& res) {
      if (req.method == "CONNECT") {
        std::string hostPort = req.path;
        Logger::Info("CONNECT interceptado: " + hostPort);
        std::cout << "\n[CONNECT] Aceito: " << hostPort << "\n";
        res.status = 200;
        res.set_header("Connection", "keep-alive");
        return;
      }
      std::cout << "\n[CATCH-ALL] Rota nao mapeada detectada (" << req.path << "). Redirecionando...\n";
      transparentForwarder(req, res);
      });

    svr.Get("/ping", [](const httplib::Request&, httplib::Response& res) {
      res.set_content("Proxy vivo!", "text/plain");
      });

    Logger::Info("Proxy SUPER DEBUG pronto na porta " + std::to_string(config.GetPort()));
    if (config.GetTargetModel().empty()) {
      Logger::Info("TARGET_MODEL nao definido: proxy nao sobrescreve o modelo enviado pelo cliente.");
    }
    else {
      Logger::Info("TARGET_MODEL definido: forcar modelo '" + config.GetTargetModel() + "'.");
    }
    Logger::Info("Log de trafego Copilot em: " + proxyLogPath);

    if (!svr.listen("0.0.0.0", config.GetPort())) {
      Logger::Error("Falha ao abrir a porta " + std::to_string(config.GetPort()));
      return 1;
    }
  }
  catch (const std::exception& e)
  {
    Logger::Error(e.what());
    return 1;
  }
  return 0;
}

