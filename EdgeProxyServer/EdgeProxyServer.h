#pragma once

// Habilita o suporte HTTPS no cliente httplib
#define CPPHTTPLIB_OPENSSL_SUPPORT

#pragma comment(lib, "Crypt32.lib")
#pragma comment(lib, "libcrypto.lib")
#pragma comment(lib, "libssl.lib")

#include "httplib.h"
#include "nlohmann/json.hpp"
#include <string>
#include <unordered_map>
#include <vector>
#include <regex>

// ==========================================
// 1. UTILITÁRIOS E CONFIGURAÇÃO
// ==========================================

class Logger
{
public:
    static void Info(const std::string& msg);
    static void Error(const std::string& msg);
    static void Debug(const std::string& msg);
};

class Config
{
private:
    std::string _apiKey;
    int _port;
    std::string _vaultPath;

public:
    void LoadFromEnvironment();
    const std::string& GetApiKey() const { return _apiKey; }
    int GetPort() const { return _port; }
    const std::string& GetVaultPath() const { return _vaultPath; }
};

// ==========================================
// 2. DOMÍNIO: GERENCIAMENTO DE IP (VAULT)
// ==========================================

class IpVault
{
private:
    std::unordered_map<std::string, std::string> _realToMask;
    std::unordered_map<std::string, std::string> _maskToReal;
    std::vector<std::string> _sortedRealKeys;
    std::vector<std::string> _sortedMaskKeys;

public:
    void LoadFromFile(const std::string& filepath);
    const std::vector<std::string>& GetSortedRealKeys() const { return _sortedRealKeys; }
    const std::vector<std::string>& GetSortedMaskKeys() const { return _sortedMaskKeys; }
    const std::string& GetMasked(const std::string& real) const { return _realToMask.at(real); }
    const std::string& GetReal(const std::string& mask) const { return _maskToReal.at(mask); }
};

// ==========================================
// 3. CORE: MOTOR DE SANITIZAÇÃO
// ==========================================

class Sanitizer
{
private:
    struct ReplaceRule
    {
        std::regex pattern;
        std::string replacement;
    };

    std::vector<ReplaceRule> _sanitizeRules;
    std::vector<ReplaceRule> _restoreRules;

public:
    void InitializeRules(const IpVault& vault);
    std::string SanitizeString(const std::string& text) const;
    std::string RestoreString(const std::string& text) const;
    void SanitizeJsonPayload(nlohmann::json& payload) const;
    void RestoreJsonPayload(nlohmann::json& payload) const;
};

// ==========================================
// 4. INFRAESTRUTURA: CLIENTE LLM E HANDLER
// ==========================================

class OpenAiClient
{
private:
    std::string _apiKey;
    // O endpoint oficial do GitHub Models para contas Pro:
    const std::string _host = "models.inference.ai.azure.com";

public:
    explicit OpenAiClient(const std::string& key);
    httplib::Result PostChatCompletion(const std::string& jsonBody) const;
};

class CompletionHandler
{
private:
    const Sanitizer& _sanitizer;
    const OpenAiClient& _llmClient;

    std::string ReadAndSanitize(const httplib::Request& req) const;
    httplib::Result CommunicateWithCloud(const std::string& safePayload) const;
    void RestoreAndRespond(httplib::Result& apiRes, httplib::Response& res) const;

public:
    CompletionHandler(const Sanitizer& s, const OpenAiClient& c);
    void HandleRequest(const httplib::Request& req, httplib::Response& res) const;
};

// ==========================================
// 5. BOOTSTRAP: SERVIDOR APP
// ==========================================

class ServerApp
{
private:
    httplib::Server _svr;
    int _port;

public:
    ServerApp(int p, const CompletionHandler& handler);
    void Start();
};
