using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using System.Threading.Tasks;

namespace IPVault.Mcp
{
    class Program
    {
        static Dictionary<string, string> _forwardMap = new();
        static Dictionary<string, string> _reverseMap = new();
        static Dictionary<string, string> _dynamicReverseMap = new();
        static int _strCounter = 1;
        static int _commentCounter = 1;
        static int _lambdaCounter = 1;

        static string _solutionDir = Environment.CurrentDirectory;

        static async Task Main(string[] args)
        {
            if (args.Length < 2)
            {
                Console.Error.WriteLine("Usage: IPVault.Mcp <map_json_path> <solution_dir> [--interactive]");
                return;
            }

            string mapPath = Path.GetFullPath(args[0]);
            if (!File.Exists(mapPath))
            {
                Console.Error.WriteLine($"Map file not found: {mapPath}");
                return;
            }

            _solutionDir = Path.GetFullPath(args[1]);
            if (!Directory.Exists(_solutionDir))
            {
                Console.Error.WriteLine($"Solution directory not found: {_solutionDir}");
                return;
            }

            Environment.CurrentDirectory = _solutionDir;

            LoadMap(mapPath);

            bool isInteractive = args.Length > 2 && args[2] == "--interactive";

            if (isInteractive)
            {
                await RunInteractiveMode();
            }
            else
            {
                await RunMcpServer();
            }
        }

        static async Task RunInteractiveMode()
        {
            Console.WriteLine("=== IPVault MCP Interactive Test Mode ===");
            Console.WriteLine("This mode allows you to manually trigger MCP tools and see the Notepad interception in action.");
            Console.WriteLine("\nAvailable commands:");
            Console.WriteLine("  read <path>");
            Console.WriteLine("  write <path> <content_text...>");
            Console.WriteLine("  exec <command...>");
            Console.WriteLine("  show <content_text...>");
            Console.WriteLine("  exit\n");

            while (true)
            {
                Console.Write("mcp> ");
                var line = Console.ReadLine();
                if (string.IsNullOrWhiteSpace(line)) continue;

                var parts = line.Split(' ', 2, StringSplitOptions.RemoveEmptyEntries);
                var cmd = parts[0].ToLower();
                var arg = parts.Length > 1 ? parts[1] : "";

                if (cmd == "exit" || cmd == "quit") break;

                try
                {
                    string result = "";
                    if (cmd == "read")
                    {
                        string targetPath = Path.GetFullPath(arg);
                        string rawText;
                        using (var fs = new FileStream(targetPath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite))
                        using (var sr = new StreamReader(fs))
                        {
                            rawText = await sr.ReadToEndAsync();
                        }
                        result = Filter(rawText);
                        result = await InterceptWithNotepad("mcp_read_file", result);
                    }
                    else if (cmd == "write")
                    {
                        var writeParts = arg.Split(' ', 2, StringSplitOptions.RemoveEmptyEntries);
                        if (writeParts.Length < 2)
                        {
                            Console.WriteLine("Usage: write <path> <content...>");
                            continue;
                        }
                        string targetPath = Path.GetFullPath(writeParts[0]);
                        string textContent = writeParts[1];
                        var unfiltered = Unfilter(textContent);

                        using (var fs = new FileStream(targetPath, FileMode.Create, FileAccess.Write, FileShare.Read))
                        using (var sw = new StreamWriter(fs))
                        {
                            await sw.WriteAsync(unfiltered);
                        }
                        result = $"Successfully wrote to {targetPath}";
                        result = await InterceptWithNotepad("mcp_write_file", result);
                    }
                    else if (cmd == "exec")
                    {
                        string command = arg;
                        var unfilteredCommand = Unfilter(command);

                        var psi = new ProcessStartInfo
                        {
                            FileName = "cmd.exe",
                            Arguments = $"/c {unfilteredCommand}",
                            RedirectStandardOutput = true,
                            RedirectStandardError = true,
                            UseShellExecute = false,
                            CreateNoWindow = true,
                            WorkingDirectory = Environment.CurrentDirectory
                        };

                        using var proc = Process.Start(psi);
                        if (proc == null) throw new Exception("Failed to start process.");

                        var stdoutOutput = await proc.StandardOutput.ReadToEndAsync();
                        var stderrOutput = await proc.StandardError.ReadToEndAsync();
                        await proc.WaitForExitAsync();

                        string combined = "";
                        if (!string.IsNullOrEmpty(stdoutOutput)) combined += "STDOUT:\n" + stdoutOutput + "\n";
                        if (!string.IsNullOrEmpty(stderrOutput)) combined += "STDERR:\n" + stderrOutput;

                        result = Filter(combined);
                        result = await InterceptWithNotepad("mcp_exec_command", result);
                    }
                    else if (cmd == "show")
                    {
                        var unfiltered = Unfilter(arg);
                        await ShowToUserWithNotepad(unfiltered);
                        result = "Successfully displayed to user.";
                    }
                    else
                    {
                        Console.WriteLine($"Unknown command: {cmd}");
                        continue;
                    }

                    Console.WriteLine("\n--- FINAL RESULT ---");
                    Console.WriteLine(result);
                    Console.WriteLine("--------------------\n");
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"Error: {ex.Message}");
                }
            }
        }

        static async Task RunMcpServer()
        {
            using var stdin = Console.OpenStandardInput();
            using var stdout = Console.OpenStandardOutput();
            using var reader = new StreamReader(stdin, new UTF8Encoding(false));
            using var writer = new StreamWriter(stdout, new UTF8Encoding(false)) { AutoFlush = true };

            while (true)
            {
                var line = await reader.ReadLineAsync();
                if (line == null) break;

                try
                {
                    var response = await HandleMessage(line);
                    if (response != null)
                    {
                        var json = JsonSerializer.Serialize(response);
                        await writer.WriteLineAsync(json);
                    }
                }
                catch (Exception ex)
                {
                    Console.Error.WriteLine($"Error handling message: {ex}");
                }
            }
        }

        static void LoadMap(string path)
        {
            try
            {
                using var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                using var sr = new StreamReader(fs);
                var json = sr.ReadToEnd();
                var map = JsonSerializer.Deserialize<Dictionary<string, string>>(json);
                if (map != null)
                {
                    foreach (var kvp in map)
                    {
                        _forwardMap[kvp.Key] = kvp.Value;
                        _reverseMap[kvp.Value] = kvp.Key;
                    }
                }
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine($"[IPVault.Mcp] Error loading map file '{path}': {ex.Message}");
            }
        }

        static readonly Dictionary<string, string> _hardcodedMap = new()
        {
            { "someProtectedString", "someSafeReplacement" }
        };

        static string Filter(string text)
        {
            // 1. Identify lambda variable assignments (e.g. auto myLambda = []...)
            string lambdaStartLookahead = @"(?=\[[^\]]*\]\s*(?:\([^)]*\))?\s*(?:(?:mutable|constexpr|noexcept)\s*)*(?:->\s*[^\{]+)?\s*\{)";
            var varMatches = Regex.Matches(text, @"\b([a-zA-Z_][a-zA-Z0-9_]*)\s*=\s*" + lambdaStartLookahead);

            var lambdaVarsToProtect = new HashSet<string>();
            foreach (Match m in varMatches)
            {
                string varName = m.Groups[1].Value;
                if (varName != "auto" && varName != "const" && varName != "operator")
                {
                    lambdaVarsToProtect.Add(varName);
                }
            }

            foreach (var varName in lambdaVarsToProtect)
            {
                string token = $"LambdaVar_{_lambdaCounter++}";
                _dynamicReverseMap[token] = varName;
                string pattern = @"(?<=^|[^a-zA-Z0-9_])" + Regex.Escape(varName) + @"(?=$|[^a-zA-Z0-9_])";
                text = Regex.Replace(text, pattern, token);
            }

            // 2. Apply Map replacements (boundaries)
            var sortedForward = _forwardMap.OrderByDescending(k => k.Key.Length).ToList();
            foreach (var kvp in sortedForward)
            {
                string pattern = @"(?<=^|[^a-zA-Z0-9])" + Regex.Escape(kvp.Key) + @"(?=$|[^a-zA-Z0-9])";
                text = Regex.Replace(text, pattern, kvp.Value);
            }

            // 3. Apply aggressive hardcoded filters (no boundaries)
            foreach (var kvp in _hardcodedMap)
            {
                text = Regex.Replace(text, Regex.Escape(kvp.Key), kvp.Value, RegexOptions.IgnoreCase);
            }

            // 4. Tokenize everything else (Lambdas, Comments, Strings, etc.)
            // Tokenize C++ Lambdas
            text = Regex.Replace(text, @"\[[^\]]*\]\s*(?:\([^)]*\))?\s*(?:(?:mutable|constexpr|noexcept)\s*)*(?:->\s*[^\{]+)?\s*\{((?>[^{}]+|\{(?<DEPTH>)|\}(?<-DEPTH>))*(?(DEPTH)(?!)))\}", match => {
                string token = $"Lambda_{_lambdaCounter++}";
                _dynamicReverseMap[token] = match.Value;
                return token;
            });

            // Tokenize comments
            text = Regex.Replace(text, @"/\*[\s\S]*?\*/|//.*", match => {
                string token = match.Value.StartsWith("//") ? $"// Comment_{_commentCounter++}" : $"/* Comment_{_commentCounter++} */";
                _dynamicReverseMap[token] = match.Value;
                return token;
            });

            // Tokenize #include angle brackets
            text = Regex.Replace(text, @"(?<=#include\s*)<([^>]+)>", match => {
                string token = $"<File_{_strCounter++}>";
                _dynamicReverseMap[token] = match.Value;
                return token;
            });

            // Tokenize strings and chars with C++ prefixes (L, u8, u, U)
            text = Regex.Replace(text, @"(L|u8|u|U)?(""(?:[^""\\]|\\.)*""|'(?:[^'\\]|\\.)*')", match => {
                string prefix = match.Groups[1].Value;
                string quote = match.Groups[2].Value.Substring(0, 1);
                string token = $"{prefix}{quote}Str_{_strCounter++}{quote}";
                _dynamicReverseMap[token] = match.Value;
                return token;
            });

            // Tokenize TEST(...) macros (gtest)
            text = Regex.Replace(text, @"\b(TEST(?:_F|_P)?)\s*\(([^)]+)\)", match => {
                string macroName = match.Groups[1].Value;
                string args = match.Groups[2].Value;
                string[] parts = args.Split(',');
                var protectedArgsList = new List<string>();

                foreach (var p in parts)
                {
                    string trimmed = p.Trim();
                    if (string.IsNullOrEmpty(trimmed)) continue;

                    string token = $"TestArg_{_strCounter++}";
                    _dynamicReverseMap[token] = trimmed;
                    protectedArgsList.Add(token);
                }

                return $"{macroName}({string.Join(", ", protectedArgsList)})";
            });

            return text;
        }

        static string Unfilter(string text)
        {
            // 1. Restore dynamic tokens (Strings, Comments, Lambdas)
            var sortedDynamic = _dynamicReverseMap.OrderByDescending(k => k.Key.Length).ToList();
            foreach (var kvp in sortedDynamic)
            {
                string pattern = @"(?<=^|[^a-zA-Z0-9])" + Regex.Escape(kvp.Key) + @"(?=$|[^a-zA-Z0-9])";
                text = Regex.Replace(text, pattern, kvp.Value);
            }

            // 2. Restore aggressive hardcoded filters
            foreach (var kvp in _hardcodedMap)
            {
                text = Regex.Replace(text, Regex.Escape(kvp.Value), kvp.Key, RegexOptions.IgnoreCase);
            }

            // 3. Restore Map Tokens
            var sortedReverse = _reverseMap.OrderByDescending(k => k.Key.Length).ToList();
            foreach (var kvp in sortedReverse)
            {
                string pattern = @"(?<=^|[^a-zA-Z0-9])" + Regex.Escape(kvp.Key) + @"(?=$|[^a-zA-Z0-9])";
                text = Regex.Replace(text, pattern, kvp.Value);
            }

            return text;
        }

        static async Task<string> InterceptWithNotepad(string toolName, string content)
        {
            string tempFile = Path.Combine(Path.GetTempPath(), $"ipvault_mcp_{Guid.NewGuid():N}.txt");

            string header = "=== IPVAULT MCP INTERCEPT ===\r\n" +
                            $"Tool: {toolName}\r\n" +
                            "Instructions: You can review and edit the content below.\r\n" +
                            "Save the file and close Notepad to continue sending this response back to the AI.\r\n" +
                            "=============================\r\n\r\n";

            try
            {
                await File.WriteAllTextAsync(tempFile, header + content);

                var psi = new ProcessStartInfo
                {
                    FileName = "notepad.exe",
                    Arguments = tempFile,
                    UseShellExecute = true
                };

                using var proc = Process.Start(psi);
                if (proc != null)
                {
                    await proc.WaitForExitAsync();
                }
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine($"[IPVault.Mcp] Error during Notepad interception: {ex.Message}");
            }

            string newContent = "";
            try
            {
                if (File.Exists(tempFile))
                {
                    newContent = await File.ReadAllTextAsync(tempFile);
                    File.Delete(tempFile);
                }
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine($"[IPVault.Mcp] Error reading/deleting temp file: {ex.Message}");
            }

            int headerEnd = newContent.IndexOf("=============================\r\n\r\n");
            if (headerEnd >= 0)
            {
                return newContent.Substring(headerEnd + "=============================\r\n\r\n".Length);
            }

            return newContent;
        }

        static async Task ShowToUserWithNotepad(string content)
        {
            string tempFile = Path.Combine(Path.GetTempPath(), $"ipvault_mcp_show_{Guid.NewGuid():N}.txt");

            string header = "=== IPVAULT: AI SHARED THIS WITH YOU ===\r\n" +
                            "Instructions: The AI wants to show you this unmasked code/text.\r\n" +
                            "Close Notepad to continue. The AI will NOT see this content.\r\n" +
                            "========================================\r\n\r\n";

            try
            {
                await File.WriteAllTextAsync(tempFile, header + content);

                var psi = new ProcessStartInfo
                {
                    FileName = "notepad.exe",
                    Arguments = tempFile,
                    UseShellExecute = true
                };

                using var proc = Process.Start(psi);
                if (proc != null)
                {
                    await proc.WaitForExitAsync();
                }
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine($"[IPVault.Mcp] Error showing to user: {ex.Message}");
            }
            finally
            {
                try
                {
                    if (File.Exists(tempFile)) File.Delete(tempFile);
                }
                catch { }
            }
        }

        static string GetEmbeddedInstructions()
        {
            try
            {
                var assembly = typeof(Program).Assembly;
                string[] resourceNames = assembly.GetManifestResourceNames();
                string? actualResourceName = resourceNames.FirstOrDefault(n => n.EndsWith("AGENTS.md", StringComparison.OrdinalIgnoreCase));

                if (actualResourceName == null)
                {
                    Console.Error.WriteLine("[IPVault.Mcp] Embedded resource 'AGENTS.md' NOT found.");
                    Console.Error.WriteLine("[IPVault.Mcp] Available resources: " + string.Join(", ", resourceNames));
                    return "";
                }

                using (Stream? stream = assembly.GetManifestResourceStream(actualResourceName))
                {
                    if (stream != null)
                    {
                        using (StreamReader reader = new StreamReader(stream))
                        {
                            return reader.ReadToEnd();
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine($"[IPVault.Mcp] Failed to load embedded instructions: {ex.Message}");
            }
            return "";
        }

        static async Task<object?> HandleMessage(string messageJson)
        {
            var doc = JsonNode.Parse(messageJson);
            if (doc == null) return null;

            var obj = doc.AsObject();
            if (!obj.ContainsKey("jsonrpc")) return null;

            string method = obj["method"]?.ToString() ?? "";
            var idNode = obj["id"];

            if (method == "initialize")
            {
                string instructions = GetEmbeddedInstructions();

                return new
                {
                    jsonrpc = "2.0",
                    id = idNode?.AsValue(),
                    result = new
                    {
                        protocolVersion = "2024-11-05",
                        capabilities = new
                        {
                            tools = new { },
                            resources = new { },
                            prompts = new { }
                        },
                        serverInfo = new
                        {
                            name = "ipvault-mcp",
                            version = "1.2.0"
                        },
                        instructions = instructions
                    }
                };
            }
            else if (method == "notifications/initialized")
            {
                return null;
            }
            else if (method == "resources/list")
            {
                return new
                {
                    jsonrpc = "2.0",
                    id = idNode?.AsValue(),
                    result = new
                    {
                        resources = new[]
                        {
                            new {
                                uri = "mcp://instructions/agents.md",
                                name = "Agent Guidelines (AGENTS.md)",
                                description = "Security and masking guidelines for this IPVault protected environment.",
                                mimeType = "text/markdown"
                            }
                        }
                    }
                };
            }
            else if (method == "resources/read")
            {
                var paramsObj = obj["params"]?.AsObject();
                string uri = paramsObj?["uri"]?.ToString() ?? "";

                if (uri == "mcp://instructions/agents.md")
                {
                    return new
                    {
                        jsonrpc = "2.0",
                        id = idNode?.AsValue(),
                        result = new
                        {
                            contents = new[]
                            {
                                new {
                                    uri = "mcp://instructions/agents.md",
                                    mimeType = "text/markdown",
                                    text = GetEmbeddedInstructions()
                                }
                            }
                        }
                    };
                }
                return null;
            }
            else if (method == "prompts/list")
            {
                return new
                {
                    jsonrpc = "2.0",
                    id = idNode?.AsValue(),
                    result = new
                    {
                        prompts = new[]
                        {
                            new {
                                name = "get-guidelines",
                                description = "Get the security and masking guidelines for this environment."
                            }
                        }
                    }
                };
            }
            else if (method == "prompts/get")
            {
                var paramsObj = obj["params"]?.AsObject();
                string name = paramsObj?["name"]?.ToString() ?? "";

                if (name == "get-guidelines")
                {
                    return new
                    {
                        jsonrpc = "2.0",
                        id = idNode?.AsValue(),
                        result = new
                        {
                            description = "Security Guidelines",
                            messages = new[]
                            {
                                new {
                                    role = "user",
                                    content = new {
                                        type = "text",
                                        text = "Please provide the AGENTS.md guidelines."
                                    }
                                },
                                new {
                                    role = "assistant",
                                    content = new {
                                        type = "text",
                                        text = GetEmbeddedInstructions()
                                    }
                                }
                            }
                        }
                    };
                }
                return null;
            }
            else if (method == "tools/list")
            {
                string ruleReminder = " IMPORTANT: Follow all masking and security rules defined in AGENTS.md.";
                return new
                {
                    jsonrpc = "2.0",
                    id = idNode?.AsValue(),
                    result = new
                    {
                        tools = new object[]
                        {
                            new {
                                name = "mcp_read_file",
                                description = "Reads a file and applies the IP Vault filter." + ruleReminder,
                                inputSchema = new {
                                    type = "object",
                                    properties = new {
                                        path = new { type = "string" }
                                    },
                                    required = new[] { "path" }
                                }
                            },
                            new {
                                name = "mcp_write_file",
                                description = "Unfilters provided content and writes it to file." + ruleReminder,
                                inputSchema = new {
                                    type = "object",
                                    properties = new {
                                        path = new { type = "string" },
                                        content = new { type = "string" }
                                    },
                                    required = new[] { "path", "content" }
                                }
                            },
                            new {
                                name = "mcp_exec_command",
                                description = "Executes command with unfiltering/filtering logic." + ruleReminder,
                                inputSchema = new {
                                    type = "object",
                                    properties = new {
                                        command = new { type = "string" },
                                        cwd = new { type = "string" }
                                    },
                                    required = new[] { "command" }
                                }
                            },
                            new {
                                name = "mcp_show_to_user",
                                description = "Shows unmasked text to user in Notepad." + ruleReminder,
                                inputSchema = new {
                                    type = "object",
                                    properties = new {
                                        content = new { type = "string" }
                                    },
                                    required = new[] { "content" }
                                }
                            }
                        }
                    }
                };
            }
            else if (method == "tools/call")
            {
                var paramsObj = obj["params"]?.AsObject();
                string toolName = paramsObj?["name"]?.ToString() ?? "";
                var args = paramsObj?["arguments"]?.AsObject();

                try
                {
                    string content = "";
                    if (toolName == "mcp_read_file")
                    {
                        string path = args?["path"]?.ToString() ?? "";
                        if (!Path.IsPathRooted(path)) path = Path.GetFullPath(path);

                        string rawText;
                        using (var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite))
                        using (var sr = new StreamReader(fs))
                        {
                            rawText = await sr.ReadToEndAsync();
                        }

                        content = Filter(rawText);
                        content = await InterceptWithNotepad("mcp_read_file", content);
                    }
                    else if (toolName == "mcp_write_file")
                    {
                        string path = args?["path"]?.ToString() ?? "";
                        if (!Path.IsPathRooted(path)) path = Path.GetFullPath(path);
                        string textContent = args?["content"]?.ToString() ?? "";
                        var unfiltered = Unfilter(textContent);

                        using (var fs = new FileStream(path, FileMode.Create, FileAccess.Write, FileShare.Read))
                        using (var sw = new StreamWriter(fs))
                        {
                            await sw.WriteAsync(unfiltered);
                        }

                        content = $"Successfully wrote to {path}";
                        content = await InterceptWithNotepad("mcp_write_file", content);
                    }
                    else if (toolName == "mcp_exec_command")
                    {
                        string command = args?["command"]?.ToString() ?? "";
                        string cwd = args?["cwd"]?.ToString() ?? Environment.CurrentDirectory;
                        if (!Path.IsPathRooted(cwd)) cwd = Path.GetFullPath(cwd);
                        var unfilteredCommand = Unfilter(command);

                        var psi = new ProcessStartInfo
                        {
                            FileName = "cmd.exe",
                            Arguments = $"/c {unfilteredCommand}",
                            RedirectStandardOutput = true,
                            RedirectStandardError = true,
                            UseShellExecute = false,
                            CreateNoWindow = true,
                            WorkingDirectory = cwd
                        };

                        using var proc = Process.Start(psi);
                        if (proc == null) throw new Exception("Failed to start process.");

                        var stdoutOutput = await proc.StandardOutput.ReadToEndAsync();
                        var stderrOutput = await proc.StandardError.ReadToEndAsync();
                        await proc.WaitForExitAsync();

                        string combined = "";
                        if (!string.IsNullOrEmpty(stdoutOutput)) combined += "STDOUT:\n" + stdoutOutput + "\n";
                        if (!string.IsNullOrEmpty(stderrOutput)) combined += "STDERR:\n" + stderrOutput;

                        content = Filter(combined);
                        content = await InterceptWithNotepad("mcp_exec_command", content);
                    }
                    else if (toolName == "mcp_show_to_user")
                    {
                        string textContent = args?["content"]?.ToString() ?? "";
                        var unfiltered = Unfilter(textContent);
                        await ShowToUserWithNotepad(unfiltered);
                        content = "Successfully displayed to user.";
                    }
                    else
                    {
                        throw new Exception($"Unknown tool: {toolName}");
                    }

                    return new
                    {
                        jsonrpc = "2.0",
                        id = idNode?.AsValue(),
                        result = new
                        {
                            content = new[]
                            {
                                new { type = "text", text = content }
                            }
                        }
                    };
                }
                catch (Exception ex)
                {
                    return new
                    {
                        jsonrpc = "2.0",
                        id = idNode?.AsValue(),
                        error = new
                        {
                            code = -32603,
                            message = ex.Message
                        }
                    };
                }
            }

            return null;
        }
    }
}
