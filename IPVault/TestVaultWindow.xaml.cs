using Microsoft.VisualStudio.Shell;
using Microsoft.VisualStudio.Shell.Interop;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.RegularExpressions;
using System.Windows;
using System.Windows.Controls;
using EnvDTE;
using EnvDTE80;

namespace IPVault
{
    public partial class TestVaultWindow : System.Windows.Window
    {
        private Dictionary<string, string> _forwardMap = new Dictionary<string, string>();
        private Dictionary<string, string> _reverseMap = new Dictionary<string, string>();
        private Dictionary<string, string> _dynamicReverseMap = new Dictionary<string, string>();
        private bool _isUpdating = false;

        private readonly Dictionary<string, string> _hardcodedMap = new Dictionary<string, string>
        {
            { "someProtectedString", "someSafeReplacement" }
        };

        public TestVaultWindow(DTE2 dte)
        {
            ThreadHelper.ThrowIfNotOnUIThread();
            InitializeComponent();
            LoadVaultMap(dte);
        }

        private void LoadVaultMap(DTE2 dte)
        {
            try
            {
                Solution solution = dte.Solution;
                if (solution == null || !solution.IsOpen) return;

                string solutionDir = Path.GetDirectoryName(solution.FullName) ?? Path.GetTempPath();
                string vaultFilePath = Path.Combine(solutionDir, ".vs", "IPVault", "ip_vault_map.json");

                if (File.Exists(vaultFilePath))
                {
                    string json = File.ReadAllText(vaultFilePath);
                    var map = ParseJson(json);

                    // Sort by length descending to replace longer tokens first
                    _forwardMap = map.OrderByDescending(kvp => kvp.Key.Length).ToDictionary(kvp => kvp.Key, kvp => kvp.Value);

                    _reverseMap = new Dictionary<string, string>();
                    foreach (var kvp in _forwardMap)
                    {
                        if (!_reverseMap.ContainsKey(kvp.Value))
                        {
                            _reverseMap[kvp.Value] = kvp.Key;
                        }
                    }
                }
                else
                {
                    MessageBox.Show("IP Vault map not found. Please run 'Generate IP Vault' first.");
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show("Error loading vault map: " + ex.Message);
            }
        }

        private Dictionary<string, string> ParseJson(string json)
        {
            var map = new Dictionary<string, string>();
            var matches = Regex.Matches(json, "\"([^\"]+)\"\\s*:\\s*\"([^\"]+)\"");
            foreach (Match m in matches)
            {
                string key = m.Groups[1].Value.Replace("\\\\", "\\").Replace("\\\"", "\"");
                string val = m.Groups[2].Value.Replace("\\\\", "\\").Replace("\\\"", "\"");
                map[key] = val;
            }
            return map;
        }

        private void TxtPlain_TextChanged(object sender, TextChangedEventArgs e)
        {
            if (_isUpdating) return;
            _isUpdating = true;
            try
            {
                string text = TxtPlain.Text;
                _dynamicReverseMap.Clear();
                int strCounter = 1;
                int commentCounter = 1;
                int lambdaCounter = 1;

                // Identify lambda variable assignments
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
                    string token = $"LambdaVar_{lambdaCounter++}";
                    _dynamicReverseMap[token] = varName;
                    string pattern = @"(?<=^|[^a-zA-Z0-9_])" + Regex.Escape(varName) + @"(?=$|[^a-zA-Z0-9_])";
                    text = Regex.Replace(text, pattern, token);
                }

                // Apply Map replacements (boundaries)
                foreach (var kvp in _forwardMap)
                {
                    string pattern = @"(?<=^|[^a-zA-Z0-9])" + Regex.Escape(kvp.Key) + @"(?=$|[^a-zA-Z0-9])";
                    text = Regex.Replace(text, pattern, kvp.Value);
                }

                // Apply aggressive hardcoded filters (no boundaries)
                foreach (var kvp in _hardcodedMap)
                {
                    text = Regex.Replace(text, Regex.Escape(kvp.Key), kvp.Value, RegexOptions.IgnoreCase);
                }

                // Tokenize C++ Lambdas
                text = Regex.Replace(text, @"\[[^\]]*\]\s*(?:\([^)]*\))?\s*(?:(?:mutable|constexpr|noexcept)\s*)*(?:->\s*[^\{]+)?\s*\{((?>[^{}]+|\{(?<DEPTH>)|\}(?<-DEPTH>))*(?(DEPTH)(?!)))\}", match => {
                    string token = $"Lambda_{lambdaCounter++}";
                    _dynamicReverseMap[token] = match.Value;
                    return token;
                });

                // Tokenize comments
                text = Regex.Replace(text, @"/\*[\s\S]*?\*/|//.*", match => {
                    string token = match.Value.StartsWith("//") ? $"// Comment_{commentCounter++}" : $"/* Comment_{commentCounter++} */";
                    _dynamicReverseMap[token] = match.Value;
                    return token;
                });

                // Tokenize #include angle brackets
                text = Regex.Replace(text, @"(?<=#include\s*)<([^>]+)>", match => {
                    string token = $"<File_{strCounter++}>";
                    _dynamicReverseMap[token] = match.Value;
                    return token;
                });

                // Tokenize strings and chars with C++ prefixes (L, u8, u, U)
                text = Regex.Replace(text, @"(L|u8|u|U)?(""(?:[^""\\]|\\.)*""|'(?:[^'\\]|\\.)*')", match => {
                    string prefix = match.Groups[1].Value;
                    string quote = match.Groups[2].Value.Substring(0, 1);
                    string token = $"{prefix}{quote}Str_{strCounter++}{quote}";
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

                        string token = $"TestArg_{strCounter++}";
                        _dynamicReverseMap[token] = trimmed;
                        protectedArgsList.Add(token);
                    }

                    return $"{macroName}({string.Join(", ", protectedArgsList)})";
                });

                TxtFiltered.Text = text;
            }
            finally
            {
                _isUpdating = false;
            }
        }

        private void TxtFiltered_TextChanged(object sender, TextChangedEventArgs e)
        {
            if (_isUpdating) return;
            _isUpdating = true;
            try
            {
                string text = TxtFiltered.Text;

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

                TxtPlain.Text = text;
            }
            finally
            {
                _isUpdating = false;
            }
        }
    }
}
