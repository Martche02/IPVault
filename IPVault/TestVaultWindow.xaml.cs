using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.RegularExpressions;
using System.Windows;
using System.Windows.Controls;
using Microsoft.VisualStudio.Shell;
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

        public TestVaultWindow(DTE2 dte)
        {
            ThreadHelper.ThrowIfNotOnUIThread();
            InitializeComponent();
            LoadMap(dte);
        }

        private void LoadMap(DTE2 dte)
        {
            ThreadHelper.ThrowIfNotOnUIThread();
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

                // Tokenize comments
                text = Regex.Replace(text, @"/\*[\s\S]*?\*/|//.*", match => {
                    string token = $"Comment_{commentCounter++}";
                    _dynamicReverseMap[token] = match.Value;
                    return token;
                });

                // Tokenize strings and chars
                text = Regex.Replace(text, @"""(?:[^""\\]|\\.)*""|'(?:[^'\\]|\\.)*'", match => {
                    string token = $"Str_{strCounter++}";
                    _dynamicReverseMap[token] = match.Value;
                    return token;
                });

                foreach (var kvp in _forwardMap)
                {
                    // Custom boundary: start/end of string OR non-alphanumeric character
                    string pattern = @"(?<=^|[^a-zA-Z0-9])" + Regex.Escape(kvp.Key) + @"(?=$|[^a-zA-Z0-9])";
                    text = Regex.Replace(text, pattern, kvp.Value);
                }
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
                
                // Restore Map Tokens
                var sortedReverse = _reverseMap.OrderByDescending(k => k.Key.Length).ToList();
                foreach (var kvp in sortedReverse)
                {
                    string pattern = @"(?<=^|[^a-zA-Z0-9])" + Regex.Escape(kvp.Key) + @"(?=$|[^a-zA-Z0-9])";
                    text = Regex.Replace(text, pattern, kvp.Value);
                }

                // Restore Dynamic Strings/Comments
                var sortedDynamic = _dynamicReverseMap.OrderByDescending(k => k.Key.Length).ToList();
                foreach (var kvp in sortedDynamic)
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