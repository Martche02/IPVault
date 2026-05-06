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
                foreach (var kvp in _forwardMap)
                {
                    // Escape key for regex and match as whole word
                    string pattern = @"\b" + Regex.Escape(kvp.Key) + @"\b";
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
                // Sort reverse keys to replace longer ones first
                var sortedReverse = _reverseMap.OrderByDescending(k => k.Key.Length).ToList();
                foreach (var kvp in sortedReverse)
                {
                    string pattern = @"\b" + Regex.Escape(kvp.Key) + @"\b";
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