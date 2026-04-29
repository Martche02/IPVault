using Microsoft.VisualStudio.Shell;
using Microsoft.VisualStudio.Shell.Interop;
using System;
using System.ComponentModel.Design;
using System.Threading;
using System.Threading.Tasks;
using EnvDTE;
using EnvDTE80;
using System.IO;
using Task = System.Threading.Tasks.Task;

namespace IPVault
{
    internal sealed class RunGeminiCommand
    {
        public const int CommandId = 0x0101;
        public static readonly Guid CommandSet = new Guid("45101b51-12e9-48b7-8bc7-7c02d439b422");
        private readonly AsyncPackage package;

        private RunGeminiCommand(AsyncPackage package, OleMenuCommandService commandService)
        {
            this.package = package ?? throw new ArgumentNullException(nameof(package));
            commandService = commandService ?? throw new ArgumentNullException(nameof(commandService));

            var menuCommandID = new CommandID(CommandSet, CommandId);
            var menuItem = new MenuCommand(this.Execute, menuCommandID);
            commandService.AddCommand(menuItem);
        }

        public static RunGeminiCommand? Instance { get; private set; }

        public static async Task InitializeAsync(AsyncPackage package)
        {
            await ThreadHelper.JoinableTaskFactory.SwitchToMainThreadAsync(package.DisposalToken);
            OleMenuCommandService? commandService = await package.GetServiceAsync(typeof(IMenuCommandService)) as OleMenuCommandService;
            if (commandService != null)
            {
                Instance = new RunGeminiCommand(package, commandService);
            }
        }

        private void Execute(object sender, EventArgs e)
        {
            _ = this.package.JoinableTaskFactory.RunAsync(async () =>
            {
                try
                {
                    await ThreadHelper.JoinableTaskFactory.SwitchToMainThreadAsync();

                    DTE2? dte = await package.GetServiceAsync(typeof(DTE)) as DTE2;
                    if (dte == null || dte.Solution == null || string.IsNullOrEmpty(dte.Solution.FullName))
                    {
                        VsShellUtilities.ShowMessageBox(
                            this.package,
                            "Please open a solution first.",
                            "IP Vault",
                            OLEMSGICON.OLEMSGICON_WARNING,
                            OLEMSGBUTTON.OLEMSGBUTTON_OK,
                            OLEMSGDEFBUTTON.OLEMSGDEFBUTTON_FIRST);
                        return;
                    }

                    string solutionDir = Path.GetDirectoryName(dte.Solution.FullName);
                    string mapPath = Path.Combine(solutionDir, ".vs", "IPVault", "ip_vault_map.json");

                    if (!File.Exists(mapPath))
                    {
                        VsShellUtilities.ShowMessageBox(
                            this.package,
                            "IP Vault map not found. Please run 'Generate IP Vault' first.",
                            "IP Vault",
                            OLEMSGICON.OLEMSGICON_WARNING,
                            OLEMSGBUTTON.OLEMSGBUTTON_OK,
                            OLEMSGDEFBUTTON.OLEMSGDEFBUTTON_FIRST);
                        return;
                    }

                    string trafficPath = Path.Combine(solutionDir, ".vs", "IPVault", "traffic.log");
                    string geminiCmd = $"gemini --filter \"{mapPath}\" --traffic-log \"{trafficPath}\"";

                    try
                    {
                        // 1. Open the standard Visual Studio Integrated Terminal
                        dte.ExecuteCommand("View.Terminal");
                        
                        // Give the terminal a moment to initialize and gain focus
                        await Task.Delay(1000);

                        // 2. Use PowerShell to force the clipboard (bypasses all VS/.NET COM locks)
                        try 
                        {
                            // Escaping any single quotes in the command just in case (though geminiCmd uses double quotes)
                            string escapedCmd = geminiCmd.Replace("'", "''");
                            
                            var psiCb = new System.Diagnostics.ProcessStartInfo("powershell.exe")
                            {
                                Arguments = $"-NoProfile -Command \"Set-Clipboard -Value '{escapedCmd}'\"",
                                CreateNoWindow = true,
                                UseShellExecute = false
                            };
                            System.Diagnostics.Process.Start(psiCb)?.WaitForExit();
                            
                            // A tiny delay to ensure the OS has registered the clipboard change
                            await Task.Delay(100);
                            
                            // Send Ctrl+V and Enter
                            System.Windows.Forms.SendKeys.SendWait("^v{ENTER}");
                        }
                        catch (Exception ex)
                        {
                            IpVaultLogger.Log($"[IPVault] PowerShell clipboard fallback failed: {ex.Message}");
                            // Absolute last resort: type it out and pray the keyboard layout accepts it
                            System.Windows.Forms.SendKeys.SendWait(geminiCmd.Replace("{", "{{}").Replace("}", "{}}") + "{ENTER}");
                        }
                        
                        IpVaultLogger.Log($"[IPVault] Gemini launched in standard integrated terminal.");
                    }
                    catch (Exception dteEx)
                    {
                        IpVaultLogger.Log($"[IPVault] Failed to use integrated terminal: {dteEx.Message}. Falling back to external window.");
                        
                        // Fallback to external window if the DTE command fails (e.g. older VS versions)
                        System.Diagnostics.ProcessStartInfo psi = new System.Diagnostics.ProcessStartInfo("powershell.exe")
                        {
                            Arguments = $"-NoExit -Command \"{geminiCmd}\"",
                            UseShellExecute = true,
                            WorkingDirectory = solutionDir
                        };
                        System.Diagnostics.Process.Start(psi);
                    }
                }
                catch (Exception ex)
                {
                    IpVaultLogger.Log($"[IPVault] Error launching Gemini: {ex.Message}");
                }
            });
        }
    }
}