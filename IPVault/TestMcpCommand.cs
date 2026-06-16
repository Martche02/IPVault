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
    internal sealed class TestMcpCommand
    {
        public const int CommandId = 0x0103;
        public static readonly Guid CommandSet = new Guid("45101b51-12e9-48b7-8bc7-7c02d439b422");
        private readonly AsyncPackage package;

        private TestMcpCommand(AsyncPackage package, OleMenuCommandService commandService)
        {
            this.package = package ?? throw new ArgumentNullException(nameof(package));
            commandService = commandService ?? throw new ArgumentNullException(nameof(commandService));

            var menuCommandID = new CommandID(CommandSet, CommandId);
            var menuItem = new MenuCommand(this.Execute, menuCommandID);
            commandService.AddCommand(menuItem);
        }

        public static TestMcpCommand? Instance { get; private set; }

        public static async Task InitializeAsync(AsyncPackage package)
        {
            OleMenuCommandService? commandService = await package.GetServiceAsync(typeof(IMenuCommandService)) as OleMenuCommandService;
            if (commandService != null)
            {
                Instance = new TestMcpCommand(package, commandService);
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

                    string extensionDirectory = Path.GetDirectoryName(System.Reflection.Assembly.GetExecutingAssembly().Location);
                    string mcpPath = Path.Combine(extensionDirectory, "Resources", "CLI", "mcp.exe");

                    if (!File.Exists(mcpPath))
                    {
                        IpVaultLogger.Log($"[IPVault] MCP executable not found at: {mcpPath}");
                        VsShellUtilities.ShowMessageBox(
                            this.package,
                            "MCP executable not found inside the extension. Please reinstall the extension.",
                            "IP Vault",
                            OLEMSGICON.OLEMSGICON_CRITICAL,
                            OLEMSGBUTTON.OLEMSGBUTTON_OK,
                            OLEMSGDEFBUTTON.OLEMSGDEFBUTTON_FIRST);
                        return;
                    }

                    string mcpCmd = $"\"{mcpPath}\" \"{mapPath}\" \"{solutionDir}\" --interactive";

                    try
                    {
                        // Launch in a standard external CMD window in the solution root
                        System.Diagnostics.ProcessStartInfo psi = new System.Diagnostics.ProcessStartInfo("cmd.exe")
                        {
                            Arguments = $"/k \"echo Starting interactive MCP Test... & {mcpCmd}\"",
                            UseShellExecute = true,
                            WorkingDirectory = solutionDir
                        };
                        System.Diagnostics.Process.Start(psi);

                        IpVaultLogger.Log($"[IPVault] MCP interactive mode launched in external CMD window.");
                    }
                    catch (Exception ex)
                    {
                        IpVaultLogger.Log($"[IPVault] Error launching MCP Test: {ex.Message}");
                    }
                }
                catch (Exception ex)
                {
                    IpVaultLogger.Log($"[IPVault] Critical Error: {ex.Message}");
                }
            });
        }
    }
}
