using Microsoft.VisualStudio.Shell;
using Microsoft.VisualStudio.Shell.Interop;
using System;
using System.ComponentModel.Design;
using System.Globalization;
using System.Threading;
using System.Threading.Tasks;
using Task = System.Threading.Tasks.Task;
using EnvDTE;
using EnvDTE80;
using System.Collections.Generic;
using System.IO;

namespace IPVault
{
    /// <summary>
    /// Command handler
    /// </summary>
    internal sealed class GenerateVaultCommand
    {
        /// <summary>
        /// Command ID.
        /// </summary>
        public const int CommandId = 0x0100;

        /// <summary>
        /// Command menu group (command set GUID).
        /// </summary>
        public static readonly Guid CommandSet = new Guid("45101b51-12e9-48b7-8bc7-7c02d439b422");

        /// <summary>
        /// VS Package that provides this command, not null.
        /// </summary>
        private readonly AsyncPackage package;

        /// <summary>
        /// Initializes a new instance of the <see cref="GenerateVaultCommand"/> class.
        /// Adds our command handlers for menu (commands must exist in the command table file)
        /// </summary>
        /// <param name="package">Owner package, not null.</param>
        /// <param name="commandService">Command service to add command to, not null.</param>
        private GenerateVaultCommand(AsyncPackage package, OleMenuCommandService commandService)
        {
            this.package = package ?? throw new ArgumentNullException(nameof(package));
            commandService = commandService ?? throw new ArgumentNullException(nameof(commandService));

            var menuCommandID = new CommandID(CommandSet, CommandId);
            var menuItem = new MenuCommand(this.Execute, menuCommandID);
            commandService.AddCommand(menuItem);
        }

        /// <summary>
        /// Gets the instance of the command.
        /// </summary>
        public static GenerateVaultCommand Instance
        {
            get;
            private set;
        }

        /// <summary>
        /// Gets the service provider from the owner package.
        /// </summary>
        private Microsoft.VisualStudio.Shell.IAsyncServiceProvider ServiceProvider
        {
            get
            {
                return this.package;
            }
        }

        /// <summary>
        /// Initializes the singleton instance of the command.
        /// </summary>
        /// <param name="package">Owner package, not null.</param>
        public static async Task InitializeAsync(AsyncPackage package)
        {
            // Switch to the main thread - the call to AddCommand in GenerateVaultCommand's constructor requires
            // the UI thread.
            await ThreadHelper.JoinableTaskFactory.SwitchToMainThreadAsync(package.DisposalToken);

            OleMenuCommandService commandService = await package.GetServiceAsync(typeof(IMenuCommandService)) as OleMenuCommandService;
            Instance = new GenerateVaultCommand(package, commandService);
        }

        /// <summary>
        /// This function is the callback used to execute the command when the menu item is clicked.
        /// See the constructor to see how the menu item is associated with this function using
        /// OleMenuCommandService service and MenuCommand class.
        /// </summary>
        /// <param name="sender">Event sender.</param>
        /// <param name="e">Event args.</param>
        private void Execute(object sender, EventArgs e)
        {
            ThreadHelper.ThrowIfNotOnUIThread();

            // Pega a instância principal do Visual Studio de forma global (Evita o erro CS0411)
            DTE2 dte = Microsoft.VisualStudio.Shell.Package.GetGlobalService(typeof(EnvDTE.DTE)) as DTE2;

            if (dte != null)
            {
                VaultExtractor extractor = new VaultExtractor(dte);

                // Roda a extração em background
                _ = System.Threading.Tasks.Task.Run(async () =>
                {
                    await extractor.ExtractAndSaveVaultAsync();
                });

                VsShellUtilities.ShowMessageBox(
                    this.package,
                    "Dicionário de IP gerado com sucesso em %TEMP%!",
                    "Zero-Trust Vault",
                    OLEMSGICON.OLEMSGICON_INFO,
                    OLEMSGBUTTON.OLEMSGBUTTON_OK,
                    OLEMSGDEFBUTTON.OLEMSGDEFBUTTON_FIRST);
            }
        }
    }
    public class VaultExtractor
    {
        private DTE2 _dte;

        // Contadores para gerar tokens únicos e com "tipos falsos"
        private int classCounter = 1;
        private int funcCounter = 1;
        private int varCounter = 1;

        public VaultExtractor(DTE2 dte)
        {
            _dte = dte;
        }

        public async System.Threading.Tasks.Task ExtractAndSaveVaultAsync()
        {
            await ThreadHelper.JoinableTaskFactory.SwitchToMainThreadAsync();

            Dictionary<string, string> vault = new Dictionary<string, string>();

            // Pega a solução atual aberta no Visual Studio
            Solution solution = _dte.Solution;

            if (solution == null || !solution.IsOpen) return;

            // Itera por todos os projetos na solução
            foreach (Project project in solution.Projects)
            {
                // Verifica se é um projeto C++ (ignora outros tipos)
                if (project.Kind == "{8BC9CEB8-8B4A-11D0-8D11-00A0C91BC942}")
                {
                    ExtractFromProjectItems(project.ProjectItems, vault);
                }
            }

            // Salva o Vault na pasta Temp para o Proxy C++ ler
            string tempPath = Path.GetTempPath();
            string vaultFilePath = Path.Combine(tempPath, "ip_vault_map.json");

            string jsonString = System.Text.Json.JsonSerializer.Serialize(vault, new System.Text.Json.JsonSerializerOptions { WriteIndented = true });
            File.WriteAllText(vaultFilePath, jsonString);
        }

        private void ExtractFromProjectItems(ProjectItems items, Dictionary<string, string> vault)
        {
            ThreadHelper.ThrowIfNotOnUIThread();
            if (items == null) return;

            foreach (ProjectItem item in items)
            {
                if (item.FileCodeModel != null)
                {
                    foreach (CodeElement element in item.FileCodeModel.CodeElements)
                    {
                        ProcessCodeElement(element, vault, item.FileNames[1]);
                    }
                }
                if (item.ProjectItems != null)
                {
                    ExtractFromProjectItems(item.ProjectItems, vault);
                }
            }
        }

        private void ProcessCodeElement(CodeElement element, Dictionary<string, string> vault, string filePath)
        {
            ThreadHelper.ThrowIfNotOnUIThread();

            // Ignorar arquivos de fora do seu projeto (ex: stdlib, windows.h)
            if (element.InfoLocation != vsCMInfoLocation.vsCMInfoLocationProject) return;

            string realName = element.Name;
            if (string.IsNullOrEmpty(realName) || vault.ContainsKey(realName)) return;

            switch (element.Kind)
            {
                case vsCMElement.vsCMElementClass:
                case vsCMElement.vsCMElementStruct:
                    vault[realName] = $"Class{NumberToAlpha(classCounter++)}";
                    break;
                case vsCMElement.vsCMElementFunction:
                    if (realName != "main") vault[realName] = $"func_{NumberToAlpha(funcCounter++).ToLower()}";
                    break;
                case vsCMElement.vsCMElementVariable:
                    vault[realName] = $"var_{NumberToAlpha(varCounter++).ToLower()}";
                    break;
                case vsCMElement.vsCMElementNamespace:
                    foreach (CodeElement child in element.Children) ProcessCodeElement(child, vault, filePath);
                    break;
            }
        }

        private string NumberToAlpha(int num)
        {
            string[] nato = { "Zero", "Alpha", "Bravo", "Charlie", "Delta", "Echo", "Foxtrot", "Golf", "Hotel", "India", "Juliett" };
            if (num < nato.Length) return nato[num];
            return $"Token{num}";
        }
    }

}
