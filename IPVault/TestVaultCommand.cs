using Microsoft.VisualStudio.Shell;
using Microsoft.VisualStudio.Shell.Interop;
using System;
using System.ComponentModel.Design;
using EnvDTE;
using EnvDTE80;
using Task = System.Threading.Tasks.Task;

namespace IPVault
{
    internal sealed class TestVaultCommand
    {
        public const int CommandId = 0x0102;
        public static readonly Guid CommandSet = new Guid("45101b51-12e9-48b7-8bc7-7c02d439b422");
        private readonly AsyncPackage package;

        private TestVaultCommand(AsyncPackage package, OleMenuCommandService commandService)
        {
            this.package = package ?? throw new ArgumentNullException(nameof(package));
            commandService = commandService ?? throw new ArgumentNullException(nameof(commandService));

            var menuCommandID = new CommandID(CommandSet, CommandId);
            var menuItem = new MenuCommand(this.Execute, menuCommandID);
            commandService.AddCommand(menuItem);
        }

        public static TestVaultCommand? Instance { get; private set; }

        public static async Task InitializeAsync(AsyncPackage package)
        {
            await ThreadHelper.JoinableTaskFactory.SwitchToMainThreadAsync(package.DisposalToken);
            OleMenuCommandService? commandService = await package.GetServiceAsync(typeof(IMenuCommandService)) as OleMenuCommandService;
            if (commandService != null)
            {
                Instance = new TestVaultCommand(package, commandService);
            }
        }

        private void Execute(object sender, EventArgs e)
        {
            ThreadHelper.ThrowIfNotOnUIThread();

            _ = this.package.JoinableTaskFactory.RunAsync(async () =>
            {
                await ThreadHelper.JoinableTaskFactory.SwitchToMainThreadAsync();
                DTE2? dte = await package.GetServiceAsync(typeof(DTE)) as DTE2;
                if (dte != null)
                {
                    var window = new TestVaultWindow(dte);
                    window.ShowDialog();
                }
            });
        }
    }
}