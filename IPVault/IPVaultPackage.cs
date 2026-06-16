using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Threading;
using Microsoft.VisualStudio.Shell;
using Microsoft.VisualStudio.Shell.Interop;
using EnvDTE;
using EnvDTE80;
using Task = System.Threading.Tasks.Task;

namespace IPVault
{
  [PackageRegistration(UseManagedResourcesOnly = true, AllowsBackgroundLoading = true)]
  [Guid("3328b24b-bbeb-4156-a459-f38ade76d1e9")]
  [ProvideMenuResource("Menus.ctmenu", 1)]
  [ProvideOptionPage(typeof(IPVaultOptions), "IPVault", "General", 0, 0, true)]
  public sealed class IPVaultPackage : AsyncPackage
  {
    protected override async Task InitializeAsync(CancellationToken cancellationToken, IProgress<ServiceProgressData> progress)
    {
      // Log on background thread if possible, or after switch
      await this.JoinableTaskFactory.SwitchToMainThreadAsync(cancellationToken);
      IpVaultLogger.Log("[IPVault] Package initialization started on Main Thread.");

      // Initialize commands sequentially on the main thread
      await GenerateVaultCommand.InitializeAsync(this);
      await RunGeminiCommand.InitializeAsync(this);
      await TestVaultCommand.InitializeAsync(this);
      await TestMcpCommand.InitializeAsync(this);

      IpVaultLogger.Log("[IPVault] Command initialization completed.");
    }
  }
}
