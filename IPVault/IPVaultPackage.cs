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
  [ProvideAutoLoad(Microsoft.VisualStudio.Shell.Interop.UIContextGuids80.SolutionExists, PackageAutoLoadFlags.BackgroundLoad)]
  public sealed class IPVaultPackage : AsyncPackage
  {
    private static readonly HashSet<string> CppExtensions = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
    {
      ".c", ".cc", ".cpp", ".cxx",
      ".h", ".hh", ".hpp", ".hxx",
      ".inl", ".ipp"
    };

    private DTE2? _dte;
    private DocumentEvents? _documentEvents;
    private SolutionEvents? _solutionEvents;

    protected override async Task InitializeAsync(CancellationToken cancellationToken, IProgress<ServiceProgressData> progress)
    {
      IpVaultLogger.Log("[IPVault] Package initialization started.");
      await this.JoinableTaskFactory.SwitchToMainThreadAsync(cancellationToken);
      await GenerateVaultCommand.InitializeAsync(this);
      IpVaultLogger.Log("[IPVault] Command initialization completed.");

      DTE2? dte = await GetServiceAsync(typeof(DTE)) as DTE2
                  ?? Microsoft.VisualStudio.Shell.Package.GetGlobalService(typeof(DTE)) as DTE2;

      if (dte == null)
      {
        IpVaultLogger.Log("[IPVault] Failed to acquire DTE service. Automatic updates disabled.");
        return;
      }

      _dte = dte;

      // 1. Hook de Guardar Documento (Ctrl+S)
      _documentEvents = _dte.Events.DocumentEvents;
      _documentEvents.DocumentSaved += OnDocumentSaved;

      // 2. Hook de Abrir Solução
      _solutionEvents = _dte.Events.SolutionEvents;
      _solutionEvents.Opened += OnSolutionOpened;

      // Se a solução já estava aberta quando a extensão carregou, dispara a função
      if (_dte.Solution != null && _dte.Solution.IsOpen)
      {
        OnSolutionOpened();
      }
    }

    // Roda silenciosamente ao ABRIR um projeto
    private void OnSolutionOpened()
    {
      ThreadHelper.ThrowIfNotOnUIThread();
      IpVaultLogger.Log("[IPVault] Solution opened event triggered");
      if (_dte == null)
      {
        IpVaultLogger.Log("[IPVault] DTE service is null on solution open.");
        return;
      }

      VaultExtractor extractor = new VaultExtractor(_dte);

      _ = JoinableTaskFactory.RunAsync(async () =>
      {
        try
        {
          IpVaultLogger.Log("[IPVault] Starting automatic vault extraction on solution open...");
          // 1. Espera o Visual Studio avisar que o carregamento da solução inteira terminou
          // Substituímos o WhenActivatedAsync por um loop manual para evitar o erro CS1061
          int contextRetries = 0;
          while (contextRetries < 20)
          {
            await JoinableTaskFactory.SwitchToMainThreadAsync();
            if (KnownUIContexts.SolutionExistsAndFullyLoadedContext.IsActive)
            {
              break;
            }

            await Task.Delay(500);
            contextRetries++;
          }
          IpVaultLogger.Log($"[IPVault] Solution fully loaded context active (retries: {contextRetries})");

          // 2. Smart Polling: Espera ativamente pelo IntelliSense do C++ dar o "OK"
          int maxRetries = 30; // Tenta por até 30 segundos
          for (int i = 0; i < maxRetries; i++)
          {
            int extractedTokens = await extractor.ExtractAndSaveVaultAsync();

            // Se encontrou entidades, o IntelliSense terminou de ler o código!
            if (extractedTokens > 0)
            {
              IpVaultLogger.Log($"[IPVault] Solution open extraction completed. Extracted {extractedTokens} tokens");
              break;
            }

            // Se retornou 0, o IntelliSense ainda está mastigando os headers C++. Espera 1s.
            IpVaultLogger.Log($"[IPVault] Waiting for IntelliSense to load... (attempt {i + 1}/{maxRetries})");
            await Task.Delay(1000);
          }
        }
        catch (Exception ex)
        {
          IpVaultLogger.Log($"[IPVault] Error in OnSolutionOpened: {ex.Message}");
        }
      });
    }

    // Roda silenciosamente ao SALVAR um arquivo (Ctrl+S)
    private void OnDocumentSaved(Document document)
    {
      ThreadHelper.ThrowIfNotOnUIThread();
      if (document == null)
      {
        IpVaultLogger.Log("[IPVault] Document saved event received null document.");
        return;
      }

      IpVaultLogger.Log($"[IPVault] Document saved: {document.Name}");

      string documentPath = string.IsNullOrWhiteSpace(document.FullName) ? document.Name : document.FullName;
      if (IsCppDocument(documentPath))
      {
        if (_dte == null)
        {
          IpVaultLogger.Log("[IPVault] DTE service is null on document save.");
          return;
        }

        IpVaultLogger.Log($"[IPVault] C++ file detected, triggering vault update...");
        VaultExtractor extractor = new VaultExtractor(_dte);

        _ = JoinableTaskFactory.RunAsync(async () =>
        {
          try
          {
            // No Ctrl+S não precisa de delay, pois o código já está carregado
            int extractedTokens = await extractor.ExtractAndSaveVaultAsync();
            IpVaultLogger.Log($"[IPVault] Document save extraction completed. Extracted {extractedTokens} tokens");
          }
          catch (Exception ex)
          {
            IpVaultLogger.Log($"[IPVault] Error in OnDocumentSaved: {ex.Message}");
          }
        });
      }
      else
      {
        IpVaultLogger.Log($"[IPVault] Non-C++ file saved, skipping vault update");
      }
    }

    private static bool IsCppDocument(string documentPath)
    {
      if (string.IsNullOrWhiteSpace(documentPath))
      {
        return false;
      }

      string extension = Path.GetExtension(documentPath);
      return !string.IsNullOrWhiteSpace(extension) && CppExtensions.Contains(extension);
    }
  }
}
