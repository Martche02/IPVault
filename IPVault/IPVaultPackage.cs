using System;
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
  [ProvideAutoLoad(Microsoft.VisualStudio.Shell.Interop.UIContextGuids80.SolutionExists, PackageAutoLoadFlags.BackgroundLoad)]
  public sealed class IPVaultPackage : AsyncPackage
  {
    private DTE2 _dte;
    private DocumentEvents _documentEvents;
    private SolutionEvents _solutionEvents;

    protected override async Task InitializeAsync(CancellationToken cancellationToken, IProgress<ServiceProgressData> progress)
    {
      await this.JoinableTaskFactory.SwitchToMainThreadAsync(cancellationToken);

      _dte = await GetServiceAsync(typeof(DTE)) as DTE2;

      if (_dte != null)
      {
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
    }

    // Roda silenciosamente ao ABRIR um projeto
    private void OnSolutionOpened()
    {
      ThreadHelper.ThrowIfNotOnUIThread();

      VaultExtractor extractor = new VaultExtractor(_dte);

      _ = Task.Run(async () =>
      {
        try
        {
          // 1. Espera o Visual Studio avisar que o carregamento da solução inteira terminou
          // Substituímos o WhenActivatedAsync por um loop manual para evitar o erro CS1061
          int contextRetries = 0;
          while (!KnownUIContexts.SolutionExistsAndFullyLoadedContext.IsActive && contextRetries < 20)
          {
            await Task.Delay(500);
            contextRetries++;
          }

          // 2. Smart Polling: Espera ativamente pelo IntelliSense do C++ dar o "OK"
          int maxRetries = 30; // Tenta por até 30 segundos
          for (int i = 0; i < maxRetries; i++)
          {
            int extractedTokens = await extractor.ExtractAndSaveVaultAsync();

            // Se encontrou entidades, o IntelliSense terminou de ler o código!
            if (extractedTokens > 0)
            {
              break;
            }

            // Se retornou 0, o IntelliSense ainda está mastigando os headers C++. Espera 1s.
            await Task.Delay(1000);
          }
        }
        catch (Exception)
        {
          // Ignora falhas silenciosas de background para não crashar a IDE
        }
      });
    }

    // Roda silenciosamente ao SALVAR um arquivo (Ctrl+S)
    private void OnDocumentSaved(Document document)
    {
      ThreadHelper.ThrowIfNotOnUIThread();

      if (document.Name.EndsWith(".cpp") || document.Name.EndsWith(".h") || document.Name.EndsWith(".hpp"))
      {
        VaultExtractor extractor = new VaultExtractor(_dte);

        _ = Task.Run(async () =>
        {
          // No Ctrl+S não precisa de delay, pois o código já está carregado
          await extractor.ExtractAndSaveVaultAsync();
        });
      }
    }
  }
}