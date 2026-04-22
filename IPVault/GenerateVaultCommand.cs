using Microsoft.VisualStudio.Shell;
using Microsoft.VisualStudio.Shell.Interop;
using System;
using System.ComponentModel.Design;
using System.Threading;
using System.Threading.Tasks;
using Task = System.Threading.Tasks.Task;
using EnvDTE;
using EnvDTE80;
using System.Collections.Generic;
using System.IO;

namespace IPVault
{
  internal sealed class GenerateVaultCommand
  {
    public const int CommandId = 0x0100;
    public static readonly Guid CommandSet = new Guid("45101b51-12e9-48b7-8bc7-7c02d439b422");
    private readonly AsyncPackage package;

    private GenerateVaultCommand(AsyncPackage package, OleMenuCommandService commandService)
    {
      this.package = package ?? throw new ArgumentNullException(nameof(package));
      commandService = commandService ?? throw new ArgumentNullException(nameof(commandService));

      var menuCommandID = new CommandID(CommandSet, CommandId);
      var menuItem = new MenuCommand(this.Execute, menuCommandID);
      commandService.AddCommand(menuItem);
    }

    public static GenerateVaultCommand Instance { get; private set; }

    public static async Task InitializeAsync(AsyncPackage package)
    {
      await ThreadHelper.JoinableTaskFactory.SwitchToMainThreadAsync(package.DisposalToken);
      OleMenuCommandService commandService = await package.GetServiceAsync(typeof(IMenuCommandService)) as OleMenuCommandService;
      Instance = new GenerateVaultCommand(package, commandService);
    }

    private void Execute(object sender, EventArgs e)
    {
      ThreadHelper.ThrowIfNotOnUIThread();
      DTE2 dte = Microsoft.VisualStudio.Shell.Package.GetGlobalService(typeof(EnvDTE.DTE)) as DTE2;

      if (dte != null)
      {
        VaultExtractor extractor = new VaultExtractor(dte);
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
    private static string _lastSolutionFullName = string.Empty;

    private int classCounter = 1;
    private int funcCounter = 1;
    private int varCounter = 1;

    public VaultExtractor(DTE2 dte)
    {
      _dte = dte;
    }

    public async System.Threading.Tasks.Task<int> ExtractAndSaveVaultAsync()
    {
      await ThreadHelper.JoinableTaskFactory.SwitchToMainThreadAsync();

      Solution solution = _dte.Solution;
      if (solution == null || !solution.IsOpen) return 0;

      Dictionary<string, string> vault = new Dictionary<string, string>();
      string tempPath = Path.GetTempPath();
      string vaultFilePath = Path.Combine(tempPath, "ip_vault_map.json");
      string currentSolution = solution.FullName;

      if (_lastSolutionFullName != currentSolution)
      {
        if (File.Exists(vaultFilePath))
        {
          File.Delete(vaultFilePath);
        }
        _lastSolutionFullName = currentSolution;
      }
      else
      {
        if (File.Exists(vaultFilePath))
        {
          try
          {
            string existingJson = File.ReadAllText(vaultFilePath);
            var loadedVault = System.Text.Json.JsonSerializer.Deserialize<Dictionary<string, string>>(existingJson);
            if (loadedVault != null) vault = loadedVault;

            classCounter = 1; funcCounter = 1; varCounter = 1;
            foreach (string val in vault.Values)
            {
              if (val.StartsWith("Class") || (val.StartsWith("Token") && !val.Contains("_"))) classCounter++;
              else if (val.StartsWith("func_")) funcCounter++;
              else if (val.StartsWith("var_")) varCounter++;
            }
          }
          catch (Exception) { }
        }
      }

      foreach (Project project in solution.Projects)
      {
        if (project.Kind == "{8BC9CEB8-8B4A-11D0-8D11-00A0C91BC942}")
        {
          ExtractFromProjectItems(project.ProjectItems, vault);
        }
      }

      string jsonString = System.Text.Json.JsonSerializer.Serialize(vault, new System.Text.Json.JsonSerializerOptions { WriteIndented = true });
      File.WriteAllText(vaultFilePath, jsonString);

      // Retorna a quantidade de entidades para sabermos se o IntelliSense já carregou
      return vault.Count;
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