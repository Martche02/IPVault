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

    public static GenerateVaultCommand? Instance { get; private set; }

    public static async Task InitializeAsync(AsyncPackage package)
    {
      await ThreadHelper.JoinableTaskFactory.SwitchToMainThreadAsync(package.DisposalToken);
      OleMenuCommandService? commandService = await package.GetServiceAsync(typeof(IMenuCommandService)) as OleMenuCommandService;
      if (commandService == null)
      {
        throw new InvalidOperationException("Unable to initialize IPVault command: IMenuCommandService not available.");
      }

      Instance = new GenerateVaultCommand(package, commandService);
      IpVaultLogger.Log("[IPVault] GenerateVaultCommand initialized.");
    }

    private void Execute(object sender, EventArgs e)
    {
      ThreadHelper.ThrowIfNotOnUIThread();
      IpVaultLogger.Log("=== EXECUTE CALLED ===");
      DTE2? dte = this.package.JoinableTaskFactory.Run(async delegate
      {
        await ThreadHelper.JoinableTaskFactory.SwitchToMainThreadAsync(this.package.DisposalToken);
        return await this.package.GetServiceAsync(typeof(DTE)) as DTE2
               ?? Microsoft.VisualStudio.Shell.Package.GetGlobalService(typeof(EnvDTE.DTE)) as DTE2;
      });

      if (dte == null)
      {
        IpVaultLogger.Log("[IPVault] DTE service unavailable in GenerateVaultCommand.");
        return;
      }

      VaultExtractor extractor = new VaultExtractor(dte);
      _ = this.package.JoinableTaskFactory.RunAsync(async () =>
      {
        try
        {
          await extractor.ExtractAndSaveVaultAsync();
        }
        catch (Exception ex)
        {
          IpVaultLogger.Log($"[IPVault Error] {ex.Message}\n{ex.StackTrace}");
        }
      });

      VsShellUtilities.ShowMessageBox(
          this.package,
          "Geração iniciada. O arquivo será atualizado em %TEMP%\\ip_vault_map.json.",
          "Zero-Trust Vault",
          OLEMSGICON.OLEMSGICON_INFO,
          OLEMSGBUTTON.OLEMSGBUTTON_OK,
          OLEMSGDEFBUTTON.OLEMSGDEFBUTTON_FIRST);
    }
  }

  public class VaultExtractor
  {
    private const string CppProjectKind = "{8BC9CEB8-8B4A-11D0-8D11-00A0C91BC942}";
    private const string SolutionFolderProjectKind = "{66A26720-8FB5-11D2-AA7E-00C04F688DDE}";

    private DTE2 _dte;
    private static string _lastSolutionFullName = string.Empty;

    private int classCounter = 1;
    private int funcCounter = 1;
    private int varCounter = 1;
    private int enumCounter = 1;
    private int methodCounter = 1;
    private int propertyCounter = 1;
    private int fileCounter = 1;

    public VaultExtractor(DTE2 dte)
    {
      _dte = dte;
    }

    public async System.Threading.Tasks.Task<int> ExtractAndSaveVaultAsync()
    {
      try
      {
        await ThreadHelper.JoinableTaskFactory.SwitchToMainThreadAsync();

        Solution solution = _dte.Solution;
        if (solution == null || !solution.IsOpen)
        {
          IpVaultLogger.Log("[IPVault] Solution is null or not open");
          return 0;
        }

        Dictionary<string, string> vault = new Dictionary<string, string>();
        string tempPath = Path.GetTempPath();
        string vaultFilePath = Path.Combine(tempPath, "ip_vault_map.json");
        string currentSolution = solution.FullName;

        IpVaultLogger.Log($"[IPVault] Processing solution: {currentSolution}");
        IpVaultLogger.Log($"[IPVault] Vault file path: {vaultFilePath}");

        if (_lastSolutionFullName != currentSolution)
        {
          IpVaultLogger.Log("[IPVault] New solution detected, clearing vault");
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
              var loadedVault = ParseJson(existingJson);
              if (loadedVault != null) vault = loadedVault;

              classCounter = 1; funcCounter = 1; varCounter = 1; enumCounter = 1; methodCounter = 1; propertyCounter = 1; fileCounter = 1;
              foreach (string val in vault.Values)
              {
                if (val.StartsWith("Class") || (val.StartsWith("Token") && !val.Contains("_"))) classCounter++;
                else if (val.StartsWith("func_")) funcCounter++;
                else if (val.StartsWith("var_")) varCounter++;
                else if (val.StartsWith("enum_")) enumCounter++;
                else if (val.StartsWith("method_")) methodCounter++;
                else if (val.StartsWith("prop_")) propertyCounter++;
                else if (val.StartsWith("file_")) fileCounter++;
              }
            }
            catch (Exception ex)
            {
               IpVaultLogger.Log($"[IPVault] Error loading existing vault: {ex.Message}");
            }
          }
        }

        int projectCount = 0;
        int totalProjects = 0;
        foreach (Project project in EnumerateProjects(solution.Projects))
        {
          if (project == null)
          {
            continue;
          }

          try
          {
            totalProjects++;
            IpVaultLogger.Log($"[IPVault] Found project: {project.Name} - Kind: {project.Kind}");
            if (string.Equals(project.Kind, CppProjectKind, StringComparison.OrdinalIgnoreCase) ||
                (project.FileName != null && project.FileName.EndsWith(".vcxproj", StringComparison.OrdinalIgnoreCase)))
            {
              projectCount++;
              IpVaultLogger.Log($"[IPVault] Processing C++ project: {project.Name}");
              ExtractFromProjectItems(project.ProjectItems, vault);
            }
          }
          catch (Exception ex)
          {
            IpVaultLogger.Log($"[IPVault] Error processing project {project?.Name}: {ex.Message}");
          }
        }

        IpVaultLogger.Log($"[IPVault] Total projects found: {totalProjects}, C++ projects: {projectCount}");
        IpVaultLogger.Log($"[IPVault] Total entities extracted: {vault.Count}");

        string jsonString = SerializeJson(vault);
        File.WriteAllText(vaultFilePath, jsonString);

        IpVaultLogger.Log($"[IPVault] Vault saved successfully to {vaultFilePath}");
        return vault.Count;
      }
      catch (Exception ex)
      {
        IpVaultLogger.Log($"[IPVault] Critical error in ExtractAndSaveVaultAsync: {ex.Message}\n{ex.StackTrace}");
        return 0;
      }
    }

    private void ExtractFromProjectItems(ProjectItems items, Dictionary<string, string> vault)
    {
      ThreadHelper.ThrowIfNotOnUIThread();
      if (items == null) return;

      try
      {
        foreach (ProjectItem item in items)
        {
          try
          {
            // Extrair nome do arquivo
            if (!string.IsNullOrEmpty(item.Name) && !vault.ContainsKey(item.Name))
            {
              string fileExt = Path.GetExtension(item.Name);
              if (!string.IsNullOrEmpty(fileExt))
              {
                vault[item.Name] = $"file_{NumberToAlpha(fileCounter++).ToLower()}";
              }
            }

            FileCodeModel? fcm = null;
            try { fcm = item.FileCodeModel; } catch { }

            if (fcm != null)
            {
              try
              {
                 IpVaultLogger.Log($"[IPVault] Processing file: {item.Name}");
                string filePath = "";
                try { filePath = item.FileNames[1]; } catch { }
                foreach (CodeElement element in fcm.CodeElements)
                {
                  ProcessCodeElement(element, vault, filePath);
                }
              }
              catch (Exception ex)
              {
                IpVaultLogger.Log($"[IPVault] Error processing FileCodeModel for {item.Name}: {ex.Message}");
              }
            }
            
            ProjectItems? subItems = null;
            try { subItems = item.ProjectItems; } catch { }

            if (subItems != null)
            {
              ExtractFromProjectItems(subItems, vault);
            }
          }
          catch (Exception ex)
          {
            IpVaultLogger.Log($"[IPVault] Error processing ProjectItem: {ex.Message}");
          }
        }
      }
      catch (Exception ex)
      {
        IpVaultLogger.Log($"[IPVault] Error in ExtractFromProjectItems: {ex.Message}");
      }
    }

    private void ProcessCodeElement(CodeElement element, Dictionary<string, string> vault, string filePath)
    {
      try
      {
        ThreadHelper.ThrowIfNotOnUIThread();
        if (element.InfoLocation != vsCMInfoLocation.vsCMInfoLocationProject) return;

        string realName = element.Name;
        if (string.IsNullOrEmpty(realName) || vault.ContainsKey(realName)) return;

        IpVaultLogger.Log($"[IPVault] Processing element: {realName} (Kind: {element.Kind})");

        switch (element.Kind)
        {
          case vsCMElement.vsCMElementClass:
          case vsCMElement.vsCMElementStruct:
            vault[realName] = $"Class{NumberToAlpha(classCounter++)}";
            // Processar membros aninhados (funções, propriedades, classes aninhadas)
            if (element.Children != null)
            {
              try
              {
                foreach (CodeElement child in element.Children)
                {
                  ProcessCodeElement(child, vault, filePath);
                }
              }
              catch (Exception ex)
              {
                IpVaultLogger.Log($"[IPVault] Error processing children of {realName}: {ex.Message}");
              }
            }
            break;
          case vsCMElement.vsCMElementEnum:
            vault[realName] = $"enum_{NumberToAlpha(enumCounter++).ToLower()}";
            // Processar valores de enum
            if (element.Children != null)
            {
              try
              {
                foreach (CodeElement child in element.Children)
                {
                  ProcessCodeElement(child, vault, filePath);
                }
              }
              catch (Exception ex)
              {
                IpVaultLogger.Log($"[IPVault] Error processing enum values of {realName}: {ex.Message}");
              }
            }
            break;
          case vsCMElement.vsCMElementFunction:
            if (realName != "main") vault[realName] = $"func_{NumberToAlpha(funcCounter++).ToLower()}";
            break;
          case vsCMElement.vsCMElementProperty:
            vault[realName] = $"prop_{NumberToAlpha(propertyCounter++).ToLower()}";
            break;
          case vsCMElement.vsCMElementVariable:
            vault[realName] = $"var_{NumberToAlpha(varCounter++).ToLower()}";
            break;
          case vsCMElement.vsCMElementNamespace:
            try
            {
              foreach (CodeElement child in element.Children) ProcessCodeElement(child, vault, filePath);
            }
            catch (Exception ex)
            {
              IpVaultLogger.Log($"[IPVault] Error processing namespace {realName}: {ex.Message}");
            }
            break;
        }
      }
      catch (Exception ex)
      {
        IpVaultLogger.Log($"[IPVault] Error in ProcessCodeElement: {ex.Message}");
      }
    }

    private IEnumerable<Project> EnumerateProjects(Projects projects)
    {
      ThreadHelper.ThrowIfNotOnUIThread();
      if (projects == null)
      {
        yield break;
      }

      foreach (Project project in projects)
      {
        foreach (Project nestedProject in EnumerateProjectTree(project))
        {
          yield return nestedProject;
        }
      }
    }

    private IEnumerable<Project> EnumerateProjectTree(Project project)
    {
      ThreadHelper.ThrowIfNotOnUIThread();
      if (project == null)
      {
        yield break;
      }

      yield return project;

      string projectKind;
      try
      {
        projectKind = project.Kind;
      }
      catch (Exception ex)
      {
         IpVaultLogger.Log($"[IPVault] Error reading project kind for {project.Name}: {ex.Message}");
        yield break;
      }

      if (!string.Equals(projectKind, SolutionFolderProjectKind, StringComparison.OrdinalIgnoreCase) ||
          project.ProjectItems == null)
      {
        yield break;
      }

      foreach (ProjectItem item in project.ProjectItems)
      {
        Project subProject;
        try
        {
          subProject = item.SubProject;
        }
        catch (Exception ex)
        {
          IpVaultLogger.Log($"[IPVault] Error reading subproject from item {item?.Name}: {ex.Message}");
          continue;
        }

        if (subProject == null)
        {
          continue;
        }

        foreach (Project nestedProject in EnumerateProjectTree(subProject))
        {
          yield return nestedProject;
        }
      }
    }

    private string NumberToAlpha(int num)
    {
      string[] nato = { "Zero", "Alpha", "Bravo", "Charlie", "Delta", "Echo", "Foxtrot", "Golf", "Hotel", "India", "Juliett" };
      if (num < nato.Length) return nato[num];
      return $"Token{num}";
    }

    private string SerializeJson(Dictionary<string, string> dict)
    {
      var sb = new System.Text.StringBuilder();
      sb.AppendLine("{");
      int count = 0;
      foreach (var kvp in dict)
      {
        count++;
        sb.Append($"  \"{kvp.Key}\": \"{kvp.Value}\"");
        if (count < dict.Count) sb.AppendLine(",");
        else sb.AppendLine();
      }
      sb.AppendLine("}");
      return sb.ToString();
    }

    private Dictionary<string, string> ParseJson(string json)
    {
      var dict = new Dictionary<string, string>();
      var lines = json.Split(new[] { '\n', '\r' }, StringSplitOptions.RemoveEmptyEntries);
      foreach (var line in lines)
      {
        var parts = line.Split(new[] { ':' }, 2);
        if (parts.Length == 2)
        {
          string key = parts[0].Trim(' ', '"', ',');
          string val = parts[1].Trim(' ', '"', ',');
          if (!string.IsNullOrEmpty(key) && key != "{" && key != "}")
            dict[key] = val;
        }
      }
      return dict;
    }
  }
}
