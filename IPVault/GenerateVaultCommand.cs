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
using System.Text;
using System.Text.RegularExpressions;
using System.Linq;
using SharpPdb.Windows;
using SharpPdb.Windows.SymbolRecords;

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
      IpVaultLogger.Log("=== EXECUTE CALLED (PDB PIPELINE) ===");
      DTE2? dte = this.package.JoinableTaskFactory.Run(async delegate
      {
        await ThreadHelper.JoinableTaskFactory.SwitchToMainThreadAsync(this.package.DisposalToken);
        return await this.package.GetServiceAsync(typeof(DTE)) as DTE2
               ?? Microsoft.VisualStudio.Shell.Package.GetGlobalService(typeof(EnvDTE.DTE)) as DTE2;
      });

      if (dte == null)
      {
        IpVaultLogger.Log("[IPVault] DTE service unavailable.");
        return;
      }

      VaultExtractor extractor = new VaultExtractor(dte, this.package);
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
          "IP Vault map generated successfully using PDB symbols!",
          "IP Vault",
          OLEMSGICON.OLEMSGICON_INFO,
          OLEMSGBUTTON.OLEMSGBUTTON_OK,
          OLEMSGDEFBUTTON.OLEMSGDEFBUTTON_FIRST);
    }
  }

  public class VaultExtractor
  {
    private DTE2 _dte;
    private AsyncPackage? _package;

    public VaultExtractor(DTE2 dte, AsyncPackage? package = null)
    {
      _dte = dte;
      _package = package;
    }

    private async System.Threading.Tasks.Task SynchronizeExternalPdbsAsync(string targetPdbDir)
    {
      try
      {
        if (_package == null) return;
        
        var options = (IPVaultOptions)_package.GetDialogPage(typeof(IPVaultOptions));
        string sourceDir = options.PdbDirectory;

        if (string.IsNullOrWhiteSpace(sourceDir) || !Directory.Exists(sourceDir))
        {
          IpVaultLogger.Log("[IPVault] No valid external PDB directory configured. Skipping synchronization.");
          return;
        }

        IpVaultLogger.Log($"[IPVault] Synchronizing PDBs from: {sourceDir} to {targetPdbDir}");
        Directory.CreateDirectory(targetPdbDir);

        var pdbFiles = Directory.GetFiles(sourceDir, "*.pdb", SearchOption.AllDirectories);
        int copiedCount = 0;

        foreach (var sourceFile in pdbFiles)
        {
          try
          {
            string fileName = Path.GetFileName(sourceFile);
            string destFile = Path.Combine(targetPdbDir, fileName);

            // Copy if doesn't exist or source is newer
            if (!File.Exists(destFile) || File.GetLastWriteTimeUtc(sourceFile) > File.GetLastWriteTimeUtc(destFile))
            {
              File.Copy(sourceFile, destFile, true);
              copiedCount++;
            }
          }
          catch (Exception ex)
          {
            IpVaultLogger.Log($"[IPVault] Failed to copy PDB {sourceFile}: {ex.Message}");
          }
        }

        IpVaultLogger.Log($"[IPVault] PDB synchronization complete. Copied {copiedCount} new/updated files.");
      }
      catch (Exception ex)
      {
        IpVaultLogger.Log($"[IPVault] Error during PDB synchronization: {ex.Message}");
      }
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

        string solutionDir = Path.GetDirectoryName(solution.FullName) ?? Path.GetTempPath();
        string vsPath = Path.Combine(solutionDir, ".vs", "IPVault");
        Directory.CreateDirectory(vsPath);
        
        string vaultFilePath = Path.Combine(vsPath, "ip_vault_map.json");
        string pdbDirPath = Path.Combine(vsPath, "PDBS");
        string whitelistPath = Path.Combine(vsPath, "WhiteList.json");

        IpVaultLogger.Initialize(vsPath);
        IpVaultLogger.Log($"[IPVault] Starting PDB-based extraction...");

        // 0. Synchronize external PDBs if configured
        await SynchronizeExternalPdbsAsync(pdbDirPath);

        // 1. Gather all files in the current solution automatically
        IpVaultLogger.Log("[IPVault] Scanning solution for included files...");
        HashSet<string> solutionFiles = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (Project project in EnumerateProjects(solution.Projects))
        {
            if (project.ProjectItems != null)
                GatherFilesFromProjectItems(project.ProjectItems, solutionFiles);
        }
        
        // 2. "Put them there": Save to WhiteList.json as requested
        SaveFileList(solutionFiles, whitelistPath);
        IpVaultLogger.Log($"[IPVault] Solution scan complete. Found {solutionFiles.Count} files. Whitelist updated.");

        // 3. Load Whitelist (now as individual files)
        List<string> whitelist = solutionFiles.ToList();
        
        HashSet<string> ipNames = new HashSet<string>(StringComparer.Ordinal);
        Dictionary<string, string> ipNameWithTypes = new Dictionary<string, string>(StringComparer.Ordinal);

        // 4. Process PDBs
        if (Directory.Exists(pdbDirPath))
        {
          string[] pdbFiles = Directory.GetFiles(pdbDirPath, "*.pdb");
          foreach (string pdbPath in pdbFiles)
          {
            IpVaultLogger.Log($"[IPVault] Parsing PDB: {pdbPath}");
            ExtractFromPdb(pdbPath, whitelist, ipNameWithTypes);
          }
        }

        // 5. IntelliSense Extraction
        IpVaultLogger.Log("[IPVault] Starting IntelliSense extraction...");
        foreach (Project project in EnumerateProjects(solution.Projects))
        {
            if (project.ProjectItems != null)
                ExtractFromIntelliSense(project.ProjectItems, solutionFiles, ipNameWithTypes);
        }

        // 6. Consolidation & Tokenization
        var vault = GenerateTokenMap(ipNameWithTypes);

        string jsonString = SerializeJson(vault);
        File.WriteAllText(vaultFilePath, jsonString);

        IpVaultLogger.Log($"[IPVault] Vault saved successfully. Extracted {vault.Count} IP entities.");
        return vault.Count;
      }
      catch (Exception ex)
      {
        IpVaultLogger.Log($"[IPVault] Critical error in ExtractAndSaveVaultAsync: {ex.Message}\n{ex.StackTrace}");
        return 0;
      }
    }

    private void GatherFilesFromProjectItems(ProjectItems items, HashSet<string> fileList)
    {
      ThreadHelper.ThrowIfNotOnUIThread();
      if (items == null) return;
      foreach (ProjectItem item in items)
      {
        try
        {
          // Add current item's files (usually 1, but can be multiple)
          for (short i = 1; i <= item.FileCount; i++)
          {
            try
            {
              string path = item.FileNames[i];
              if (!string.IsNullOrEmpty(path)) fileList.Add(Path.GetFullPath(path));
            }
            catch { }
          }
          // Recurse into folders
          if (item.ProjectItems != null) GatherFilesFromProjectItems(item.ProjectItems, fileList);
          // Handle nested projects
          if (item.SubProject != null && item.SubProject.ProjectItems != null)
             GatherFilesFromProjectItems(item.SubProject.ProjectItems, fileList);
        }
        catch { }
      }
    }

    private IEnumerable<Project> EnumerateProjects(Projects projects)
    {
      ThreadHelper.ThrowIfNotOnUIThread();
      if (projects == null) yield break;
      foreach (Project project in projects)
      {
        if (project.Kind == "{66A26720-8FB5-11D2-AA7E-00C04F688DDE}") // Solution Folder
        {
            foreach (ProjectItem item in project.ProjectItems)
            {
                if (item.SubProject != null)
                {
                    foreach (Project sub in EnumerateProjectTree(item.SubProject)) yield return sub;
                }
            }
        }
        else yield return project;
      }
    }

    private IEnumerable<Project> EnumerateProjectTree(Project project)
    {
      ThreadHelper.ThrowIfNotOnUIThread();
      yield return project;
      if (project.ProjectItems != null)
      {
          foreach (ProjectItem item in project.ProjectItems)
          {
              if (item.SubProject != null)
              {
                  foreach (Project sub in EnumerateProjectTree(item.SubProject)) yield return sub;
              }
          }
      }
    }

    private void SaveFileList(HashSet<string> files, string path)
    {
        try
        {
            StringBuilder sb = new StringBuilder();
            sb.AppendLine("[");
            var list = files.ToList();
            for (int i = 0; i < list.Count; i++)
            {
                sb.Append($"  \"{EscapeJsonString(list[i])}\"");
                if (i < list.Count - 1) sb.AppendLine(",");
                else sb.AppendLine();
            }
            sb.AppendLine("]");
            File.WriteAllText(path, sb.ToString());
        }
        catch { }
    }

    private List<string> LoadWhitelist(string path)
    {
      try
      {
        if (!File.Exists(path)) return new List<string>();
        string content = File.ReadAllText(path);
        var matches = Regex.Matches(content, "\"([^\"]+)\"");
        var list = new List<string>();
        foreach (Match m in matches)
        {
          string file = m.Groups[1].Value.Replace("\\\\", "\\");
          list.Add(Path.GetFullPath(file));
        }
        return list;
      }
      catch { return new List<string>(); }
    }

    private void ExtractFromPdb(string pdbPath, List<string> whitelist, Dictionary<string, string> ipNames)
    {
      HashSet<string> whitelistSet = new HashSet<string>(whitelist, StringComparer.OrdinalIgnoreCase);
      try
      {
        using (var pdb = new PdbFile(pdbPath))
        {
          var dbi = pdb.DbiStream;
          if (dbi == null) return;

          foreach (var module in dbi.Modules)
          {
            bool moduleIsProprietary = false;
            var sourceFiles = module.Files;
            if (sourceFiles != null)
            {
              foreach (var sf in sourceFiles)
              {
                if (whitelistSet.Contains(Path.GetFullPath(sf)))
                {
                  moduleIsProprietary = true;
                  break;
                }
              }
            }

            if (!moduleIsProprietary) continue;

            var localSymbols = module.LocalSymbolStream;
            if (localSymbols == null || localSymbols.References == null) continue;

            for (int i = 0; i < localSymbols.References.Count; i++)
            {
              var sym = localSymbols[i];
              if (sym == null) continue;
              string name = GetNameFromSymbol(sym);
              if (string.IsNullOrEmpty(name) || name.Length <= 3) continue;

              string type = "Var";
              if (sym is ProcedureSymbol) type = "Func";
              else if (sym is UdtSymbol) type = "Class";
              else if (sym is ConstantSymbol) type = "Var"; 

              if (!ipNames.ContainsKey(name)) ipNames[name] = type;
            }
          }
        }
      }
      catch (Exception ex)
      {
        IpVaultLogger.Log($"[IPVault] Error reading PDB {pdbPath}: {ex.Message}");
      }
    }

    private string GetNameFromSymbol(object sym)
    {
      if (sym == null) return "";
      if (sym is ProcedureSymbol rs) return rs.Name.ToString();
      if (sym is Public32Symbol ps) return ps.Name.ToString();
      if (sym is DataSymbol ds) return ds.Name.ToString();
      if (sym is ConstantSymbol cs) return cs.Name.ToString();
      if (sym is UdtSymbol us) return us.Name.ToString();
      
      try
      {
          var prop = sym.GetType().GetProperty("Name");
          if (prop != null) return prop.GetValue(sym)?.ToString() ?? "";
          var field = sym.GetType().GetField("Name");
          if (field != null) return field.GetValue(sym)?.ToString() ?? "";
      } catch {}

      return "";
    }

    private void ExtractFromIntelliSense(ProjectItems items, HashSet<string> whitelist, Dictionary<string, string> ipNames)
    {
      ThreadHelper.ThrowIfNotOnUIThread();
      if (items == null) return;

      foreach (ProjectItem item in items)
      {
        try
        {
          bool isProprietary = false;
          for (short i = 1; i <= item.FileCount; i++)
          {
            try
            {
              string path = item.FileNames[i];
              if (!string.IsNullOrEmpty(path) && whitelist.Contains(Path.GetFullPath(path)))
              {
                isProprietary = true;
                break;
              }
            }
            catch { }
          }

          if (isProprietary && item.FileCodeModel != null)
          {
            foreach (CodeElement element in item.FileCodeModel.CodeElements)
            {
              ProcessCodeElement(element, ipNames);
            }
          }

          if (item.ProjectItems != null) ExtractFromIntelliSense(item.ProjectItems, whitelist, ipNames);
          if (item.SubProject != null && item.SubProject.ProjectItems != null)
            ExtractFromIntelliSense(item.SubProject.ProjectItems, whitelist, ipNames);
        }
        catch { }
      }
    }

    private void ProcessCodeElement(CodeElement element, Dictionary<string, string> ipNames)
    {
      ThreadHelper.ThrowIfNotOnUIThread();
      try
      {
        string name = element.Name;
        if (!string.IsNullOrEmpty(name) && name.Length > 3 && !ipNames.ContainsKey(name))
        {
          string type = "";
          switch (element.Kind)
          {
            case vsCMElement.vsCMElementClass:
            case vsCMElement.vsCMElementStruct:
              type = "Class";
              break;
            case vsCMElement.vsCMElementFunction:
              type = "Func";
              break;
            case vsCMElement.vsCMElementVariable:
              type = "Var";
              break;
            case vsCMElement.vsCMElementEnum:
              type = "Enum";
              break;
            case vsCMElement.vsCMElementMacro:
              type = "Macro";
              break;
            case vsCMElement.vsCMElementProperty:
              type = "Property";
              break;
            case vsCMElement.vsCMElementTypeDef:
              type = "Typedef";
              break;
          }

          if (!string.IsNullOrEmpty(type)) ipNames[name] = type;
        }

        // Recurse into children (namespaces, classes, etc.)
        if (element.Kind == vsCMElement.vsCMElementNamespace || 
            element.Kind == vsCMElement.vsCMElementClass || 
            element.Kind == vsCMElement.vsCMElementStruct ||
            element.Kind == vsCMElement.vsCMElementEnum)
        {
            foreach (CodeElement child in element.Children)
            {
                ProcessCodeElement(child, ipNames);
            }
        }
      }
      catch { }
    }

    private Dictionary<string, string> GenerateTokenMap(Dictionary<string, string> names)
    {
      var map = new Dictionary<string, string>(StringComparer.Ordinal);
      var counters = new Dictionary<string, int> { 
          {"Class", 1}, {"Var", 1}, {"Func", 1}, {"Enum", 1}, {"Macro", 1}, {"File", 1}, {"Property", 1}, {"Typedef", 1} 
      };
      
      var sortedNames = names.Keys.OrderBy(n => n).ToList();
      foreach (var name in sortedNames)
      {
        if (IsReserved(name)) continue;
        string type = names[name];
        map[name] = $"{type}_{counters[type]++}";
      }
      return map;
    }

    private bool IsReserved(string name)
    {
       string[] reserved = { "main", "std", "void", "int", "char", "bool", "float", "double" };
       return reserved.Contains(name);
    }

    private string SerializeJson(Dictionary<string, string> dict)
    {
      var sb = new StringBuilder();
      sb.AppendLine("{");
      int count = 0;
      foreach (var kvp in dict)
      {
        count++;
        sb.Append($"  \"{EscapeJsonString(kvp.Key)}\": \"{EscapeJsonString(kvp.Value)}\"");
        if (count < dict.Count) sb.AppendLine(",");
        else sb.AppendLine();
      }
      sb.AppendLine("}");
      return sb.ToString();
    }

    private string EscapeJsonString(string value)
    {
      if (value == null) return string.Empty;
      return value.Replace("\\", "\\\\").Replace("\"", "\\\"");
    }
  }
}
