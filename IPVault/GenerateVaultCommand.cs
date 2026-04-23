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
    private int macroCounter = 1;
    private int templateParamCounter = 1;
    private int shortIdentifierCounter = 1;
    private int namespaceCounter = 1;
    private int nameCounter = 1;
    private readonly HashSet<string> _processedFiles = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string, string> _namespaceTokenMap = new Dictionary<string, string>(StringComparer.Ordinal);
    
    private class NameObservation
    {
      public string Name { get; set; } = string.Empty;
      public string Type { get; set; } = string.Empty;
      public bool IsMapped { get; set; }
      public string? FilterReason { get; set; }
    }

    private readonly Dictionary<string, Dictionary<string, NameObservation>> _nameObservationsByFile =
      new Dictionary<string, Dictionary<string, NameObservation>>(StringComparer.OrdinalIgnoreCase);
    private static readonly HashSet<string> CppKeywords = new HashSet<string>(StringComparer.Ordinal)
    {
      "alignas","alignof","and","and_eq","asm","auto","bitand","bitor","bool","break","case","catch","char","char8_t",
      "char16_t","char32_t","class","compl","concept","const","consteval","constexpr","constinit","const_cast","continue",
      "co_await","co_return","co_yield","decltype","default","delete","do","double","dynamic_cast","else","enum","explicit",
      "export","extern","false","float","for","friend","goto","if","inline","int","long","mutable","namespace","new","noexcept",
      "not","not_eq","nullptr","operator","or","or_eq","private","protected","public","register","reinterpret_cast","requires",
      "return","short","signed","sizeof","static","static_assert","static_cast","struct","switch","template","this","thread_local",
      "throw","true","try","typedef","typeid","typename","union","unsigned","using","virtual","void","volatile","wchar_t","while",
      "xor","xor_eq",
      "abs", "accumulate", "addressof", "adjacent_difference", "adjacent_find", "all_of", "allocate_shared", "allocator",
      "allocator_traits", "any", "any_of", "array", "async", "atomic", "atomic_cancel", "atomic_commit", "atomic_flag",
      "atomic_noexcept", "bad_alloc", "bad_cast", "bad_typeid", "barrier", "binary_search", "bind", "bitset", "byte", "ceil",
      "cerr", "chrono", "cin", "clamp", "clog", "complex", "condition_variable", "copy", "copy_backward", "copy_if", "copy_n",
      "cos", "count", "count_if", "cout", "cref", "declval", "defined", "deque", "duration", "endl", "ends", "equal",
      "equal_range", "error_code", "exception", "exp", "expected", "filebuf", "fill", "fill_n", "final", "find", "find_end",
      "find_first_of", "find_if", "find_if_not", "floor", "flush", "for_each", "for_each_n", "format", "forward", "forward_list",
      "fstream", "function", "future", "gcd", "generate", "generate_n", "get", "hash", "high_resolution_clock", "hours",
      "ifstream", "import", "includes", "initializer_list", "inner_product", "inplace_merge", "invalid_argument", "invoke",
      "iostream", "iota", "is_sorted", "is_sorted_until", "istringstream", "jthread", "latch", "lcm", "list", "lock_guard",
      "log", "logic_error", "lower_bound", "make_heap", "make_pair", "make_shared", "make_tuple", "make_unique", "map", "max",
      "max_element", "mdspan", "mem_fn", "merge", "microseconds", "milliseconds", "min", "min_element", "minmax", "minutes",
      "mismatch", "module", "move", "move_backward", "multimap", "multiset", "mutex", "nanoseconds", "none_of", "nth_element",
      "nullptr_t", "numbers", "numeric_limits", "ofstream", "optional", "ostringstream", "out_of_range", "overflow_error",
      "override", "packaged_task", "pair", "partial_sort", "partial_sum", "partition", "partition_copy", "pop_heap", "pow",
      "print", "println", "priority_queue", "promise", "ptrdiff_t", "push_heap", "queue", "ratio", "recursive_mutex", "reduce",
      "ref", "reflexpr", "remove", "remove_copy", "remove_copy_if", "remove_if", "replace", "replace_copy", "replace_copy_if",
      "replace_if", "reverse", "reverse_copy", "rotate", "rotate_copy", "round", "runtime_error", "sample", "scoped_lock",
      "search", "search_n", "seconds", "semaphore", "set", "set_difference", "set_intersection", "set_symmetric_difference",
      "set_union", "shared_ptr", "shuffle", "sin", "size_t", "sort", "sort_heap", "span", "sqrt", "stable_partition", "stable_sort",
      "stack", "std", "stderr", "stdin", "stdout", "steady_clock", "stop_token", "streambuf", "string", "string_view",
      "stringstream", "swap", "system_clock", "tan", "thread", "tie", "timed_mutex", "transform", "tuple", "u16string",
      "u32string", "u8string", "underflow_error", "unique", "unique_copy", "unique_lock", "unique_ptr", "unordered_map",
      "unordered_multimap", "unordered_multiset", "unordered_set", "upper_bound", "valarray", "variant", "vector", "weak_ptr",
      "ws", "wstring",
      "_DEBUG", "_MSC_BUILD", "_MSC_EXTENSIONS", "_MSC_FULL_VER", "_MSC_VER", "_MSVC_LANG", "_MT", "_WIN32", "_WIN64"
    };

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
                else if (val.StartsWith("macro_")) macroCounter++;
                else if (val.StartsWith("tmpl_param_")) templateParamCounter++;
                else if (val.StartsWith("short_")) shortIdentifierCounter++;
                else if (val.IndexOf("ns_", StringComparison.Ordinal) >= 0) namespaceCounter++;
              }
            }
            catch (Exception ex)
            {
               IpVaultLogger.Log($"[IPVault] Error loading existing vault: {ex.Message}");
            }
          }
        }
        EnsureRegexMaskingRules(vault);

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
              ExtractAdditionalProtoHeaders(project, vault);
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
        WriteExtractionLog(solution.FullName, vault);

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
            string filePath = "";
            try { filePath = item.FileNames[1]; } catch { }
            ExtractFromRawFile(filePath, vault);

            if (fcm != null)
            {
              try
              {
                 IpVaultLogger.Log($"[IPVault] Processing file: {item.Name}");
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
        string intellisenseType = element.Kind.ToString();
        TrackName(filePath, realName, intellisenseType);
        if (string.IsNullOrEmpty(realName))
        {
          return;
        }

        if (vault.ContainsKey(realName))
        {
          MarkMapped(filePath, realName);
          return;
        }

        IpVaultLogger.Log($"[IPVault] Processing element: {realName} (Kind: {element.Kind})");

        switch (element.Kind)
        {
          case vsCMElement.vsCMElementClass:
          case vsCMElement.vsCMElementStruct:
            AddNameMapping(vault, filePath, realName, $"Class{NumberToAlpha(classCounter++)}");
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
            AddNameMapping(vault, filePath, realName, $"enum_{NumberToAlpha(enumCounter++).ToLower()}");
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
            if (realName != "main")
            {
              AddNameMapping(vault, filePath, realName, $"func_{NumberToAlpha(funcCounter++).ToLower()}");
            }
            else
            {
              MarkFiltered(filePath, realName, "excluded_main");
            }
            break;
          case vsCMElement.vsCMElementProperty:
            AddNameMapping(vault, filePath, realName, $"prop_{NumberToAlpha(propertyCounter++).ToLower()}");
            break;
          case vsCMElement.vsCMElementVariable:
            AddNameMapping(vault, filePath, realName, $"var_{NumberToAlpha(varCounter++).ToLower()}");
            break;
          case vsCMElement.vsCMElementNamespace:
            AddNamespaceDeclarationMapping(realName, vault, filePath, intellisenseType);
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

    private Dictionary<string, string> ParseJson(string json)
    {
      var dict = new Dictionary<string, string>();
      var lines = json.Split(new[] { "\r\n", "\n" }, StringSplitOptions.RemoveEmptyEntries);
      Regex lineRegex = new Regex("^\\s*\"((?:\\\\.|[^\"\\\\])*)\"\\s*:\\s*\"((?:\\\\.|[^\"\\\\])*)\"\\s*,?\\s*$");
      foreach (string line in lines)
      {
        Match match = lineRegex.Match(line);
        if (!match.Success)
        {
          continue;
        }

        string key = UnescapeJsonString(match.Groups[1].Value);
        string val = UnescapeJsonString(match.Groups[2].Value);
        if (!string.IsNullOrEmpty(key) && key != "{" && key != "}")
        {
          dict[key] = val;
        }
      }
      return dict;
    }

    private void EnsureRegexMaskingRules(Dictionary<string, string> vault)
    {
      AddIfMissing(vault, "//[^\\r\\n]*", "generic_comment");
      AddIfMissing(vault, "/\\*[\\s\\S]*?\\*/", "generic_comment");
      AddIfMissing(vault, "\"(?:\\\\.|[^\"\\\\])*\"", "generic_string");
      AddIfMissing(vault, "'(?:\\\\.|[^'\\\\])*'", "generic_string");
    }

    private void ExtractFromRawFile(string filePath, Dictionary<string, string> vault)
    {
      if (string.IsNullOrWhiteSpace(filePath))
      {
        return;
      }

      string fullPath;
      try
      {
        fullPath = Path.GetFullPath(filePath);
      }
      catch
      {
        return;
      }

      if (!ShouldScanFile(fullPath))
      {
        return;
      }

      if (_processedFiles.Contains(fullPath))
      {
        return;
      }

      _processedFiles.Add(fullPath);

      if (!File.Exists(fullPath))
      {
        return;
      }

      string content;
      try
      {
        content = File.ReadAllText(fullPath);
      }
      catch (Exception ex)
      {
        IpVaultLogger.Log($"[IPVault] Error reading source file {fullPath}: {ex.Message}");
        return;
      }

      string sanitizedContent = MaskCommentsAndStrings(content);
      AddMacroMappings(sanitizedContent, vault, fullPath);
      AddTemplateMappings(sanitizedContent, vault, fullPath);
      AddClassMappings(sanitizedContent, vault, fullPath);
      AddUsingMappings(sanitizedContent, vault, fullPath);
      AddTypedefMappings(sanitizedContent, vault, fullPath);
      AddConceptMappings(sanitizedContent, vault, fullPath);
      AddModuleMappings(sanitizedContent, vault, fullPath);
      AddEnumValueMappings(sanitizedContent, vault, fullPath);
      AddNamespaceMappings(sanitizedContent, vault, fullPath);
      AddShortIdentifierMappings(sanitizedContent, vault, fullPath);
    }

    private void ExtractAdditionalProtoHeaders(Project project, Dictionary<string, string> vault)
    {
      ThreadHelper.ThrowIfNotOnUIThread();
      if (project == null)
      {
        return;
      }

      string projectFilePath;
      try
      {
        projectFilePath = project.FileName;
      }
      catch
      {
        return;
      }

      if (string.IsNullOrWhiteSpace(projectFilePath))
      {
        return;
      }

      string projectDirectory;
      try
      {
        projectDirectory = Path.GetDirectoryName(projectFilePath);
      }
      catch
      {
        return;
      }

      if (string.IsNullOrWhiteSpace(projectDirectory) || !Directory.Exists(projectDirectory))
      {
        return;
      }

      ScanProtoHeaders(projectDirectory, "*.pb.h", vault);
      ScanProtoHeaders(projectDirectory, "*.ph.h", vault);
    }

    private void ScanProtoHeaders(string projectDirectory, string pattern, Dictionary<string, string> vault)
    {
      IEnumerable<string> files;
      try
      {
        files = Directory.EnumerateFiles(projectDirectory, pattern, SearchOption.AllDirectories);
      }
      catch (Exception ex)
      {
        IpVaultLogger.Log($"[IPVault] Error scanning {pattern} in {projectDirectory}: {ex.Message}");
        return;
      }

      foreach (string file in files)
      {
        if (IsUnderIncludeDirectory(file))
        {
          continue;
        }

        ExtractFromRawFile(file, vault);
      }
    }

    private void AddMacroMappings(string content, Dictionary<string, string> vault, string filePath)
    {
      Regex macroRegex = new Regex("^\\s*#\\s*define\\s+([A-Za-z_][A-Za-z0-9_]*)", RegexOptions.Multiline);
      foreach (Match match in macroRegex.Matches(content))
      {
        if (!match.Success)
        {
          continue;
        }

        string macroName = match.Groups[1].Value;
        TrackName(filePath, macroName, "raw_macro");
        AddNameMapping(vault, filePath, macroName, $"macro_{NumberToAlpha(macroCounter++).ToLower()}");
      }
    }

    private void AddTemplateMappings(string content, Dictionary<string, string> vault, string filePath)
    {
      Regex templateDeclRegex = new Regex(
        "template\\s*<(?<params>[^>]+)>\\s*(?:class|struct)\\s+(?<name>[A-Za-z_][A-Za-z0-9_]*)",
        RegexOptions.Multiline);

      foreach (Match match in templateDeclRegex.Matches(content))
      {
        if (!match.Success)
        {
          continue;
        }

        string templateTypeName = match.Groups["name"].Value;
        TrackName(filePath, templateTypeName, "raw_template_type");
        AddNameMapping(vault, filePath, templateTypeName, $"Class{NumberToAlpha(classCounter++)}");

        string parameters = match.Groups["params"].Value;
        Regex templateParamRegex = new Regex("\\b(?:class|typename)\\s+([A-Za-z_][A-Za-z0-9_]*)");
        foreach (Match paramMatch in templateParamRegex.Matches(parameters))
        {
          if (!paramMatch.Success)
          {
            continue;
          }

          string paramName = paramMatch.Groups[1].Value;
          TrackName(filePath, paramName, "raw_template_param");
          AddNameMapping(vault, filePath, paramName, $"tmpl_param_{NumberToAlpha(templateParamCounter++).ToLower()}");
        }
      }
    }

    private void AddClassMappings(string content, Dictionary<string, string> vault, string filePath)
    {
      Regex classRegex = new Regex("(?<!\\benum\\s+)\\b(?:class|struct|union)\\s+([A-Za-z_][A-Za-z0-9_]*)\\b");
      foreach (Match match in classRegex.Matches(content))
      {
        if (!match.Success)
        {
          continue;
        }

        string className = match.Groups[1].Value;
        TrackName(filePath, className, "raw_class");

        if (CppKeywords.Contains(className))
        {
          MarkFiltered(filePath, className, "cpp_keyword");
          continue;
        }

        AddNameMapping(vault, filePath, className, $"Class{NumberToAlpha(classCounter++)}");
      }
    }

    private void AddUsingMappings(string content, Dictionary<string, string> vault, string filePath)
    {
      Regex usingRegex = new Regex("\\busing\\s+([A-Za-z_][A-Za-z0-9_]*)\\s*=");
      foreach (Match match in usingRegex.Matches(content))
      {
        if (!match.Success) continue;
        string name = match.Groups[1].Value;
        TrackName(filePath, name, "raw_using");
        if (CppKeywords.Contains(name)) { MarkFiltered(filePath, name, "cpp_keyword"); continue; }
        AddNameMapping(vault, filePath, name, $"Class{NumberToAlpha(classCounter++)}");
      }
    }

    private void AddTypedefMappings(string content, Dictionary<string, string> vault, string filePath)
    {
      Regex typedefRegex = new Regex("\\btypedef\\s+(?:[^;]+?\\s+)?([A-Za-z_][A-Za-z0-9_]*)(?:\\s*\\[.*?\\])*\\s*;");
      foreach (Match match in typedefRegex.Matches(content))
      {
        if (!match.Success) continue;
        string name = match.Groups[1].Value;
        TrackName(filePath, name, "raw_typedef");
        if (CppKeywords.Contains(name)) { MarkFiltered(filePath, name, "cpp_keyword"); continue; }
        AddNameMapping(vault, filePath, name, $"Class{NumberToAlpha(classCounter++)}");
      }
    }

    private void AddConceptMappings(string content, Dictionary<string, string> vault, string filePath)
    {
      Regex conceptRegex = new Regex("\\bconcept\\s+([A-Za-z_][A-Za-z0-9_]*)\\s*=");
      foreach (Match match in conceptRegex.Matches(content))
      {
        if (!match.Success) continue;
        string name = match.Groups[1].Value;
        TrackName(filePath, name, "raw_concept");
        if (CppKeywords.Contains(name)) { MarkFiltered(filePath, name, "cpp_keyword"); continue; }
        AddNameMapping(vault, filePath, name, $"Class{NumberToAlpha(classCounter++)}");
      }
    }

    private void AddModuleMappings(string content, Dictionary<string, string> vault, string filePath)
    {
      Regex moduleRegex = new Regex("\\b(?:import|module)\\s+([A-Za-z_][A-Za-z0-9_]*(?:\\.[A-Za-z_][A-Za-z0-9_]*)*)\\s*;");
      foreach (Match match in moduleRegex.Matches(content))
      {
        if (!match.Success) continue;
        string name = match.Groups[1].Value;
        string[] parts = name.Split('.');
        foreach (string part in parts)
        {
          TrackName(filePath, part, "raw_module");
          if (CppKeywords.Contains(part)) { MarkFiltered(filePath, part, "cpp_keyword"); continue; }
          AddNameMapping(vault, filePath, part, $"ns_{NumberToAlpha(namespaceCounter++).ToLower()}");
        }
      }
    }

    private void AddShortIdentifierMappings(string content, Dictionary<string, string> vault, string filePath)
    {
      Regex identifierRegex = new Regex("\\b[A-Za-z_][A-Za-z0-9_]*\\b");
      foreach (Match match in identifierRegex.Matches(content))
      {
        if (!match.Success)
        {
          continue;
        }

        string identifier = match.Value;
        TrackName(filePath, identifier, "raw_fallback_identifier");

        if (CppKeywords.Contains(identifier))
        {
          MarkFiltered(filePath, identifier, "cpp_keyword");
          continue;
        }

        if (identifier.StartsWith("VAR_") || identifier.StartsWith("STR_") || identifier.StartsWith("DIR_") || 
            identifier.StartsWith("PRE_") || identifier.StartsWith("PATH_") || identifier.StartsWith("Class") || 
            identifier.StartsWith("Token") || identifier.StartsWith("enum_") || identifier.StartsWith("func_") || 
            identifier.StartsWith("var_") || identifier.StartsWith("prop_") || identifier.StartsWith("macro_") || 
            identifier.StartsWith("tmpl_") || identifier.StartsWith("short_") || identifier.StartsWith("ns_") ||
            identifier.StartsWith("name_"))
        {
          MarkFiltered(filePath, identifier, "already_obfuscated_prefix");
          continue;
        }

        AddNameMapping(vault, filePath, identifier, $"name_{NumberToAlpha(nameCounter++).ToLower()}");
      }
    }

    private void AddEnumValueMappings(string content, Dictionary<string, string> vault, string filePath)
    {
      Regex enumRegex = new Regex("\\benum(?:\\s+class)?(?:\\s+[A-Za-z_][A-Za-z0-9_]*)?\\s*\\{(?<body>[\\s\\S]*?)\\}",
        RegexOptions.Multiline);

      foreach (Match enumMatch in enumRegex.Matches(content))
      {
        if (!enumMatch.Success)
        {
          continue;
        }

        string body = enumMatch.Groups["body"].Value;
        string[] members = body.Split(new[] { ',' }, StringSplitOptions.RemoveEmptyEntries);
        foreach (string member in members)
        {
          string candidate = member;
          int assignIndex = candidate.IndexOf('=');
          if (assignIndex >= 0)
          {
            candidate = candidate.Substring(0, assignIndex);
          }

          Match nameMatch = Regex.Match(candidate, "\\b([A-Za-z_][A-Za-z0-9_]*)\\b");
          if (!nameMatch.Success)
          {
            continue;
          }

          string enumValueName = nameMatch.Groups[1].Value;
          TrackName(filePath, enumValueName, "raw_enum_value");

          if (CppKeywords.Contains(enumValueName))
          {
            MarkFiltered(filePath, enumValueName, "cpp_keyword");
            continue;
          }

          AddNameMapping(vault, filePath, enumValueName, $"enum_{NumberToAlpha(enumCounter++).ToLower()}");
        }
      }
    }

    private void AddNamespaceMappings(string content, Dictionary<string, string> vault, string filePath)
    {
      Regex namespaceRegex = new Regex("\\bnamespace\\s+([A-Za-z_][A-Za-z0-9_]*(?:::[A-Za-z_][A-Za-z0-9_]*)*)");
      foreach (Match match in namespaceRegex.Matches(content))
      {
        if (!match.Success)
        {
          continue;
        }

        string fullNamespace = match.Groups[1].Value;
        AddNamespaceDeclarationMapping(fullNamespace, vault, filePath);
      }
    }

    private void AddNamespaceDeclarationMapping(string fullNamespace, Dictionary<string, string> vault, string filePath, string type = "raw_namespace")
    {
      if (string.IsNullOrWhiteSpace(fullNamespace))
      {
        return;
      }

      string[] parts = fullNamespace.Split(new[] { "::" }, StringSplitOptions.RemoveEmptyEntries);
      if (parts.Length == 0)
      {
        return;
      }

      List<string> mappedParts = new List<string>(parts.Length);
      foreach (string part in parts)
      {
        TrackName(filePath, part, type);
        mappedParts.Add(GetOrCreateNamespaceToken(part));
      }

      string key = $"\\bnamespace\\s+{Regex.Escape(fullNamespace)}\\b";
      string value = $"namespace {string.Join("::", mappedParts)}";
      AddIfMissing(vault, key, value);
    }

    private string GetOrCreateNamespaceToken(string namespaceName)
    {
      if (string.IsNullOrWhiteSpace(namespaceName))
      {
        return $"ns_{NumberToAlpha(namespaceCounter++).ToLower()}";
      }

      if (_namespaceTokenMap.TryGetValue(namespaceName, out string existing))
      {
        return existing;
      }

      string created = $"ns_{NumberToAlpha(namespaceCounter++).ToLower()}";
      _namespaceTokenMap[namespaceName] = created;
      return created;
    }

    private bool ShouldScanFile(string fullPath)
    {
      if (string.IsNullOrWhiteSpace(fullPath))
      {
        return false;
      }

      string extension = Path.GetExtension(fullPath);
      if (string.IsNullOrEmpty(extension))
      {
        return false;
      }

      return string.Equals(extension, ".h", StringComparison.OrdinalIgnoreCase) ||
             string.Equals(extension, ".hpp", StringComparison.OrdinalIgnoreCase) ||
             string.Equals(extension, ".hh", StringComparison.OrdinalIgnoreCase) ||
             string.Equals(extension, ".hxx", StringComparison.OrdinalIgnoreCase) ||
             string.Equals(extension, ".c", StringComparison.OrdinalIgnoreCase) ||
             string.Equals(extension, ".cc", StringComparison.OrdinalIgnoreCase) ||
             string.Equals(extension, ".cpp", StringComparison.OrdinalIgnoreCase) ||
             string.Equals(extension, ".cxx", StringComparison.OrdinalIgnoreCase) ||
             string.Equals(extension, ".ipp", StringComparison.OrdinalIgnoreCase) ||
             string.Equals(extension, ".inl", StringComparison.OrdinalIgnoreCase);
    }

    private bool IsUnderIncludeDirectory(string fullPath)
    {
      if (string.IsNullOrWhiteSpace(fullPath))
      {
        return false;
      }

      string normalized = fullPath.Replace('/', '\\');
      return normalized.IndexOf("\\Include\\", StringComparison.OrdinalIgnoreCase) >= 0;
    }

    private void TrackName(string filePath, string name, string type = "unknown")
    {
      if (string.IsNullOrWhiteSpace(name)) return;

      string normalizedFilePath = string.IsNullOrWhiteSpace(filePath) ? "(unknown)" : filePath;
      if (!_nameObservationsByFile.TryGetValue(normalizedFilePath, out var dict))
      {
        dict = new Dictionary<string, NameObservation>(StringComparer.Ordinal);
        _nameObservationsByFile[normalizedFilePath] = dict;
      }

      if (!dict.TryGetValue(name, out var obs))
      {
        obs = new NameObservation { Name = name, Type = type, IsMapped = false, FilterReason = "not_mapped" };
        dict[name] = obs;
      }
      else if (type != "unknown")
      {
        if (obs.Type == "unknown" || (obs.Type.StartsWith("raw_") && !type.StartsWith("raw_")))
        {
          obs.Type = type;
        }
      }
    }

    private void MarkMapped(string filePath, string name)
    {
      string normalizedFilePath = string.IsNullOrWhiteSpace(filePath) ? "(unknown)" : filePath;
      if (_nameObservationsByFile.TryGetValue(normalizedFilePath, out var dict) &&
          dict.TryGetValue(name, out var obs))
      {
        obs.IsMapped = true;
        obs.FilterReason = null;
      }
    }

    private void MarkFiltered(string filePath, string name, string filterReason)
    {
      string normalizedFilePath = string.IsNullOrWhiteSpace(filePath) ? "(unknown)" : filePath;
      if (_nameObservationsByFile.TryGetValue(normalizedFilePath, out var dict) &&
          dict.TryGetValue(name, out var obs))
      {
        if (obs.IsMapped) return;
        obs.IsMapped = false;
        obs.FilterReason = filterReason;
      }
    }

    private void AddNameMapping(Dictionary<string, string> vault, string filePath, string name, string mappedTo)
    {
      AddIfMissing(vault, name, mappedTo);
      MarkMapped(filePath, name);
    }

    private void WriteExtractionLog(string solutionPath, Dictionary<string, string> vault)
    {
      string logPath = Path.Combine(Path.GetTempPath(), "ip_vault_extraction_log.json");
      StringBuilder sb = new StringBuilder();
      sb.AppendLine("{");
      sb.AppendLine($"  \"solution\": \"{EscapeJsonString(solutionPath ?? string.Empty)}\",");
      sb.AppendLine($"  \"generatedAtUtc\": \"{DateTime.UtcNow:O}\",");
      sb.AppendLine("  \"files\": [");

      List<string> files = new List<string>(_nameObservationsByFile.Keys);
      files.Sort(StringComparer.OrdinalIgnoreCase);

      for (int fileIndex = 0; fileIndex < files.Count; fileIndex++)
      {
        string file = files[fileIndex];
        var dict = _nameObservationsByFile[file];
        List<NameObservation> orderedObs = new List<NameObservation>(dict.Values);
        orderedObs.Sort((a, b) => string.Compare(a.Name, b.Name, StringComparison.Ordinal));

        sb.AppendLine("    {");
        sb.AppendLine($"      \"file\": \"{EscapeJsonString(file)}\",");
        sb.AppendLine($"      \"count\": {orderedObs.Count},");
        sb.AppendLine("      \"names\": [");
        for (int i = 0; i < orderedObs.Count; i++)
        {
          var obs = orderedObs[i];
          string mappedTo = vault.TryGetValue(obs.Name, out string mt) ? $"\"{EscapeJsonString(mt)}\"" : "null";
          sb.AppendLine("        {");
          sb.AppendLine($"          \"name\": \"{EscapeJsonString(obs.Name)}\",");
          sb.AppendLine($"          \"type\": \"{EscapeJsonString(obs.Type)}\",");
          sb.AppendLine($"          \"mapped\": {(obs.IsMapped ? "true" : "false").ToString().ToLower()},");
          sb.AppendLine($"          \"mappedTo\": {mappedTo},");
          sb.AppendLine($"          \"filterReason\": {(obs.FilterReason == null ? "null" : $"\"{EscapeJsonString(obs.FilterReason)}\"")}");
          string comma = i + 1 < orderedObs.Count ? "," : string.Empty;
          sb.AppendLine($"        }}{comma}");
        }
        sb.AppendLine("      ]");
        sb.Append("    }");
        sb.AppendLine(fileIndex + 1 < files.Count ? "," : string.Empty);
      }

      sb.AppendLine("  ]");
      sb.AppendLine("}");

      try
      {
        File.WriteAllText(logPath, sb.ToString());
      }
      catch (Exception ex)
      {
        IpVaultLogger.Log($"[IPVault] Error writing extraction log json: {ex.Message}");
      }
    }

    private void EnsureTrackedNamesInVault(Dictionary<string, string> vault)
    {
      foreach (var fileEntry in _nameObservationsByFile)
      {
        string filePath = fileEntry.Key;
        foreach (var obs in fileEntry.Value.Values)
        {
          if (obs.IsMapped) continue;
          if (obs.FilterReason != null && obs.FilterReason != "not_mapped") continue;

          string name = obs.Name;
          if (string.IsNullOrWhiteSpace(name)) continue;

          if (CppKeywords.Contains(name))
          {
            MarkFiltered(filePath, name, "cpp_keyword");
            continue;
          }

          if (string.Equals(name, "main", StringComparison.Ordinal))
          {
            MarkFiltered(filePath, name, "excluded_main");
            continue;
          }

          if (!vault.ContainsKey(name))
          {
            AddNameMapping(vault, filePath, name, $"name_{NumberToAlpha(nameCounter++).ToLower()}");
          }
          else
          {
            MarkMapped(filePath, name);
          }
        }
      }
    }

    private string MaskCommentsAndStrings(string content)
    {
      if (string.IsNullOrEmpty(content))
      {
        return string.Empty;
      }

      StringBuilder result = new StringBuilder(content.Length);
      bool inLineComment = false;
      bool inBlockComment = false;
      bool inDoubleString = false;
      bool inSingleString = false;
      bool escaped = false;

      for (int i = 0; i < content.Length; i++)
      {
        char c = content[i];
        char next = i + 1 < content.Length ? content[i + 1] : '\0';

        if (inLineComment)
        {
          if (c == '\r' || c == '\n')
          {
            inLineComment = false;
            result.Append(c);
          }
          else
          {
            result.Append(' ');
          }
          continue;
        }

        if (inBlockComment)
        {
          if (c == '*' && next == '/')
          {
            result.Append(' ');
            result.Append(' ');
            i++;
            inBlockComment = false;
          }
          else if (c == '\r' || c == '\n')
          {
            result.Append(c);
          }
          else
          {
            result.Append(' ');
          }
          continue;
        }

        if (inDoubleString)
        {
          if (!escaped && c == '\\')
          {
            escaped = true;
            result.Append(' ');
            continue;
          }

          if (!escaped && c == '"')
          {
            inDoubleString = false;
            result.Append(' ');
            continue;
          }

          escaped = false;
          result.Append(c == '\r' || c == '\n' ? c : ' ');
          continue;
        }

        if (inSingleString)
        {
          if (!escaped && c == '\\')
          {
            escaped = true;
            result.Append(' ');
            continue;
          }

          if (!escaped && c == '\'')
          {
            inSingleString = false;
            result.Append(' ');
            continue;
          }

          escaped = false;
          result.Append(c == '\r' || c == '\n' ? c : ' ');
          continue;
        }

        if (c == '/' && next == '/')
        {
          result.Append(' ');
          result.Append(' ');
          i++;
          inLineComment = true;
          continue;
        }

        if (c == '/' && next == '*')
        {
          result.Append(' ');
          result.Append(' ');
          i++;
          inBlockComment = true;
          continue;
        }

        if (c == '"')
        {
          inDoubleString = true;
          escaped = false;
          result.Append(' ');
          continue;
        }

        if (c == '\'')
        {
          inSingleString = true;
          escaped = false;
          result.Append(' ');
          continue;
        }

        result.Append(c);
      }

      return result.ToString();
    }

    private void AddIfMissing(Dictionary<string, string> vault, string key, string value)
    {
      if (string.IsNullOrWhiteSpace(key) || vault.ContainsKey(key))
      {
        return;
      }

      vault[key] = value;
    }

    private string EscapeJsonString(string value)
    {
      if (value == null)
      {
        return string.Empty;
      }

      StringBuilder sb = new StringBuilder(value.Length + 8);
      foreach (char c in value)
      {
        switch (c)
        {
          case '\\': sb.Append("\\\\"); break;
          case '"': sb.Append("\\\""); break;
          case '\b': sb.Append("\\b"); break;
          case '\f': sb.Append("\\f"); break;
          case '\n': sb.Append("\\n"); break;
          case '\r': sb.Append("\\r"); break;
          case '\t': sb.Append("\\t"); break;
          default:
            if (c < 0x20)
            {
              sb.Append("\\u");
              sb.Append(((int)c).ToString("x4"));
            }
            else
            {
              sb.Append(c);
            }
            break;
        }
      }

      return sb.ToString();
    }

    private string UnescapeJsonString(string value)
    {
      if (string.IsNullOrEmpty(value))
      {
        return string.Empty;
      }

      StringBuilder sb = new StringBuilder(value.Length);
      for (int i = 0; i < value.Length; i++)
      {
        char c = value[i];
        if (c != '\\' || i + 1 >= value.Length)
        {
          sb.Append(c);
          continue;
        }

        char next = value[++i];
        switch (next)
        {
          case '\\': sb.Append('\\'); break;
          case '"': sb.Append('"'); break;
          case 'b': sb.Append('\b'); break;
          case 'f': sb.Append('\f'); break;
          case 'n': sb.Append('\n'); break;
          case 'r': sb.Append('\r'); break;
          case 't': sb.Append('\t'); break;
          case 'u':
            if (i + 4 < value.Length)
            {
              string hex = value.Substring(i + 1, 4);
              if (int.TryParse(hex, System.Globalization.NumberStyles.HexNumber, null, out int charCode))
              {
                sb.Append((char)charCode);
                i += 4;
                break;
              }
            }
            sb.Append('u');
            break;
          default:
            sb.Append(next);
            break;
        }
      }

      return sb.ToString();
    }
  }
}
