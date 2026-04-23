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
    private readonly HashSet<string> _processedFiles = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
    private static readonly HashSet<string> CppKeywords = new HashSet<string>(StringComparer.Ordinal)
    {
      "alignas","alignof","and","and_eq","asm","auto","bitand","bitor","bool","break","case","catch","char","char8_t",
      "char16_t","char32_t","class","compl","concept","const","consteval","constexpr","constinit","const_cast","continue",
      "co_await","co_return","co_yield","decltype","default","delete","do","double","dynamic_cast","else","enum","explicit",
      "export","extern","false","float","for","friend","goto","if","inline","int","long","mutable","namespace","new","noexcept",
      "not","not_eq","nullptr","operator","or","or_eq","private","protected","public","register","reinterpret_cast","requires",
      "return","short","signed","sizeof","static","static_assert","static_cast","struct","switch","template","this","thread_local",
      "throw","true","try","typedef","typeid","typename","union","unsigned","using","virtual","void","volatile","wchar_t","while",
      "xor","xor_eq"
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
      AddMacroMappings(sanitizedContent, vault);
      AddTemplateMappings(sanitizedContent, vault);
      AddShortIdentifierMappings(sanitizedContent, vault);
    }

    private void AddMacroMappings(string content, Dictionary<string, string> vault)
    {
      Regex macroRegex = new Regex("^\\s*#\\s*define\\s+([A-Za-z_][A-Za-z0-9_]*)", RegexOptions.Multiline);
      foreach (Match match in macroRegex.Matches(content))
      {
        if (!match.Success)
        {
          continue;
        }

        string macroName = match.Groups[1].Value;
        AddIfMissing(vault, macroName, $"macro_{NumberToAlpha(macroCounter++).ToLower()}");
      }
    }

    private void AddTemplateMappings(string content, Dictionary<string, string> vault)
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
        AddIfMissing(vault, templateTypeName, $"Class{NumberToAlpha(classCounter++)}");

        string parameters = match.Groups["params"].Value;
        Regex templateParamRegex = new Regex("\\b(?:class|typename)\\s+([A-Za-z_][A-Za-z0-9_]*)");
        foreach (Match paramMatch in templateParamRegex.Matches(parameters))
        {
          if (!paramMatch.Success)
          {
            continue;
          }

          string paramName = paramMatch.Groups[1].Value;
          AddIfMissing(vault, paramName, $"tmpl_param_{NumberToAlpha(templateParamCounter++).ToLower()}");
        }
      }
    }

    private void AddShortIdentifierMappings(string content, Dictionary<string, string> vault)
    {
      Regex identifierRegex = new Regex("\\b[A-Za-z_][A-Za-z0-9_]*\\b");
      foreach (Match match in identifierRegex.Matches(content))
      {
        if (!match.Success)
        {
          continue;
        }

        string identifier = match.Value;
        if (identifier.Length >= 3 || CppKeywords.Contains(identifier))
        {
          continue;
        }

        AddIfMissing(vault, identifier, $"short_{NumberToAlpha(shortIdentifierCounter++).ToLower()}");
      }
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
