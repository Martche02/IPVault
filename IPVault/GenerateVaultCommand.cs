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
using SharpPdb.Windows.TypeRecords;

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
    private HashSet<string> _thirdPartyChainTerms = new HashSet<string>(StringComparer.Ordinal);

    private static readonly HashSet<string> _cppKeywords = new HashSet<string>(StringComparer.Ordinal)
    {
        "alignas", "alignof", "and", "and_eq", "asm", "atomic_cancel", "atomic_commit", "atomic_noexcept",
        "auto", "bitand", "bitor", "bool", "break", "case", "catch", "char", "char8_t", "char16_t", "char32_t",
        "class", "compl", "concept", "const", "consteval", "constexpr", "constinit", "const_cast", "continue",
        "co_await", "co_return", "co_yield", "decltype", "default", "delete", "do", "double", "dynamic_cast",
        "else", "enum", "explicit", "export", "extern", "false", "float", "for", "friend", "goto", "if",
        "inline", "int", "long", "mutable", "namespace", "new", "noexcept", "not", "not_eq", "nullptr",
        "operator", "or", "or_eq", "private", "protected", "public", "reflexpr", "register", "reinterpret_cast",
        "requires", "return", "short", "signed", "sizeof", "static", "static_assert", "static_cast", "struct",
        "switch", "synchronized", "template", "this", "thread_local", "throw", "true", "try", "typedef",
        "typeid", "typename", "union", "unsigned", "using", "virtual", "void", "volatile", "wchar_t", "while",
        "xor", "xor_eq",
        "std", "string", "vector", "map", "set", "list", "array", "deque", "unordered_map", "unordered_set",
        "shared_ptr", "unique_ptr", "weak_ptr", "allocator", "basic_string", "char_traits", "pair", "tuple",
        "optional", "variant", "any", "function", "function_ref", "span", "string_view", "size_t", "ptrdiff_t",
        "intptr_t", "uintptr_t", "int8_t", "int16_t", "int32_t", "int64_t", "uint8_t", "uint16_t", "uint32_t", "uint64_t",
        "__cdecl", "__stdcall", "__fastcall", "__thiscall", "__vectorcall", "__ptr64", "__ptr32", "__unaligned",
        "__sptr", "__uptr", "__declspec", "__forceinline", "__inline", "__w64", "__int8", "__int16", "__int32", "__int64",
        "begin", "end", "cbegin", "cend", "rbegin", "rend", "crbegin", "crend", "size", "length", "empty",
        "clear", "insert", "erase", "push_back", "pop_back", "push_front", "pop_front", "emplace", "emplace_back",
        "emplace_front", "front", "back", "first", "second", "get", "make_pair", "make_tuple", "tie", "swap",
        "reserve", "capacity", "shrink_to_fit", "find", "count", "contains", "lower_bound", "upper_bound",
        "equal_range", "iterator", "const_iterator", "reverse_iterator", "const_reverse_iterator",
        "value_type", "reference", "const_reference", "pointer", "const_pointer", "difference_type",
        "filesystem", "chrono", "thread", "mutex", "atomic", "regex", "copy", "move", "transform", "sort",
        "find_if", "remove", "remove_if", "replace", "cin", "cout", "cerr", "endl", "make_shared", "make_unique",
        "async", "future", "promise", "lock_guard", "unique_lock",
        "Class", "Var", "Func", "Enum", "Macro", "File", "Property", "Typedef",
        "google", "protobuf", "boost", "testing", "benchmark", "web", "utility", "concurrency", "pplx", "nlohmann", "json", "http",
        "TEST", "TEST_F", "TEST_P", "TYPED_TEST", "TYPED_TEST_P", "EXPECT_EQ", "ASSERT_EQ", "EXPECT_TRUE", "ASSERT_TRUE", "EXPECT_FALSE", "ASSERT_FALSE"
    };
    public VaultExtractor(DTE2 dte, AsyncPackage? package = null)
    {
      _dte = dte;
      _package = package;
    }

    private async System.Threading.Tasks.Task SynchronizeExternalPdbsAsync(string targetPdbDir)
    {
      try
      {
        string sourceDir = "";

        if (_package != null)
        {
            var options = (IPVaultOptions)_package.GetDialogPage(typeof(IPVaultOptions));
            sourceDir = options?.PdbDirectory ?? "";
        }

        // Fallback to Environment Variable
        if (string.IsNullOrWhiteSpace(sourceDir))
        {
            sourceDir = Environment.GetEnvironmentVariable("IPVAULT_EXTERNAL_PDB_DIR") ?? "";
        }

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

        // 2. Save to WhiteList.json
        SaveFileList(solutionFiles, whitelistPath);
        IpVaultLogger.Log($"[IPVault] Solution scan complete. Found {solutionFiles.Count} files. Whitelist updated.");

        // 3. Build Blacklist from Non-Proprietary Modules in all PDBs
        HashSet<string> blacklist = new HashSet<string>(StringComparer.Ordinal);
        string[] pdbFiles = Directory.Exists(pdbDirPath) ? Directory.GetFiles(pdbDirPath, "*.pdb") : new string[0];

        IpVaultLogger.Log("[IPVault] Building blacklist from external PDB modules...");
        foreach (string pdbPath in pdbFiles)
        {
            BuildBlacklistFromPdb(pdbPath, solutionFiles, blacklist);
        }
        IpVaultLogger.Log($"[IPVault] Blacklist built with {blacklist.Count} terms.");

        // 4. Process PDBs for Proprietary Symbols
        Dictionary<string, string> ipNameWithTypes = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (string pdbPath in pdbFiles)
        {
          IpVaultLogger.Log($"[IPVault] Parsing PDB for proprietary symbols: {pdbPath}");
          ExtractProprietaryFromPdb(pdbPath, solutionFiles, blacklist, ipNameWithTypes);
        }

        // 5. IntelliSense Extraction
        IpVaultLogger.Log("[IPVault] Starting IntelliSense extraction...");
        foreach (Project project in EnumerateProjects(solution.Projects))
        {
            if (project.ProjectItems != null)
                ExtractFromIntelliSense(project.ProjectItems, solutionFiles, ipNameWithTypes);
        }

        // 5.5 Extract File and Folder Names
        IpVaultLogger.Log("[IPVault] Extracting file and folder names...");
        foreach (string file in solutionFiles)
        {
            try
            {
                string[] pathParts = file.Split(new char[] { Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar }, StringSplitOptions.RemoveEmptyEntries);
                foreach (string part in pathParts)
                {
                    string cleanPart = Path.GetFileNameWithoutExtension(part);
                    // Avoid adding drive letters or very short directory names
                    if (cleanPart.Length > 3 && !cleanPart.EndsWith(":") && !ipNameWithTypes.ContainsKey(cleanPart))
                    {
                        ipNameWithTypes[cleanPart] = "File";
                    }
                }
            }
            catch { }
        }

        // 6. Consolidation & Tokenization
        IpVaultLogger.Log("[IPVault] Extracting file and folder names...");
        foreach (string file in solutionFiles)
        {
            try
            {
                string[] pathParts = file.Split(new char[] { Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar }, StringSplitOptions.RemoveEmptyEntries);
                foreach (string part in pathParts)
                {
                    string cleanPart = Path.GetFileNameWithoutExtension(part);
                    // Avoid adding drive letters or very short directory names
                    if (cleanPart.Length > 3 && !cleanPart.EndsWith(":") && !ipNameWithTypes.ContainsKey(cleanPart))
                    {
                        ipNameWithTypes[cleanPart] = "File";
                    }
                }
            }
            catch { }
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

    private bool IsFileProprietary(string filePath, HashSet<string> whitelistSet)
    {
        if (string.IsNullOrEmpty(filePath)) return false;

        string fullPath;
        try { fullPath = Path.GetFullPath(filePath); }
        catch { return false; }

        if (whitelistSet.Contains(fullPath)) return true;

        if (fullPath.EndsWith(".pb.h", StringComparison.OrdinalIgnoreCase) ||
            fullPath.EndsWith(".pb.cc", StringComparison.OrdinalIgnoreCase))
        {
            string fileName = Path.GetFileName(fullPath);
            if (fileName.EndsWith(".pb.h", StringComparison.OrdinalIgnoreCase))
                fileName = fileName.Substring(0, fileName.Length - 5);
            else if (fileName.EndsWith(".pb.cc", StringComparison.OrdinalIgnoreCase))
                fileName = fileName.Substring(0, fileName.Length - 6);

            string expected = "\\" + fileName + ".proto";
            return whitelistSet.Any(w => w.EndsWith(expected, StringComparison.OrdinalIgnoreCase));
        }

        return false;
    }

    private void BuildBlacklistFromPdb(string pdbPath, HashSet<string> whitelistSet, HashSet<string> blacklist)
    {
      try
      {
        using (var pdb = new PdbFile(pdbPath))
        {
          var dbi = pdb.DbiStream;
          if (dbi == null) return;

          foreach (var module in dbi.Modules)
          {
            bool isProprietary = false;
            if (module.Files != null)
            {
              foreach (var sf in module.Files)
              {
                if (IsFileProprietary(sf, whitelistSet))
                {
                  isProprietary = true;
                  break;
                }
              }
            }

            // If module is purely external, add only Types and Functions to blacklist to avoid polluting with common variable names
            if (!isProprietary)
            {
              var localSymbols = module.LocalSymbolStream;
              if (localSymbols == null || localSymbols.References == null) continue;

              for (int i = 0; i < localSymbols.References.Count; i++)
              {
                var sym = localSymbols[i];
                if (sym is UdtSymbol || sym is ProcedureSymbol)
                {
                    string name = GetNameFromSymbol(sym);
                    if (!string.IsNullOrEmpty(name)) AddToBlacklist(name, blacklist);
                }
              }
            }
          }

          // Global and Public symbols in what we assume are system PDBs are also blacklisted
          bool pdbHasProprietary = dbi.Modules.Any(m => m.Files != null && m.Files.Any(f => IsFileProprietary(f, whitelistSet)));
          if (!pdbHasProprietary)
          {
              if (pdb.GlobalsStream != null && pdb.GlobalsStream.Symbols != null)
              {
                  for (int i = 0; i < pdb.GlobalsStream.Symbols.Count; i++)
                  {
                      string name = GetNameFromSymbol(pdb.GlobalsStream.Symbols[i]);
                      if (!string.IsNullOrEmpty(name)) AddToBlacklist(name, blacklist);
                  }
              }
              if (pdb.PublicsStream != null && pdb.PublicsStream.PublicSymbols != null)
              {
                  foreach (var ps in pdb.PublicsStream.PublicSymbols)
                  {
                      string name = GetNameFromSymbol(ps);
                      if (!string.IsNullOrEmpty(name)) AddToBlacklist(name, blacklist);
                  }
              }
          }
        }
      }
      catch { }
    }

    private void AddToBlacklist(string fullName, HashSet<string> blacklist)
    {
        char[] separators = new char[] { '?', ':', '.', '_', '<', '>', ',', ' ', '&', '*', '(', ')', '[', ']', '-', '+', '=', '~', '`', '\'', '\"', '\\', '/', '$', '@', '!' };
        string[] parts = fullName.Split(separators, StringSplitOptions.RemoveEmptyEntries);
        foreach (var part in parts)
        {
            if (string.IsNullOrEmpty(part) || char.IsDigit(part[0])) continue;
            blacklist.Add(part);
        }
    }

    private void ExtractProprietaryFromPdb(string pdbPath, HashSet<string> whitelistSet, HashSet<string> blacklist, Dictionary<string, string> ipNames)
    {
      try
      {
        using (var pdb = new PdbFile(pdbPath))
        {
          var dbi = pdb.DbiStream;
          if (dbi == null) return;

          foreach (var module in dbi.Modules)
          {
            bool isProprietary = false;
            if (module.Files != null)
            {
              foreach (var sf in module.Files)
              {
                if (IsFileProprietary(sf, whitelistSet))
                {
                  isProprietary = true;
                  break;
                }
              }
            }

            if (!isProprietary) continue;

            var localSymbols = module.LocalSymbolStream;
            if (localSymbols == null || localSymbols.References == null) continue;

            for (int i = 0; i < localSymbols.References.Count; i++)
            {
              var sym = localSymbols[i];
              if (sym == null) continue;
              string fullName = GetNameFromSymbol(sym);
              if (string.IsNullOrEmpty(fullName)) continue;

              string type = "Var";
              if (sym is ProcedureSymbol) type = "Func";
              else if (sym is ConstantSymbol || sym is LocalSymbol || sym is DataSymbol) type = "Var";
              else if (sym is UdtSymbol us)
              {
                  type = "Class";
                  ExtractMembersFromUdt(pdb, us, ipNames, blacklist);
              }

              ProcessAndFilterSymbol(fullName, type, ipNames, blacklist);
            }
          }

          // Process GlobalsStream to catch enums and global types not bound to local module streams
          if (pdb.GlobalsStream != null && pdb.GlobalsStream.Symbols != null)
          {
              for (int i = 0; i < pdb.GlobalsStream.Symbols.Count; i++)
              {
                  var sym = pdb.GlobalsStream.Symbols[i];
                  if (sym == null) continue;
                  string fullName = GetNameFromSymbol(sym);
                  if (string.IsNullOrEmpty(fullName)) continue;

                  string type = "Var";
                  if (sym is ProcedureSymbol) type = "Func";
                  else if (sym is ConstantSymbol || sym is LocalSymbol || sym is DataSymbol) type = "Var";
                  else if (sym is UdtSymbol us)
                  {
                      type = "Class";
                      ExtractMembersFromUdt(pdb, us, ipNames, blacklist);
                  }

                  ProcessAndFilterSymbol(fullName, type, ipNames, blacklist);
              }
          }
        }
      }
      catch (Exception ex)
      {
        IpVaultLogger.Log($"[IPVault] Error reading PDB {pdbPath}: {ex.Message}");
      }
    }

    private void ExtractMembersFromUdt(PdbFile pdb, UdtSymbol us, Dictionary<string, string> ipNames, HashSet<string> blacklist)
    {
        try
        {
            var tpi = pdb.TpiStream;
            if (tpi == null) return;

            var typeRecord = tpi[us.Type];
            TypeIndex fieldListIndex = default;

            if (typeRecord is ClassRecord cr)
            {
                fieldListIndex = cr.FieldList;
            }
            else if (typeRecord is EnumRecord er)
            {
                fieldListIndex = er.FieldList;
            }

            if (fieldListIndex == default) return;

            var fieldListRecord = tpi[fieldListIndex] as FieldListRecord;
            if (fieldListRecord == null || fieldListRecord.Fields == null) return;

            foreach (var field in fieldListRecord.Fields)
            {
                if (field is DataMemberRecord dmr)
                {
                    string fieldName = dmr.Name.ToString();
                    if (!string.IsNullOrEmpty(fieldName))
                    {
                        ProcessAndFilterSymbol(fieldName, "Var", ipNames, blacklist);
                    }
                }
                else if (field is EnumeratorRecord enr)
                {
                    string enumName = enr.Name.ToString();
                    if (!string.IsNullOrEmpty(enumName))
                    {
                        ProcessAndFilterSymbol(enumName, "Enum", ipNames, blacklist);
                    }
                }
                else
                {
                    string name = GetNameFromSymbol(field);
                    if (!string.IsNullOrEmpty(name))
                    {
                        ProcessAndFilterSymbol(name, "Var", ipNames, blacklist);
                    }
                }
            }
        }
        catch {}
    }

    private bool IsThirdPartyNamespace(string name)
    {
        string clean = name.Replace("const ", "").Replace("struct ", "").Replace("class ", "").Replace("enum ", "").Trim();
        int spaceIdx = clean.IndexOf(' ');
        if (spaceIdx > 0 && spaceIdx < clean.IndexOf("::"))
        {
            clean = clean.Substring(spaceIdx + 1).Trim();
        }

        return clean.StartsWith("std::") ||
               clean.StartsWith("__gnu_cxx::") ||
               clean.StartsWith("google::protobuf::") ||
               clean.StartsWith("boost::") ||
               clean.StartsWith("testing::") ||
               clean.StartsWith("benchmark::") ||
               clean.StartsWith("web::") ||
               clean.StartsWith("utility::") ||
               clean.StartsWith("concurrency::") ||
               clean.StartsWith("pplx::") ||
               clean.StartsWith("nlohmann::");
    }

    private void ProcessAndFilterSymbol(string fullName, string defaultType, Dictionary<string, string> ipNames, HashSet<string>? blacklist)
    {
        if (string.IsNullOrEmpty(fullName)) return;

        if (IsThirdPartyNamespace(fullName))
        {
            // Extract the third-party namespace chain terms so we never tokenize them anywhere
            int start = fullName.IndexOf('<');
            string chain = start != -1 ? fullName.Substring(0, start) : fullName;

            // For a function, remove the argument list as well
            int parenStart = chain.IndexOf('(');
            if (parenStart != -1) chain = chain.Substring(0, parenStart);

            string[] chainParts = chain.Split(new[] { "::", "." }, StringSplitOptions.RemoveEmptyEntries);
            foreach (string cp in chainParts)
            {
                string cleanCp = cp.Trim('?', '&', '*'); // MSVC and pointer artifacts
                if (!string.IsNullOrEmpty(cleanCp) && !char.IsDigit(cleanCp[0]))
                {
                    _thirdPartyChainTerms.Add(cleanCp);
                }
            }

            // Discard the third-party shell, but extract and process its template arguments
            if (start != -1)
            {
                int end = fullName.LastIndexOf('>');
                if (end > start)
                {
                    string inner = fullName.Substring(start + 1, end - start - 1);
                    var args = SplitTemplateArgs(inner);
                    foreach (var arg in args)
                    {
                        ProcessAndFilterSymbol(arg.Trim(), defaultType, ipNames, blacklist);
                    }
                }
            }
            return;
        }

        // Normal proprietary symbol
        AddProcessedNames(fullName, defaultType, ipNames, blacklist);
    }

    private List<string> SplitTemplateArgs(string inner)
    {
        var list = new List<string>();
        int depth = 0;
        int lastStart = 0;
        for (int i = 0; i < inner.Length; i++)
        {
            if (inner[i] == '<') depth++;
            else if (inner[i] == '>') depth--;
            else if (inner[i] == ',' && depth == 0)
            {
                list.Add(inner.Substring(lastStart, i - lastStart));
                lastStart = i + 1;
            }
        }
        if (lastStart < inner.Length)
        {
            list.Add(inner.Substring(lastStart));
        }
        return list;
    }

    private void AddProcessedNames(string fullName, string defaultType, Dictionary<string, string> ipNames, HashSet<string>? blacklist)
    {
        char[] separators = new char[] { '?', ':', '.', '_', '<', '>', ',', ' ', '&', '*', '(', ')', '[', ']', '-', '+', '=', '~', '`', '\'', '\"', '\\', '/', '$', '@', '!' };
        string[] parts = fullName.Split(separators, StringSplitOptions.RemoveEmptyEntries);

        foreach (string part in parts)
        {
            if (string.IsNullOrEmpty(part)) continue;

            // Filter MSVC mangling artifacts and pure numbers (valid identifiers don't start with digits)
            if (char.IsDigit(part[0])) continue;

            // Apply blacklist if provided
            if (blacklist != null && blacklist.Contains(part)) continue;

            if (_cppKeywords.Contains(part)) continue;

            if (!ipNames.ContainsKey(part))
            {
                string type = defaultType;
                if (parts.Length > 1 && part != parts.Last()) type = "Class";
                ipNames[part] = type;
            }
        }
    }

    private string GetNameFromSymbol(object sym)
    {
      if (sym == null) return "";

      // SymbolRecords
      if (sym is ProcedureSymbol rs) return rs.Name.ToString();
      if (sym is Public32Symbol ps) return ps.Name.ToString();
      if (sym is DataSymbol ds) return ds.Name.ToString();
      if (sym is ConstantSymbol cs) return cs.Name.ToString();
      if (sym is UdtSymbol us) return us.Name.ToString();
      if (sym is LocalSymbol ls) return ls.Name.ToString();
      if (sym is RegisterRelativeSymbol rrs) return rrs.Name.ToString();
      if (sym is ThreadLocalDataSymbol tds) return tds.Name.ToString();
      if (sym is FileStaticSymbol fss) return fss.Name.ToString();
      if (sym is ExportSymbol es) return es.Name.ToString();
      if (sym is BlockSymbol bs) return bs.Name.ToString();
      if (sym is LabelSymbol lsym) return lsym.Name.ToString();
      if (sym is ManagedProcedureSymbol mps) return mps.Name.ToString();
      if (sym is ObjectNameSymbol ons) return ons.Name.ToString();
      if (sym is Thunk32Symbol t32s) return t32s.Name.ToString();

      // TypeRecords
      if (sym is EnumeratorRecord er) return er.Name.ToString();
      if (sym is DataMemberRecord dmr) return dmr.Name.ToString();
      if (sym is EnumRecord enr) return enr.Name.ToString();
      if (sym is ClassRecord cr) return cr.Name.ToString();

      try
      {
          var prop = sym.GetType().GetProperty("Name", System.Reflection.BindingFlags.Public | System.Reflection.BindingFlags.Instance | System.Reflection.BindingFlags.FlattenHierarchy);
          if (prop != null) return prop.GetValue(sym)?.ToString() ?? "";
          var field = sym.GetType().GetField("Name", System.Reflection.BindingFlags.Public | System.Reflection.BindingFlags.Instance | System.Reflection.BindingFlags.FlattenHierarchy);
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
              if (IsFileProprietary(path, whitelist))
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
        string fullName = element.FullName;
        if (string.IsNullOrEmpty(fullName)) fullName = element.Name;

        if (!string.IsNullOrEmpty(fullName))
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
            case vsCMElement.vsCMElementNamespace:
              type = "Class";
              break;
          }

          if (!string.IsNullOrEmpty(type))
          {
              AddProcessedNames(fullName, type, ipNames, null);
          }
        }

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
        if (name == "main") continue;
        if (_thirdPartyChainTerms.Contains(name)) continue;

        string type = names[name];
        map[name] = $"{type}_{counters[type]++}";
      }
      return map;
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
              if (!string.IsNullOrEmpty(path))
              {
                string fullPath = Path.GetFullPath(path);
                fileList.Add(fullPath);

                // Protocol Buffer Mapping: .proto -> .pb.h
                if (fullPath.EndsWith(".proto", StringComparison.OrdinalIgnoreCase))
                {
                    string pbhPath = Path.ChangeExtension(fullPath, ".pb.h");
                    fileList.Add(pbhPath);
                }
              }
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
