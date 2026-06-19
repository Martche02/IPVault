import os
import sys
import ast
import re
import json
import keyword
import builtins

# Global sets for classifications
class_names = set()
func_names = set()
var_names = set()
file_names = set()

# Programmatically build base blacklist (reserved keywords, built-ins, and magic methods)
BASE_BLACKLIST = set(keyword.kwlist) | set(dir(builtins)) | {
    "self", "cls", "__init__", "__str__", "__repr__", "__name__", "__main__", "__module__",
    "__dict__", "__weakref__", "__doc__", "__file__", "__package__", "__loader__", "__spec__",
    "__path__", "__cached__", "args", "kwargs", "argv"
}

# Add standard library module names to blacklist to avoid masking them if imported
STANDARD_LIBS = {
    # Standard library module names
    "os", "sys", "re", "json", "math", "datetime", "time", "collections", "itertools", 
    "functools", "pathlib", "shutil", "argparse", "subprocess", "logging", "threading", 
    "multiprocessing", "uuid", "hashlib", "socket", "select", "asyncio", "csv", "xml", 
    "ast", "parser", "typing", "tempfile", "traceback", "pdb", "unittest", "mock",
    "urllib", "http", "html", "email", "ftplib", "sqlite3", "io", "glob", "fnmatch",
    "pickle", "copy", "weakref", "gc", "inspect", "struct", "ctypes",
    # Well-known external libraries and their common aliases
    "pandas", "numpy", "matplotlib", "seaborn", "tensorflow", "torch", "scipy", "sklearn",
    "keras", "jax", "cv2", "pil", "requests", "flask", "django", "fastapi", "uvicorn",
    "pytest", "sqlalchemy", "yaml", "toml", "jinja2", "click", "tqdm", "boto3", "pymongo",
    "redis", "pydantic", "black", "flake8",
    "pd", "np", "plt", "sns", "tf"
}
BASE_BLACKLIST |= STANDARD_LIBS

# SQL Reserved Keywords Blacklist
SQL_KEYWORDS = {
    "select", "insert", "update", "delete", "from", "where", "join", "on", "create", 
    "table", "int", "integer", "varchar", "text", "drop", "into", "values", "and", "or", 
    "not", "null", "primary", "key", "foreign", "references", "database", "index", "view", 
    "procedure", "function", "returns", "as", "begin", "end", "if", "else", "declare", 
    "set", "exec", "execute", "with", "by", "order", "group", "having", "count", "sum", 
    "min", "max", "avg", "left", "right", "inner", "outer", "cross", "union", "all", 
    "any", "some", "exists", "in", "like", "between", "is", "true", "false", "add", 
    "alter", "column", "constraint", "default", "unique", "check", "numeric", "decimal", 
    "float", "double", "date", "datetime", "timestamp", "boolean", "bigint", "smallint"
}

# Batch Reserved Keywords Blacklist
BATCH_KEYWORDS = {
    "echo", "set", "call", "exit", "goto", "if", "else", "rem", "pause", "cls", 
    "errorlevel", "for", "in", "do", "del", "copy", "move", "mkdir", "rmdir", "type", 
    "find", "findstr", "attrib", "assoc", "ftype", "path", "pushd", "popd", "cd", "dir", 
    "start", "taskkill", "tasklist", "xcopy", "robocopy", "powershell", "cmd", "python", 
    "git", "npm", "dotnet", "msbuild", "defined", "exist", "not", "nul", "con"
}

# Common Python object/type attribute and method names that should NOT be masked
COMMON_ATTRIBUTES = {
    # List/Dict/Set/String methods
    "append", "extend", "insert", "remove", "pop", "clear", "index", "count", "sort", "reverse", "copy",
    "keys", "values", "items", "get", "fromkeys", "popitem", "setdefault", "update",
    "add", "difference", "difference_update", "discard", "intersection", "intersection_update",
    "isdisjoint", "issubset", "issuperset", "symmetric_difference", "symmetric_difference_update", "union",
    "capitalize", "casefold", "center", "encode", "endswith", "expandtabs", "find", "format", "format_map",
    "isalnum", "isalpha", "isascii", "isdecimal", "isdigit", "isidentifier", "islower", "isnumeric",
    "isprintable", "isspace", "istitle", "isupper", "join", "ljust", "lower", "lstrip", "maketrans",
    "partition", "removeprefix", "removesuffix", "replace", "rfind", "rindex", "rjust", "rpartition",
    "rsplit", "rstrip", "split", "splitlines", "startswith", "strip", "swapcase", "title", "translate",
    "upper", "zfill",
    # File / IO methods
    "close", "detach", "fileno", "flush", "isatty", "read", "readable", "readline", "readlines",
    "seek", "seekable", "tell", "truncate", "writable", "write", "writelines",
    # Standard library / framework / common naming conventions
    "dumps", "loads", "dump", "load", "path", "exists", "dirname", "basename", "abspath", "isdir", "isfile",
    "env", "environ", "exit", "argv", "logger", "info", "warning", "error", "critical", "debug", "exception", "log",
    "run", "start", "stop", "main", "parse", "args", "kwargs", "setup", "teardown", "test"
}

def is_valid_identifier(name):
    # Skips empty, keywords, numeric-starting, or very short names (unless they're variables, but we keep min len of 2)
    if not name:
        return False
    if name.lower() in BASE_BLACKLIST:
        return False
    if name[0].isdigit():
        return False
    if len(name) < 2:
        return False
    return True

def get_local_modules(workspace_dir):
    """Scan workspace to identify local python modules and packages."""
    local_modules = set()
    for root, dirs, files in os.walk(workspace_dir):
        # Prune ignore folders in-place
        dirs[:] = [d for d in dirs if d not in {".git", ".venv", "venv", "env", "__pycache__", ".vscode", ".vs", "node_modules", "build", "dist"}]
        
        # Add directories as package names
        for d in dirs:
            local_modules.add(d)
        for f in files:
            if f.endswith(".py"):
                name = f[:-3]
                if name != "__init__":
                    local_modules.add(name)
    return local_modules

class PythonSymbolExtractor(ast.NodeVisitor):
    def __init__(self, local_modules):
        super().__init__()
        self.local_modules = local_modules

    def visit_ClassDef(self, node):
        if is_valid_identifier(node.name):
            class_names.add(node.name)
        self.generic_visit(node)

    def visit_FunctionDef(self, node):
        if is_valid_identifier(node.name):
            func_names.add(node.name)
        # Extract arguments/parameters
        for arg in node.args.args:
            if is_valid_identifier(arg.arg):
                var_names.add(arg.arg)
        for arg in node.args.kwonlyargs:
            if is_valid_identifier(arg.arg):
                var_names.add(arg.arg)
        if node.args.vararg and is_valid_identifier(node.args.vararg.arg):
            var_names.add(node.args.vararg.arg)
        if node.args.kwarg and is_valid_identifier(node.args.kwarg.arg):
            var_names.add(node.args.kwarg.arg)
        self.generic_visit(node)

    def visit_AsyncFunctionDef(self, node):
        self.visit_FunctionDef(node)

    def visit_Assign(self, node):
        for target in node.targets:
            self._extract_target(target)
        self.generic_visit(node)

    def visit_AnnAssign(self, node):
        self._extract_target(node.target)
        self.generic_visit(node)

    def visit_NamedExpr(self, node):
        self._extract_target(node.target)
        self.generic_visit(node)

    def visit_Import(self, node):
        for alias in node.names:
            name_parts = alias.name.split('.')
            base_module = name_parts[0]
            # Only protect if it is a local module
            if base_module in self.local_modules:
                if alias.asname:
                    if is_valid_identifier(alias.asname):
                        var_names.add(alias.asname)
                else:
                    if is_valid_identifier(alias.name):
                        var_names.add(alias.name)
        self.generic_visit(node)

    def visit_ImportFrom(self, node):
        if node.module:
            base_module = node.module.split('.')[0]
            if base_module in self.local_modules:
                for alias in node.names:
                    name_to_check = alias.asname or alias.name
                    if is_valid_identifier(name_to_check):
                        var_names.add(name_to_check)
        self.generic_visit(node)

    def visit_Attribute(self, node):
        # Extract attributes/methods accessed on self or other proprietary objects/classes
        if is_valid_identifier(node.attr):
            attr_lower = node.attr.lower()
            if node.attr not in COMMON_ATTRIBUTES and attr_lower not in COMMON_ATTRIBUTES:
                receiver_name = None
                if isinstance(node.value, ast.Name):
                    receiver_name = node.value.id
                elif isinstance(node.value, ast.Attribute):
                    base = node.value
                    while isinstance(base, ast.Attribute):
                        base = base.value
                    if isinstance(base, ast.Name):
                        receiver_name = base.id

                # Only protect if the receiver is local or self/cls (excluding external modules/libraries)
                if receiver_name in ("self", "cls") or (receiver_name and receiver_name not in BASE_BLACKLIST and receiver_name not in STANDARD_LIBS):
                    var_names.add(node.attr)
                    
        self.generic_visit(node)

    def _extract_target(self, node):
        if isinstance(node, ast.Name):
            if is_valid_identifier(node.id):
                var_names.add(node.id)
        elif isinstance(node, ast.Attribute):
            if is_valid_identifier(node.attr):
                var_names.add(node.attr)
            self._extract_target(node.value)
        elif isinstance(node, ast.Subscript):
            self._extract_target(node.value)
        elif isinstance(node, (ast.Tuple, ast.List)):
            for elt in node.elts:
                self._extract_target(elt)

def extract_python_symbols(filepath, local_modules):
    try:
        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
            code = f.read()
        tree = ast.parse(code, filepath)
        extractor = PythonSymbolExtractor(local_modules)
        extractor.visit(tree)
    except Exception as e:
        print(f"Error parsing Python file {filepath}: {e}", file=sys.stderr)

def extract_sql_symbols(filepath):
    try:
        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()
        
        # Strip single-line SQL comments
        content = re.sub(r'--.*', '', content)
        # Strip block SQL comments
        content = re.sub(r'/\*[\s\S]*?\*/', '', content)
        
        # Find all word tokens
        words = re.findall(r'\b[a-zA-Z_][a-zA-Z0-9_]*\b', content)
        for word in words:
            if word.lower() not in SQL_KEYWORDS and len(word) >= 2 and not word[0].isdigit():
                var_names.add(word)
    except Exception as e:
        print(f"Error parsing SQL file {filepath}: {e}", file=sys.stderr)

def extract_batch_symbols(filepath):
    try:
        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
            lines = f.readlines()
        
        for line in lines:
            # Strip comments
            stripped = line.strip()
            if stripped.lower().startswith("rem") or stripped.startswith("::"):
                continue
            
            # Find variable assignments: set NAME=value or set /p NAME=value or set /a NAME=value
            set_matches = re.findall(r'\bset\s+(?:/[pa]\s+)?([a-zA-Z_][a-zA-Z0-9_]*)\s*=', line, re.IGNORECASE)
            for var in set_matches:
                if var.lower() not in BATCH_KEYWORDS:
                    var_names.add(var)
            
            # Find %VAR% usage
            percent_matches = re.findall(r'%([a-zA-Z_][a-zA-Z0-9_]*)%', line)
            for var in percent_matches:
                if var.lower() not in BATCH_KEYWORDS:
                    var_names.add(var)
            
            # Find labels: :label_name
            label_match = re.match(r'^\s*:([a-zA-Z_][a-zA-Z0-9_]*)\b', line)
            if label_match:
                label = label_match.group(1)
                if label.lower() not in BATCH_KEYWORDS:
                    var_names.add(label)
    except Exception as e:
        print(f"Error parsing Batch file {filepath}: {e}", file=sys.stderr)

def load_requirements_txt(workspace_dir):
    req_path = os.path.join(workspace_dir, "requirements.txt")
    libs = set()
    if os.path.exists(req_path):
        try:
            with open(req_path, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith('#') or line.startswith('-'):
                        continue
                    # Match package name (letters, numbers, underscores, hyphens)
                    match = re.match(r'^([a-zA-Z0-9_\-]+)', line)
                    if match:
                        lib_name = match.group(1).replace('-', '_').lower()
                        libs.add(lib_name)
            print(f"Loaded {len(libs)} unprotected library names from requirements.txt")
        except Exception as e:
            print(f"Warning: Failed to read requirements.txt: {e}", file=sys.stderr)
    return libs

def main():
    if len(sys.argv) < 2:
        workspace_dir = os.getcwd()
    else:
        workspace_dir = os.path.abspath(sys.argv[1])

    if not os.path.isdir(workspace_dir):
        print(f"Error: Workspace directory '{workspace_dir}' does not exist.", file=sys.stderr)
        sys.exit(1)

    # Load dynamic unprotected libraries from requirements.txt
    req_libs = load_requirements_txt(workspace_dir)
    if req_libs:
        STANDARD_LIBS.update(req_libs)
        BASE_BLACKLIST.update(req_libs)

    print(f"Scanning workspace: {workspace_dir}")
    
    local_modules = get_local_modules(workspace_dir)
    print(f"Identified {len(local_modules)} local modules/packages.")

    # Walk the directory
    for root, dirs, files in os.walk(workspace_dir):
        # Ignore common non-project folders
        dirs[:] = [d for d in dirs if d not in {".git", ".venv", "venv", "env", "__pycache__", ".vscode", ".vs", "node_modules", "build", "dist"}]
        
        # Extract folder names as File names (length > 3, not drive, not already classified)
        for d in dirs:
            if len(d) > 3 and not d.endswith(":") and is_valid_identifier(d):
                file_names.add(d)

        for file in files:
            filepath = os.path.join(root, file)
            
            # Extract file name without extension
            clean_name = os.path.splitext(file)[0]
            if len(clean_name) > 3 and is_valid_identifier(clean_name):
                file_names.add(clean_name)
                
            if file.endswith(".py"):
                extract_python_symbols(filepath, local_modules)
            elif file.endswith(".sql"):
                extract_sql_symbols(filepath)
            elif file.endswith((".bat", ".cmd")):
                extract_batch_symbols(filepath)

    # Generate flat map
    token_map = {}
    
    # We want to assign IDs deterministically or sequentially
    # Sort for consistent mapping across runs
    sorted_classes = sorted(list(class_names))
    sorted_funcs = sorted(list(func_names))
    sorted_vars = sorted(list(var_names))
    sorted_files = sorted(list(file_names))
    
    class_idx = 1
    func_idx = 1
    var_idx = 1
    file_idx = 1
    
    for c in sorted_classes:
        token_map[c] = f"Class_{class_idx}"
        class_idx += 1
        
    for f in sorted_funcs:
        # Avoid overriding class name
        if f not in token_map:
            token_map[f] = f"Func_{func_idx}"
            func_idx += 1
            
    for v in sorted_vars:
        if v not in token_map:
            token_map[v] = f"Var_{var_idx}"
            var_idx += 1
            
    for fl in sorted_files:
        if fl not in token_map:
            token_map[fl] = f"File_{file_idx}"
            file_idx += 1

    # Output directory
    vscode_dir = os.path.join(workspace_dir, ".vscode")
    os.makedirs(vscode_dir, exist_ok=True)
    
    output_path = os.path.join(vscode_dir, "filter.json")
    with open(output_path, "w", encoding="utf-8") as out:
        json.dump(token_map, out, indent=2)
        
    print(f"IP Vault map successfully generated with {len(token_map)} protected entries!")
    print(f"Map saved to: {output_path}")

if __name__ == "__main__":
    main()
