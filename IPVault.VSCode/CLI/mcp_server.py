import os
import sys
import re
import json
import uuid
import subprocess
import asyncio
import shutil

_forwardMap = {}
_reverseMap = {}
_dynamicReverseMap = {}
_dynamicVarCounter = 1

_strCounter = 1
_commentCounter = 1
_lambdaCounter = 1

_solutionDir = os.getcwd()

def load_map(path):
    global _forwardMap, _reverseMap, _dynamicVarCounter
    try:
        if os.path.exists(path):
            with open(path, "r", encoding="utf-8") as f:
                map_data = json.load(f)
                _forwardMap = map_data
                _reverseMap = {v: k for k, v in map_data.items()}
            
            # Initialize dynamic variable counter to max existing index + 1
            max_idx = 0
            for v in _forwardMap.values():
                if isinstance(v, str) and v.startswith("Var_"):
                    try:
                        idx = int(v[4:])
                        if idx > max_idx:
                            max_idx = idx
                    except:
                        pass
            _dynamicVarCounter = max_idx + 1
            
            print(f"[IPVault.Mcp] Loaded map with {len(_forwardMap)} keys from {path} (next dynamic index: {_dynamicVarCounter})", file=sys.stderr)
        else:
            print(f"[IPVault.Mcp] Warning: Map file not found at {path}", file=sys.stderr)
    except Exception as e:
        print(f"[IPVault.Mcp] Error loading map file '{path}': {e}", file=sys.stderr)

# Programmatically build base blacklist (reserved keywords, built-ins, and magic methods)
import keyword
import builtins

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

# Standard python library modules and common external packages/aliases
UNPROTECTED_ROOTS = {
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

BASE_BLACKLIST = set(keyword.kwlist) | set(dir(builtins)) | {
    "self", "cls", "__init__", "__str__", "__repr__", "__name__", "__main__", "__module__",
    "__dict__", "__weakref__", "__doc__", "__file__", "__package__", "__loader__", "__spec__",
    "__path__", "__cached__", "args", "kwargs", "argv"
} | SQL_KEYWORDS | BATCH_KEYWORDS | UNPROTECTED_ROOTS

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
    if not name:
        return False
    if name.lower() in BASE_BLACKLIST:
        return False
    if name[0].isdigit():
        return False
    if len(name) < 2:
        return False
    return True

# String tokenizing regex
# Matches Python comments starting with #
# For CMD/Batch comments, we don't treat # as a comment start since # can be part of paths, but for python we do.
COMMENT_RE = re.compile(r'#.*')

# Matches Python lambdas: lambda [args]: [expr]
LAMBDA_RE = re.compile(r'\blambda\b[^:]*:[^,\n)]*')

def filter_text(text):
    global _strCounter, _commentCounter, _lambdaCounter, _dynamicVarCounter
    
    # 0. Detect and dynamically register attributes accessed on protected names (recursively)
    if _forwardMap:
        # Match dot-separated identifier chains: identifier.attr1.attr2...
        chain_regex = re.compile(r'\b[a-zA-Z_][a-zA-Z0-9_]*(?:\.[a-zA-Z_][a-zA-Z0-9_]*)+\b')
        new_regs = {}
        for match in chain_regex.finditer(text):
            chain = match.group(0)
            parts = chain.split('.')
            if not parts:
                continue
            
            root = parts[0]
            # Check if root is known unprotected
            if root.lower() in UNPROTECTED_ROOTS or root.lower() in BASE_BLACKLIST:
                if root in ("self", "cls"):
                    start_idx = 1
                else:
                    # Skip the whole chain because the root is unprotected (e.g. numpy.random.rand)
                    continue
            else:
                start_idx = 0
                
            # Protect every valid identifier in the proprietary chain from start_idx onwards
            for i in range(start_idx, len(parts)):
                attr = parts[i]
                if is_valid_identifier(attr) and attr not in _forwardMap and attr not in new_regs:
                    if attr not in COMMON_ATTRIBUTES and attr.lower() not in COMMON_ATTRIBUTES:
                        token = f"Var_{_dynamicVarCounter}"
                        _dynamicVarCounter += 1
                        new_regs[attr] = token
                            
        # Apply all new registrations to the map
        for attr, token in new_regs.items():
            _forwardMap[attr] = token
            _reverseMap[token] = attr
            print(f"[IPVault.Mcp] Dynamically registered nested attribute '{attr}' -> '{token}'", file=sys.stderr)
                            
        # Apply all new registrations to the map
        for attr, token in new_regs.items():
            _forwardMap[attr] = token
            _reverseMap[token] = attr
            print(f"[IPVault.Mcp] Dynamically registered nested attribute '{attr}' -> '{token}'", file=sys.stderr)

    # 1. Apply Map replacements first (boundaries)
    # Sort keys by length descending to avoid partial matches
    sorted_forward = sorted(_forwardMap.items(), key=lambda x: len(x[0]), reverse=True)
    for original, masked in sorted_forward:
        pattern = r'\b' + re.escape(original) + r'\b'
        text = re.sub(pattern, masked, text)

    # Helper function to tokenize a match
    def add_dynamic_token(token_prefix, val, counter_name):
        nonlocal text
        counter_val = globals()[counter_name]
        token = f"{token_prefix}_{counter_val}"
        globals()[counter_name] += 1
        _dynamicReverseMap[token] = val
        return token

    # 2. Tokenize comments
    def comment_repl(match):
        return add_dynamic_token("Comment", match.group(0), "_commentCounter")
    text = COMMENT_RE.sub(comment_repl, text)

    # 3. Tokenize lambdas
    def lambda_repl(match):
        return add_dynamic_token("Lambda", match.group(0), "_lambdaCounter")
    text = LAMBDA_RE.sub(lambda_repl, text)

    # 4. Tokenize strings and handle f-strings
    # Python strings regex (includes triple-quoted and single/double-quoted with prefixes)
    # Prefixes: f, r, fr, rf, b, br, rb, u (case insensitive)
    string_pattern = r'([fFrRuUbB]{0,2})' + r'(' + r'"""[\s\S]*?"""' + r'|' + r"'''[\s\S]*?'''" + r'|' + r'"(?:[^"\\]|\\.)*"' + r'|' + r"'(?:[^'\\]|\\.)*'" + r')'
    
    def string_repl(match):
        prefix = match.group(1).lower()
        content = match.group(2)
        
        # If it's an f-string, we want to extract and process expressions inside { }
        if 'f' in prefix:
            # We want to find matches inside curly braces. E.g. {var_name} or {func_call()}
            # But we must avoid double braces {{ and }} which are f-string escapes
            # Let's find single curly braces
            parts = []
            last_idx = 0
            
            # Simple brace parser
            depth = 0
            brace_start = -1
            i = 0
            while i < len(content):
                if content[i:i+2] == '{{':
                    i += 2
                    continue
                elif content[i:i+2] == '}}':
                    i += 2
                    continue
                elif content[i] == '{':
                    if depth == 0:
                        brace_start = i
                        # Literal part before the brace
                        literal_part = content[last_idx:brace_start]
                        if literal_part:
                            # Tokenize literal segment
                            lit_token = add_dynamic_token("Str", literal_part, "_strCounter")
                            parts.append(f"{{{lit_token}}}")
                    depth += 1
                elif content[i] == '}':
                    depth -= 1
                    if depth == 0 and brace_start != -1:
                        # Expression part inside the brace
                        expr = content[brace_start+1:i]
                        # Apply symbol filtering inside the expression
                        filtered_expr = filter_text(expr)
                        parts.append(f"{{{filtered_expr}}}")
                        last_idx = i + 1
                i += 1
            
            # Trailing literal part
            if last_idx < len(content):
                literal_part = content[last_idx:]
                if literal_part:
                    lit_token = add_dynamic_token("Str", literal_part, "_strCounter")
                    parts.append(f"{{{lit_token}}}")
                    
            # Return reconstituted f-string
            fstring_token = add_dynamic_token("FStr", prefix + "".join(parts), "_strCounter")
            return fstring_token
        else:
            # Non-f-string: tokenize the whole string
            str_token = add_dynamic_token("Str", match.group(0), "_strCounter")
            return str_token

    text = re.sub(string_pattern, string_repl, text)
    return text

def unfilter_text(text):
    # 1. Restore dynamic tokens (Strings, Comments, Lambdas, F-strings)
    # Sort keys by length descending to ensure longer tokens are restored first
    sorted_dynamic = sorted(_dynamicReverseMap.items(), key=lambda x: len(x[0]), reverse=True)
    for token, val in sorted_dynamic:
        text = text.replace(token, val)

    # 2. Restore Map Tokens
    sorted_reverse = sorted(_reverseMap.items(), key=lambda x: len(x[0]), reverse=True)
    for masked, original in sorted_reverse:
        pattern = r'\b' + re.escape(masked) + r'\b'
        text = re.sub(pattern, original, text)

    return text

async def open_in_editor(temp_file):
    code_path = shutil.which("code")
    if code_path:
        try:
            proc = await asyncio.create_subprocess_exec(
                "cmd.exe", "/c", code_path, "--wait", temp_file,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )
            await proc.wait()
            return
        except Exception as e:
            print(f"[IPVault.Mcp] Failed to open in VS Code: {e}. Falling back to notepad...", file=sys.stderr)
            
    # Fallback to Notepad
    try:
        proc = await asyncio.create_subprocess_exec("notepad.exe", temp_file)
        await proc.wait()
    except Exception as e:
        print(f"[IPVault.Mcp] Failed to open in Notepad: {e}", file=sys.stderr)

async def intercept_with_editor(tool_name, content):
    temp_file = os.path.join(os.environ.get("TEMP", "."), f"ipvault_mcp_{uuid.uuid4().hex}.txt")
    header = (
        "=== IPVAULT MCP INTERCEPT ===\r\n"
        f"Tool: {tool_name}\r\n"
        "Instructions: You can review and edit the content below.\r\n"
        "Save the file and close the editor tab (or Notepad) to continue sending this response back to the AI.\r\n"
        "=============================\r\n\r\n"
    )
    try:
        with open(temp_file, "w", encoding="utf-8") as f:
            f.write(header + content)
            
        await open_in_editor(temp_file)
    except Exception as e:
        print(f"[IPVault.Mcp] Error during editor interception: {e}", file=sys.stderr)

    new_content = ""
    try:
        if os.path.exists(temp_file):
            with open(temp_file, "r", encoding="utf-8") as f:
                new_content = f.read()
            os.remove(temp_file)
    except Exception as e:
        print(f"[IPVault.Mcp] Error reading/deleting temp file: {e}", file=sys.stderr)

    header_end = new_content.find("=============================\r\n\r\n")
    if header_end >= 0:
        return new_content[header_end + len("=============================\r\n\r\n"):]
        
    return new_content

async def show_to_user_with_editor(content):
    temp_file = os.path.join(os.environ.get("TEMP", "."), f"ipvault_mcp_show_{uuid.uuid4().hex}.txt")
    header = (
        "=== IPVAULT: AI SHARED THIS WITH YOU ===\r\n"
        "Instructions: The AI wants to show you this unmasked code/text.\r\n"
        "Close the editor tab (or Notepad) to continue. The AI will NOT see this content.\r\n"
        "========================================\r\n\r\n"
    )
    try:
        with open(temp_file, "w", encoding="utf-8") as f:
            f.write(header + content)
            
        await open_in_editor(temp_file)
    except Exception as e:
        print(f"[IPVault.Mcp] Error showing to user: {e}", file=sys.stderr)
    finally:
        try:
            if os.path.exists(temp_file):
                os.remove(temp_file)
        except:
            pass

def get_embedded_instructions():
    try:
        agents_md_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "AGENTS.md")
        if os.path.exists(agents_md_path):
            with open(agents_md_path, "r", encoding="utf-8") as f:
                return f.read()
    except Exception as e:
        print(f"[IPVault.Mcp] Failed to load instructions: {e}", file=sys.stderr)
    return "Security and masking guidelines for this IPVault protected environment."

async def handle_message(message_json):
    try:
        doc = json.loads(message_json)
    except Exception as e:
        return None

    if "jsonrpc" not in doc:
        return None

    method = doc.get("method", "")
    msg_id = doc.get("id", None)

    if method == "initialize":
        instructions = get_embedded_instructions()
        return {
            "jsonrpc": "2.0",
            "id": msg_id,
            "result": {
                "protocolVersion": "2024-11-05",
                "capabilities": {
                    "tools": {},
                    "resources": {},
                    "prompts": {}
                },
                "serverInfo": {
                    "name": "ipvault-mcp-python",
                    "version": "2.0.0"
                },
                "instructions": instructions
            }
        }
    elif method == "notifications/initialized":
        return None
    elif method == "resources/list":
        return {
            "jsonrpc": "2.0",
            "id": msg_id,
            "result": {
                "resources": [
                    {
                        "uri": "mcp://instructions/agents.md",
                        "name": "Agent Guidelines (AGENTS.md)",
                        "description": "Security and masking guidelines for this IPVault protected environment.",
                        "mimeType": "text/markdown"
                    }
                ]
            }
        }
    elif method == "resources/read":
        params = doc.get("params", {})
        uri = params.get("uri", "")
        if uri == "mcp://instructions/agents.md":
            return {
                "jsonrpc": "2.0",
                "id": msg_id,
                "result": {
                    "contents": [
                        {
                            "uri": "mcp://instructions/agents.md",
                            "mimeType": "text/markdown",
                            "text": get_embedded_instructions()
                        }
                    ]
                }
            }
        return None
    elif method == "prompts/list":
        return {
            "jsonrpc": "2.0",
            "id": msg_id,
            "result": {
                "prompts": [
                    {
                        "name": "get-guidelines",
                        "description": "Get the security and masking guidelines for this environment."
                    }
                ]
            }
        }
    elif method == "prompts/get":
        params = doc.get("params", {})
        name = params.get("name", "")
        if name == "get-guidelines":
            instructions = get_embedded_instructions()
            return {
                "jsonrpc": "2.0",
                "id": msg_id,
                "result": {
                    "description": "Security Guidelines",
                    "messages": [
                        {
                            "role": "user",
                            "content": {
                                "type": "text",
                                "text": "Please provide the AGENTS.md guidelines."
                            }
                        },
                        {
                            "role": "assistant",
                            "content": {
                                "type": "text",
                                "text": instructions
                            }
                        }
                    ]
                }
            }
        return None
    elif method == "tools/list":
        rule_reminder = " IMPORTANT: Follow all masking and security rules defined in AGENTS.md."
        return {
            "jsonrpc": "2.0",
            "id": msg_id,
            "result": {
                "tools": [
                    {
                        "name": "mcp_read_file",
                        "description": "Reads a file and applies the IP Vault filter." + rule_reminder,
                        "inputSchema": {
                            "type": "object",
                            "properties": {
                                "path": {"type": "string"}
                            },
                            "required": ["path"]
                        }
                    },
                    {
                        "name": "mcp_write_file",
                        "description": "Unfilters provided content and writes it to file." + rule_reminder,
                        "inputSchema": {
                            "type": "object",
                            "properties": {
                                "path": {"type": "string"},
                                "content": {"type": "string"}
                            },
                            "required": ["path", "content"]
                        }
                    },
                    {
                        "name": "mcp_exec_command",
                        "description": "Executes command with unfiltering/filtering logic." + rule_reminder,
                        "inputSchema": {
                            "type": "object",
                            "properties": {
                                "command": {"type": "string"},
                                "cwd": {"type": "string"}
                            },
                            "required": ["command"]
                        }
                    },
                    {
                        "name": "mcp_show_to_user",
                        "description": "Shows unmasked text to user in Notepad." + rule_reminder,
                        "inputSchema": {
                            "type": "object",
                            "properties": {
                                "content": {"type": "string"}
                            },
                            "required": ["content"]
                        }
                    }
                ]
            }
        }
    elif method == "tools/call":
        params = doc.get("params", {})
        tool_name = params.get("name", "")
        arguments = params.get("arguments", {})

        try:
            content = ""
            if tool_name == "mcp_read_file":
                path = arguments.get("path", "")
                if not os.path.isabs(path):
                    path = os.path.abspath(os.path.join(_solutionDir, path))

                with open(path, "r", encoding="utf-8", errors="ignore") as f:
                    raw_text = f.read()

                content = filter_text(raw_text)
                content = await intercept_with_editor("mcp_read_file", content)
            elif tool_name == "mcp_write_file":
                path = arguments.get("path", "")
                if not os.path.isabs(path):
                    path = os.path.abspath(os.path.join(_solutionDir, path))
                text_content = arguments.get("content", "")
                unfiltered = unfilter_text(text_content)

                with open(path, "w", encoding="utf-8") as f:
                    f.write(unfiltered)

                content = f"Successfully wrote to {path}"
                content = await intercept_with_editor("mcp_write_file", content)
            elif tool_name == "mcp_exec_command":
                command = arguments.get("command", "")
                cwd = arguments.get("cwd", _solutionDir)
                if not os.path.isabs(cwd):
                    cwd = os.path.abspath(os.path.join(_solutionDir, cwd))
                unfiltered_command = unfilter_text(command)

                # Run shell command directly to prevent Windows escaping from adding extra backslashes to quotes
                proc = await asyncio.create_subprocess_shell(
                    unfiltered_command,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    cwd=cwd
                )
                stdout, stderr = await proc.communicate()
                
                stdout_str = stdout.decode("utf-8", errors="ignore")
                stderr_str = stderr.decode("utf-8", errors="ignore")
                
                combined = ""
                if stdout_str:
                    combined += "STDOUT:\n" + stdout_str + "\n"
                if stderr_str:
                    combined += "STDERR:\n" + stderr_str

                content = filter_text(combined)
                content = await intercept_with_editor("mcp_exec_command", content)
            elif tool_name == "mcp_show_to_user":
                text_content = arguments.get("content", "")
                unfiltered = unfilter_text(text_content)
                await show_to_user_with_editor(unfiltered)
                content = "Successfully displayed to user."
            else:
                raise Exception(f"Unknown tool: {tool_name}")

            return {
                "jsonrpc": "2.0",
                "id": msg_id,
                "result": {
                    "content": [
                        {"type": "text", "text": content}
                    ]
                }
            }
        except Exception as ex:
            return {
                "jsonrpc": "2.0",
                "id": msg_id,
                "error": {
                    "code": -32603,
                    "message": str(ex)
                }
            }
    return None

async def run_interactive_mode():
    print("=== IPVault MCP Interactive Test Mode (Python) ===")
    print("This mode allows you to manually trigger MCP tools and see the editor interception in action.")
    print("\nAvailable commands:")
    print("  read <path>")
    print("  write <path> <content_text...>")
    print("  exec <command...>")
    print("  show <content_text...>")
    print("  exit\n")

    loop = asyncio.get_event_loop()
    while True:
        sys.stdout.write("mcp> ")
        sys.stdout.flush()
        line = await loop.run_in_executor(None, sys.stdin.readline)
        if not line:
            break
        line = line.strip()
        if not line:
            continue

        parts = line.split(' ', 1)
        cmd = parts[0].lower()
        arg = parts[1] if len(parts) > 1 else ""

        if cmd in ("exit", "quit"):
            break

        try:
            result = ""
            if cmd == "read":
                target_path = os.path.abspath(os.path.join(_solutionDir, arg))
                with open(target_path, "r", encoding="utf-8", errors="ignore") as f:
                    raw_text = f.read()
                result = filter_text(raw_text)
                result = await intercept_with_editor("mcp_read_file", result)
            elif cmd == "write":
                write_parts = arg.split(' ', 1)
                if len(write_parts) < 2:
                    print("Usage: write <path> <content...>")
                    continue
                target_path = os.path.abspath(os.path.join(_solutionDir, write_parts[0]))
                text_content = write_parts[1]
                unfiltered = unfilter_text(text_content)
                with open(target_path, "w", encoding="utf-8") as f:
                    f.write(unfiltered)
                result = f"Successfully wrote to {target_path}"
                result = await intercept_with_editor("mcp_write_file", result)
            elif cmd == "exec":
                unfiltered_command = unfilter_text(arg)
                proc = await asyncio.create_subprocess_shell(
                    unfiltered_command,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    cwd=_solutionDir
                )
                stdout, stderr = await proc.communicate()
                stdout_str = stdout.decode("utf-8", errors="ignore")
                stderr_str = stderr.decode("utf-8", errors="ignore")
                combined = ""
                if stdout_str:
                    combined += "STDOUT:\n" + stdout_str + "\n"
                if stderr_str:
                    combined += "STDERR:\n" + stderr_str
                result = filter_text(combined)
                result = await intercept_with_editor("mcp_exec_command", result)
            elif cmd == "show":
                unfiltered = unfilter_text(arg)
                await show_to_user_with_editor(unfiltered)
                result = "Successfully displayed to user."
            else:
                print(f"Unknown command: {cmd}")
                continue

            print("\n--- FINAL RESULT ---")
            print(result)
            print("--------------------\n")
        except Exception as ex:
            print(f"Error: {ex}")

async def run_mcp_server():
    loop = asyncio.get_event_loop()
    # Read/write from standard streams
    # JSON-RPC lines are read line by line
    while True:
        line = await loop.run_in_executor(None, sys.stdin.readline)
        if not line:
            break
        response = await handle_message(line)
        if response is not None:
            sys.stdout.write(json.dumps(response) + "\n")
            sys.stdout.flush()

def load_requirements_txt(solution_dir):
    req_path = os.path.join(solution_dir, "requirements.txt")
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
            print(f"[IPVault.Mcp] Loaded {len(libs)} unprotected library names from requirements.txt", file=sys.stderr)
        except Exception as e:
            print(f"[IPVault.Mcp] Warning: Failed to read requirements.txt: {e}", file=sys.stderr)
    return libs

async def main():
    global _solutionDir
    if len(sys.argv) < 2:
        print("Usage: python mcp_server.py <filter_json_path> <solution_dir> [--interactive]", file=sys.stderr)
        sys.exit(1)

    map_path = os.path.abspath(sys.argv[1])
    _solutionDir = os.path.abspath(sys.argv[2])

    load_map(map_path)

    # Load dynamic unprotected libraries from requirements.txt
    req_libs = load_requirements_txt(_solutionDir)
    if req_libs:
        UNPROTECTED_ROOTS.update(req_libs)
        BASE_BLACKLIST.update(req_libs)

    is_interactive = len(sys.argv) > 3 and sys.argv[3] == "--interactive"

    if is_interactive:
        await run_interactive_mode()
    else:
        await run_mcp_server()

if __name__ == "__main__":
    asyncio.run(main())
