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

_strCounter = 1
_commentCounter = 1
_lambdaCounter = 1

_solutionDir = os.getcwd()

def load_map(path):
    global _forwardMap, _reverseMap
    try:
        if os.path.exists(path):
            with open(path, "r", encoding="utf-8") as f:
                map_data = json.load(f)
                _forwardMap = map_data
                _reverseMap = {v: k for k, v in map_data.items()}
            print(f"[IPVault.Mcp] Loaded map with {len(_forwardMap)} keys from {path}", file=sys.stderr)
        else:
            print(f"[IPVault.Mcp] Warning: Map file not found at {path}", file=sys.stderr)
    except Exception as e:
        print(f"[IPVault.Mcp] Error loading map file '{path}': {e}", file=sys.stderr)

# String tokenizing regex
# Matches Python comments starting with #
COMMENT_RE = re.compile(r'#.*')

# Matches Python lambdas: lambda [args]: [expr]
LAMBDA_RE = re.compile(r'\blambda\b[^:]*:[^,\n)]*')

def filter_text(text):
    global _strCounter, _commentCounter, _lambdaCounter
    
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

async def main():
    global _solutionDir
    if len(sys.argv) < 2:
        print("Usage: python mcp_server.py <filter_json_path> <solution_dir> [--interactive]", file=sys.stderr)
        sys.exit(1)

    map_path = os.path.abspath(sys.argv[1])
    _solutionDir = os.path.abspath(sys.argv[2])

    load_map(map_path)

    is_interactive = len(sys.argv) > 3 and sys.argv[3] == "--interactive"

    if is_interactive:
        await run_interactive_mode()
    else:
        await run_mcp_server()

if __name__ == "__main__":
    asyncio.run(main())
