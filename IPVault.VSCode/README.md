# IPVault VS Code Extension

IPVault is a Zero-Trust privacy proxy designed to protect the Proprietary Intellectual Property (IP) of your codebase when interacting with AI assistants. 

This is the **Python-version** optimized for **Visual Studio Code**, replacing the original C++/Visual Studio extension. It automatically masks local symbols, variables, functions, and files, while leaving standard packages (such as `pandas`, `numpy`, etc.) unmasked to preserve syntax context.

## How It Works

1. **Local Scanner (`IP Vault: Generate IP Vault`):**
   Scans your workspace recursively. It parses Python files (`.py`) via Abstract Syntax Tree (AST), tokenizes SQL scripts (`.sql`), and Batch scripts (`.bat`/`.cmd`) to identify proprietary classes, functions, variable names, labels, and file paths. It generates a mapping dictionary stored in `.vscode/filter.json`.
   
   *Programmatic standard library and Python built-in keywords are automatically skipped.* External libraries not defined within the workspace (like `numpy` or `pandas`) also remain unmasked to give the model context.

2. **Secure Proxy (`IP Vault: Get MCP Server Config`):**
   Generates a Model Context Protocol (MCP) server configuration that executes the lightweight Python MCP server (`mcp.bat`). 

3. **Inline Masking & Editor Interception:**
   When your AI agent reads a file, the MCP server translates original terms to masked names (e.g. `Class_1`, `Var_2`). When writing back, it translates masked names back to original names. It also intercepts calls using VS Code (with a `--wait` temporary tab) or `notepad.exe` as a fallback, so you can manually review/verify what the AI is seeing.

## Commands

- `IP Vault: Generate IP Vault` - Scan current workspace files and generate `.vscode/filter.json`.
- `IP Vault: Get MCP Server Config` - Copy the MCP server configuration block to clipboard.
- `IP Vault: Test MCP Server (Interactive)` - Run the MCP server in interactive terminal mode for manual testing.

## Advanced Protection Features

* **SQL Files:** Automatically extracts table and column names to mask them, keeping generic SQL keywords clear.
* **Batch Files:** Scans batch scripts for environment variables and label blocks, excluding standard batch commands.
* **Python f-strings:** Intelligent f-string parsing allows variables inside `{expression}` blocks to be masked, while keeping structural curly braces clear for the AI.
