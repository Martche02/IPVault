const vscode = require('vscode');
const cp = require('child_process');
const path = require('path');
const fs = require('fs');

function activate(context) {
    console.log('IPVault VS Code extension is active.');

    // Helper to get active workspace folder
    function getWorkspaceFolder() {
        const folders = vscode.workspace.workspaceFolders;
        if (!folders || folders.length === 0) {
            vscode.window.showWarningMessage('Please open a workspace folder first.');
            return null;
        }
        return folders[0].uri.fsPath;
    }

    // Helper to run python script
    function runPythonScript(scriptPath, args, callback) {
        // Try 'python' first, then 'python3', then 'py'
        const commands = ['python', 'python3', 'py'];
        let cmdIdx = 0;

        function attempt() {
            if (cmdIdx >= commands.length) {
                callback(new Error('Could not find Python interpreter in your system PATH. Please ensure Python is installed and added to PATH.'));
                return;
            }

            const command = commands[cmdIdx];
            const proc = cp.spawn(command, [scriptPath, ...args]);
            let stderr = '';
            let stdout = '';

            proc.stdout.on('data', (data) => {
                stdout += data.toString();
            });

            proc.stderr.on('data', (data) => {
                stderr += data.toString();
            });

            proc.on('close', (code) => {
                if (code === 0) {
                    callback(null, stdout);
                } else {
                    // If it couldn't execute the command at all (ENOENT)
                    if (stderr.includes('ENOENT') || stderr.includes('not recognized') || stderr.includes('command not found')) {
                        cmdIdx++;
                        attempt();
                    } else {
                        callback(new Error(stderr || `Process exited with code ${code}`));
                    }
                }
            });

            proc.on('error', (err) => {
                if (err.code === 'ENOENT') {
                    cmdIdx++;
                    attempt();
                } else {
                    callback(err);
                }
            });
        }

        attempt();
    }

    // Command: Generate IP Vault
    let generateDisposable = vscode.commands.registerCommand('ipvault.generate', () => {
        const workspacePath = getWorkspaceFolder();
        if (!workspacePath) return;

        const extractorScript = path.join(context.extensionPath, 'CLI', 'extractor.py');

        vscode.window.withProgress({
            location: vscode.ProgressLocation.Notification,
            title: "IP Vault",
            cancellable: false
        }, (progress) => {
            progress.report({ message: "Extracting symbols from workspace..." });
            
            return new Promise((resolve, reject) => {
                runPythonScript(extractorScript, [workspacePath], (err, stdout) => {
                    if (err) {
                        vscode.window.showErrorMessage(`Extraction failed: ${err.message}`);
                        reject(err);
                    } else {
                        vscode.window.showInformationMessage('IP Vault map generated successfully using Python AST!');
                        resolve(stdout);
                    }
                });
            });
        });
    });

    // Command: Get MCP Server Config
    let getConfigDisposable = vscode.commands.registerCommand('ipvault.getConfig', () => {
        const workspacePath = getWorkspaceFolder();
        if (!workspacePath) return;

        const mapPath = path.join(workspacePath, '.vscode', 'filter.json');
        if (!fs.existsSync(mapPath)) {
            vscode.window.showWarningMessage("IP Vault map not found. Please run 'IP Vault: Generate IP Vault' first.");
            return;
        }

        const mcpBatPath = path.join(context.extensionPath, 'CLI', 'mcp.bat');
        
        // Escape backslashes for JSON compatibility
        const escapedMcpPath = mcpBatPath.replace(/\\/g, '\\\\');
        const escapedMapPath = mapPath.replace(/\\/g, '\\\\');
        const escapedWorkspacePath = workspacePath.replace(/\\/g, '\\\\');

        const mcpConfig = {
            mcpServers: {
                ipvault: {
                    command: escapedMcpPath,
                    args: [escapedMapPath, escapedWorkspacePath]
                }
            }
        };

        const configString = JSON.stringify(mcpConfig, null, 2);
        vscode.env.clipboard.writeText(configString).then(() => {
            vscode.window.showInformationMessage(
                "IP Vault MCP Server configuration copied to clipboard!\nPaste it into your Claude Desktop or other MCP client settings.",
                "View Config"
            ).then((selection) => {
                if (selection === "View Config") {
                    vscode.workspace.openTextDocument({
                        content: configString,
                        language: "json"
                    }).then(doc => vscode.window.showTextDocument(doc));
                }
            });
        });
    });

    // Command: Test MCP Server (Interactive)
    let testInteractiveDisposable = vscode.commands.registerCommand('ipvault.testInteractive', () => {
        const workspacePath = getWorkspaceFolder();
        if (!workspacePath) return;

        const mapPath = path.join(workspacePath, '.vscode', 'filter.json');
        if (!fs.existsSync(mapPath)) {
            vscode.window.showWarningMessage("IP Vault map not found. Please run 'IP Vault: Generate IP Vault' first.");
            return;
        }

        const mcpBatPath = path.join(context.extensionPath, 'CLI', 'mcp.bat');

        // Create and show an interactive VS Code terminal running the interactive mode
        const terminal = vscode.window.createTerminal({
            name: "IPVault MCP Test",
            shellPath: "cmd.exe",
            cwd: workspacePath
        });
        
        terminal.sendText(`"${mcpBatPath}" "${mapPath}" "${workspacePath}" --interactive`);
        terminal.show();
    });

    context.subscriptions.push(generateDisposable, getConfigDisposable, testInteractiveDisposable);
}

function deactivate() {}

module.exports = {
    activate,
    deactivate
};
