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

    // Command: Show Options Menu (Quick Pick)
    let showMenuDisposable = vscode.commands.registerCommand('ipvault.showMenu', () => {
        vscode.window.showQuickPick([
            {
                label: "$(symbol-class) Generate Symbol Map",
                description: "Extract workspace symbols and rebuild filter.json",
                commandId: 'ipvault.generate'
            },
            {
                label: "$(copy) Get MCP Config",
                description: "Copy MCP server configurations to clipboard",
                commandId: 'ipvault.getConfig'
            },
            {
                label: "$(terminal) Test MCP Interactive",
                description: "Start interactive masking terminal console",
                commandId: 'ipvault.testInteractive'
            },
            {
                label: "$(edit) Translate Prompt to Masked",
                description: "Replace unprotected names in selection or clipboard with masked ones",
                commandId: 'ipvault.translatePrompt'
            }
        ], {
            placeHolder: "Select an IPVault action to execute"
        }).then(selected => {
            if (selected) {
                vscode.commands.executeCommand(selected.commandId);
            }
        });
    });

    // Command: Translate Prompt to Masked
    let translatePromptDisposable = vscode.commands.registerCommand('ipvault.translatePrompt', () => {
        const workspacePath = getWorkspaceFolder();
        if (!workspacePath) return;

        const mapPath = path.join(workspacePath, '.vscode', 'filter.json');
        if (!fs.existsSync(mapPath)) {
            vscode.window.showWarningMessage("IP Vault map not found. Please run 'IP Vault: Generate IP Vault' first.");
            return;
        }

        // Helper to perform the translation
        function translateText(text) {
            const mapData = JSON.parse(fs.readFileSync(mapPath, 'utf8'));
            const keys = Object.keys(mapData).sort((a, b) => b.length - a.length);
            let filteredText = text;
            for (const original of keys) {
                const masked = mapData[original];
                const escapedOriginal = original.replace(/[-\/\\^$*+?.()|[\]{}]/g, '\\$&');
                const regex = new RegExp('\\b' + escapedOriginal + '\\b', 'g');
                filteredText = filteredText.replace(regex, masked);
            }
            return filteredText;
        }

        function showResult(translated) {
            vscode.env.clipboard.writeText(translated).then(() => {
                vscode.workspace.openTextDocument({
                    content: translated,
                    language: "markdown"
                }).then(doc => {
                    vscode.window.showTextDocument(doc);
                    vscode.window.showInformationMessage("Translated prompt copied to clipboard!");
                });
            });
        }

        // Try reading selection first
        const editor = vscode.window.activeTextEditor;
        if (editor && !editor.selection.isEmpty) {
            const selectedText = editor.document.getText(editor.selection);
            const translated = translateText(selectedText);
            showResult(translated);
        } else {
            // Read from clipboard, or prompt if clipboard is empty
            vscode.env.clipboard.readText().then(clipText => {
                if (clipText && clipText.trim()) {
                    const translated = translateText(clipText);
                    showResult(translated);
                } else {
                    vscode.window.showInputBox({
                        prompt: "Paste your prompt containing real (unprotected) names to translate",
                        placeHolder: "e.g., Write a function in MyClass using MySubClass...",
                        ignoreFocusOut: true
                    }).then(input => {
                        if (input) {
                            const translated = translateText(input);
                            showResult(translated);
                        }
                    });
                }
            });
        }
    });

    // Register sidebar tree view
    const treeDataProvider = new IPVaultTreeDataProvider();
    const treeView = vscode.window.registerTreeDataProvider('ipvault-actions', treeDataProvider);

    // Create status bar item
    const statusBarItem = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Left, 100);
    statusBarItem.text = "$(shield) IPVault";
    statusBarItem.tooltip = "Click to open IPVault Control Panel";
    statusBarItem.command = "ipvault.showMenu";
    statusBarItem.show();

    context.subscriptions.push(
        generateDisposable, 
        getConfigDisposable, 
        testInteractiveDisposable,
        showMenuDisposable,
        translatePromptDisposable,
        statusBarItem,
        treeView
    );
}

class IPVaultTreeDataProvider {
    getTreeItem(element) {
        return element;
    }

    getChildren(element) {
        if (!element) {
            return [
                new IPVaultTreeItem(
                    "Generate Symbol Map",
                    "Extract workspace symbols and rebuild filter.json",
                    vscode.TreeItemCollapsibleState.None,
                    {
                        command: 'ipvault.generate',
                        title: 'Generate Symbol Map'
                    },
                    new vscode.ThemeIcon('symbol-class')
                ),
                new IPVaultTreeItem(
                    "Get MCP Config",
                    "Copy MCP server configurations to clipboard",
                    vscode.TreeItemCollapsibleState.None,
                    {
                        command: 'ipvault.getConfig',
                        title: 'Get MCP Config'
                    },
                    new vscode.ThemeIcon('copy')
                ),
                new IPVaultTreeItem(
                    "Test MCP Interactive",
                    "Start interactive masking terminal console",
                    vscode.TreeItemCollapsibleState.None,
                    {
                        command: 'ipvault.testInteractive',
                        title: 'Test MCP Interactive'
                    },
                    new vscode.ThemeIcon('terminal')
                ),
                new IPVaultTreeItem(
                    "Translate Prompt",
                    "Replace unprotected names in a prompt with masked ones",
                    vscode.TreeItemCollapsibleState.None,
                    {
                        command: 'ipvault.translatePrompt',
                        title: 'Translate Prompt'
                    },
                    new vscode.ThemeIcon('edit')
                )
            ];
        }
        return [];
    }
}

class IPVaultTreeItem extends vscode.TreeItem {
    constructor(label, tooltip, collapsibleState, command, icon) {
        super(label, collapsibleState);
        this.tooltip = tooltip;
        this.command = command;
        this.iconPath = icon;
        this.contextValue = 'actions';
    }
}

function deactivate() {}

module.exports = {
    activate,
    deactivate
};
