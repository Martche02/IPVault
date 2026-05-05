# Packaging Custom Gemini CLI within IPVault VSIX

This document outlines the strategy for distributing a custom, modified version of the `gemini-cli` directly inside the IPVault Visual Studio Extension (.vsix). This ensures coworkers can simply install the extension without needing to manually install Node.js, configure their environment, or resolve conflicts with the official `gemini-cli`.

## The Strategy: Standalone Executable

Since `gemini-cli` is written in JavaScript/TypeScript for Node.js, it can be compiled into a single, standalone Windows executable (`.exe`). This executable bundles the Node.js runtime and all custom code into one file.

### Step 1: Compile the Custom Gemini CLI
In the custom `gemini-cli` repository, use a tool like `pkg` (by Vercel) to create the executable:

```bash
npm install -g pkg
pkg . --targets node18-win-x64 --output custom-gemini.exe
```
*(This generates a single `custom-gemini.exe` file containing the specific version of the agent).*

### Step 2: Include the `.exe` inside the Visual Studio Extension
1. Copy `custom-gemini.exe` into a folder in the `IPVault` Visual Studio project (e.g., `Resources\CLI\`).
2. In Visual Studio, click on `custom-gemini.exe` in the Solution Explorer.
3. In the Properties window, set:
   * **Build Action**: `Content`
   * **Include in VSIX**: `True`
   * **Copy to Output Directory**: `Copy always`

### Step 3: Update `RunGeminiCommand.cs`
Update the extension's C# code to dynamically locate and execute the bundled `.exe` instead of relying on the user's global system PATH.

```csharp
// Get the directory where the IPVault extension is installed on the user's machine
string extensionDirectory = Path.GetDirectoryName(System.Reflection.Assembly.GetExecutingAssembly().Location);
string customGeminiPath = Path.Combine(extensionDirectory, "Resources", "CLI", "custom-gemini.exe");

// Execute the specific executable
string geminiCmd = $"& '{customGeminiPath}' --filter '{mapPath}' --traffic-log '{trafficPath}'";
```

## Benefits of this Approach
1. **Zero Setup**: Coworkers only need to double-click the `IPVault.vsix` file to install it.
2. **No Conflicts**: Because the extension calls its own internal `custom-gemini.exe` via an absolute path, it will never conflict with an official `gemini-cli` installed globally.
3. **Seamless Updates**: When custom Gemini logic is updated, simply replace the `.exe` in the VS project, bump the VSIX version, and distribute the update. Everyone stays in sync automatically.