using Microsoft.VisualStudio.Shell;
using System.ComponentModel;
using System.Runtime.InteropServices;

namespace IPVault
{
    [Guid("A95B2A65-19A6-48BD-BE2A-582522DBB13D")]
    public class IPVaultOptions : DialogPage
    {
        [Category("Zero-Trust Copilot")]
        [DisplayName("OpenAI API Key (GitHub Token)")]
        [Description("The API Key used by EdgeProxyServer to connect to the LLM (e.g., GitHub Copilot Token).")]
        [PasswordPropertyText(true)]
        public string OpenAiApiKey { get; set; } = "";

        [Category("Zero-Trust Copilot")]
        [DisplayName("Target Model")]
        [Description("Optional. Forces a specific model name to be sent to the LLM.")]
        public string TargetModel { get; set; } = "";

        [Category("Zero-Trust Copilot")]
        [DisplayName("External PDB Directory")]
        [Description("Path to an external directory containing .pdb files to be used in the filter generation.")]
        public string PdbDirectory { get; set; } = "";
    }
}
