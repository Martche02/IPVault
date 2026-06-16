using Microsoft.VisualStudio.Shell;
using System.ComponentModel;
using System.Runtime.InteropServices;

namespace IPVault
{
    [Guid("A95B2A65-19A6-48BD-BE2A-582522DBB13D")]
    public class IPVaultOptions : DialogPage
    {
        [Category("IPVault Options")]
        [DisplayName("External PDB Directory")]
        [Description("Path to an external directory containing .pdb files to be used in the filter generation. Can also be set via IPVAULT_EXTERNAL_PDB_DIR environment variable.")]
        public string PdbDirectory { get; set; } = "";
    }
}
