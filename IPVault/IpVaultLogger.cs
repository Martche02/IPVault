using System;
using System.Diagnostics;
using System.IO;

namespace IPVault
{
  internal static class IpVaultLogger
  {
    private static readonly object SyncRoot = new object();
    private static readonly string LogPath = Path.Combine(Path.GetTempPath(), "ip_vault_ext_log.txt");

    internal static void Log(string message)
    {
      string line = $"{DateTime.Now:O}: {message}";
      Debug.WriteLine(line);

      try
      {
        lock (SyncRoot)
        {
          File.AppendAllText(LogPath, line + Environment.NewLine);
        }
      }
      catch (Exception ex)
      {
        Debug.WriteLine($"{DateTime.Now:O}: [IPVault] Failed to write log: {ex.Message}");
      }
    }
  }
}
