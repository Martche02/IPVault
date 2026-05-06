using System;
using System.Reflection;
using System.Linq;

public class Program {
    public static void Main() {
        var path = @"C:\Users\marcelo.stangler\.nuget\packages\sharppdb.windows\1.0.4\lib\net45\SharpPdb.Windows.dll";
        var assembly = Assembly.LoadFrom(path);
        
        var types = assembly.GetTypes().Where(t => t.Namespace == "SharpPdb.Windows.SymbolRecords");
        foreach (var type in types) {
            var nameField = type.GetField("Name", BindingFlags.Public | BindingFlags.Instance | BindingFlags.FlattenHierarchy);
            var nameProp = type.GetProperty("Name", BindingFlags.Public | BindingFlags.Instance | BindingFlags.FlattenHierarchy);
            if (nameField != null || nameProp != null) {
                Console.WriteLine("Type with Name: " + type.Name);
            }
        }
    }
}