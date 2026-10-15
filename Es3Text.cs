using System.IO;
using System.Text.RegularExpressions;

namespace Es3Offline
{
    /// <summary>
    /// ES3 saves use bare numeric keys ("12:{...}") which are not valid JSON object
    /// keys. These helpers rename them to "12_fixed" so editors/parsers accept the
    /// file, and back again. (Approach ported from fakeyw/EasySave3Tool.)
    /// </summary>
    static class Es3Text
    {
        static readonly Regex NumericKey = new Regex(@"\d+:{", RegexOptions.Compiled);
        static readonly Regex FixedKey = new Regex(@"""(\d+)_fixed"":\{", RegexOptions.Compiled);

        public static string ToJson(string es3)
        {
            return NumericKey.Replace(es3, m =>
            {
                var digits = m.Value.Substring(0, m.Value.Length - 2);
                return "\"" + digits + "_fixed\":{";
            });
        }

        public static string FromJson(string json)
        {
            return FixedKey.Replace(json, m => m.Groups[1].Value + ":{");
        }

        public static string ReadText(string path) => File.ReadAllText(path);
        public static void WriteText(string path, string text) => File.WriteAllText(path, text);
    }
}
