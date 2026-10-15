using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

namespace Es3Offline
{
    /// <summary>
    /// Password candidate extraction. Game code stores the ES3 password as a string
    /// constant, which lives in the managed DLL's UTF-16 (#US heap) or as raw ASCII.
    /// We scan raw bytes at both UTF-16 alignments plus ASCII; false candidates only
    /// cost one cheap PBKDF2 attempt.
    /// </summary>
    static class Candidates
    {
        public const int MinLength = 3;
        public const int MaxLength = 64;

        public static readonly string[] BuiltIns =
        {
            "password", "Password", "PASSWORD", "es3", "ES3", "key", "secret", "1234", "12345", "123456",
        };

        public static HashSet<string> FromAssembly(byte[] data)
        {
            var result = new HashSet<string>();
            Utf16Scan(data, 0, result);   // even alignment
            Utf16Scan(data, 1, result);   // odd alignment
            AsciiScan(data, result);
            return result;
        }

        public static HashSet<string> FromWordlist(string path)
        {
            var result = new HashSet<string>();
            foreach (var line in File.ReadAllLines(path))
            {
                var s = line.Trim();
                if (s.Length > 0 && !s.StartsWith("#", StringComparison.Ordinal))
                    result.Add(s);
            }
            return result;
        }

        static void Utf16Scan(byte[] data, int offset, HashSet<string> result)
        {
            var sb = new StringBuilder();
            for (int i = offset; i + 1 < data.Length; i += 2)
            {
                int c = data[i] | (data[i + 1] << 8);
                if (c >= 0x20 && c < 0x7f) sb.Append((char)c);
                else { Flush(result, sb); sb.Length = 0; }
            }
            Flush(result, sb);
        }

        static void AsciiScan(byte[] data, HashSet<string> result)
        {
            var sb = new StringBuilder();
            foreach (var b in data)
            {
                if (b >= 0x20 && b < 0x7f) sb.Append((char)b);
                else { Flush(result, sb); sb.Length = 0; }
            }
            Flush(result, sb);
        }

        static void Flush(HashSet<string> set, StringBuilder sb)
        {
            if (sb.Length >= MinLength && sb.Length <= MaxLength)
                set.Add(sb.ToString());
        }
    }
}
