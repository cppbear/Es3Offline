using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;

namespace Es3Offline
{
    /// <summary>Offline Easy Save 3 password finder and decryptor.</summary>
    static class Program
    {
        const int ExitOk = 0;
        const int ExitUsage = 1;
        const int ExitNoPassword = 2;
        const int ExitManualReview = 3;

        static int Main(string[] args)
        {
            Console.OutputEncoding = Encoding.UTF8;
            if (args.Length < 1) return Usage();

            try
            {
                var command = args[0].ToLowerInvariant();

                // "help <command>" and "<command> --help" both print per-command details.
                var helpTarget =
                    (command == "help" || command == "--help" || command == "-h") && args.Length > 1 ? args[1].ToLowerInvariant()
                    : IsCommand(command) && args.Skip(1).Any(WantsHelp) ? command
                    : null;
                if (helpTarget != null)
                    return CommandHelp(helpTarget);

                switch (command)
                {
                    case "find": return Find(args);
                    case "dec": return Dec(args);
                    case "enc": return Enc(args);
                    case "info": return Info(args);
                    case "es3json": return Es3Json(args);
                    case "jsones3": return JsonEs3(args);
                    case "help":
                    case "--help":
                    case "-h": return Usage(ExitOk);
                    default:
                        Console.Error.WriteLine("unknown command: " + args[0]);
                        return Usage();
                }
            }
            catch (Exception e)
            {
                Console.Error.WriteLine("error: " + e.Message);
                return ExitUsage;
            }
        }

        static bool IsCommand(string name)
        {
            switch (name)
            {
                case "find":
                case "dec":
                case "enc":
                case "info":
                case "es3json":
                case "jsones3":
                    return true;
                default:
                    return false;
            }
        }

        static bool WantsHelp(string arg)
        {
            return arg == "--help" || arg == "-h" || arg == "-?";
        }

        static int CommandHelp(string command)
        {
            switch (command)
            {
                case "find":
                    Console.WriteLine(
                        "find <save.es3> [--dict words.txt] [game.dll ...]\n" +
                        "\n" +
                        "  Brute-forces the password. Candidates = strings extracted from the given\n" +
                        "  game DLLs + lines of each --dict wordlist + built-in defaults.\n" +
                        "  On success prints the password and writes <save.es3.dec> (GZip payloads\n" +
                        "  are decompressed automatically).\n" +
                        "\n" +
                        "  exit codes: 0 found, 2 none worked, 3 relaxed candidates need review");
                    return ExitOk;
                case "dec":
                    Console.WriteLine(
                        "dec <in> <out> <password>\n" +
                        "\n" +
                        "  Decrypts one file. Unencrypted (already textual) input is copied verbatim.");
                    return ExitOk;
                case "enc":
                    Console.WriteLine(
                        "enc <in> <out> <password> [--gzip]\n" +
                        "\n" +
                        "  Re-encrypts an edited save. Pass --gzip when the original file was\n" +
                        "  GZip-compressed (find/dec tell you when they decompress).");
                    return ExitOk;
                case "info":
                    Console.WriteLine(
                        "info <file>\n" +
                        "\n" +
                        "  Diagnoses a file: encrypted or not, salt, AES block count, plaintext preview.");
                    return ExitOk;
                case "es3json":
                    Console.WriteLine(
                        "es3json <in> <out>\n" +
                        "\n" +
                        "  Converts bare numeric keys to parseable JSON (\"12:{\" -> \"12_fixed\":{).\n" +
                        "  Only needed for ES3 versions that emit numeric keys.");
                    return ExitOk;
                case "jsones3":
                    Console.WriteLine(
                        "jsones3 <in> <out>\n" +
                        "\n" +
                        "  Inverse of es3json; run it on the edited JSON before re-encrypting.");
                    return ExitOk;
                default:
                    Console.Error.WriteLine("no help for unknown command: " + command);
                    return Usage();
            }
        }

        static int Find(string[] args)
        {
            // find <save> [--dict file] [source.dll ...]
            if (args.Length < 2) { Console.Error.WriteLine("find needs <save.es3> [--dict words.txt] [source.dll ...]"); return ExitUsage; }

            var save = args[1];
            var blob = File.ReadAllBytes(save);
            if (Crypto.LooksPlaintext(blob))
            {
                Console.WriteLine("this file is NOT encrypted (already textual) - no password needed");
                return ExitOk;
            }
            if (blob.Length < Crypto.SaltSize + 16)
            {
                Console.Error.WriteLine("file too small to be an ES3 AES save");
                return ExitUsage;
            }

            var candidates = new HashSet<string>(Candidates.BuiltIns);
            var sources = new List<string>();
            for (int i = 2; i < args.Length; i++)
            {
                if (args[i] == "--dict")
                {
                    if (i + 1 >= args.Length) { Console.Error.WriteLine("--dict needs a file path"); return ExitUsage; }
                    var words = Candidates.FromWordlist(args[++i]);
                    Console.WriteLine($"[dict {Path.GetFileName(args[i])}] {words.Count} words");
                    foreach (var w in words) candidates.Add(w);
                }
                else
                {
                    sources.Add(args[i]);
                }
            }

            foreach (var dll in sources)
            {
                if (!File.Exists(dll)) { Console.Error.WriteLine("warning: missing " + dll); continue; }
                var found = Candidates.FromAssembly(File.ReadAllBytes(dll));
                Console.WriteLine($"[{Path.GetFileName(dll)}] {found.Count} candidate strings");
                foreach (var s in found) candidates.Add(s);
            }
            Console.WriteLine($"total unique candidates: {candidates.Count}");

            // Pass 1: strict content check - a true hit is essentially certain.
            foreach (var candidate in candidates)
            {
                var plain = Crypto.TryDecrypt(blob, candidate, 0.98);
                if (plain == null) continue;

                var content = Crypto.GunzipIfCompressed(plain);
                var outPath = save + ".dec";
                File.WriteAllBytes(outPath, content);
                Console.WriteLine();
                Console.WriteLine("PASSWORD FOUND: " + candidate);
                Console.WriteLine("decrypted save written to: " + outPath + (Crypto.IsGzip(plain) ? " (was gzip-compressed, auto-decompressed)" : ""));
                Console.WriteLine("preview: " + Preview(content));
                return ExitOk;
            }

            // Pass 2: relaxed - report for manual review, do not auto-claim.
            var relaxed = new List<string>();
            foreach (var candidate in candidates)
            {
                if (Crypto.TryDecrypt(blob, candidate, 0.90) != null)
                {
                    relaxed.Add(candidate);
                    if (relaxed.Count >= 5) break;
                }
            }
            if (relaxed.Count > 0)
            {
                Console.Error.WriteLine();
                Console.Error.WriteLine("no strict match; these decrypt to text-like output (verify manually with 'dec'):");
                foreach (var h in relaxed)
                    Console.Error.WriteLine("  candidate: " + h);
                return ExitManualReview;
            }

            Console.Error.WriteLine();
            Console.Error.WriteLine($"no candidate worked ({candidates.Count} tried). The password may be computed at " +
                "runtime or stored elsewhere; pass more game DLLs (Assembly-CSharp*.dll, Plugins/*.dll) or a --dict wordlist.");
            return ExitNoPassword;
        }

        static int Dec(string[] args)
        {
            if (args.Length < 4) { Console.Error.WriteLine("dec needs <in> <out> <password>"); return ExitUsage; }

            var blob = File.ReadAllBytes(args[1]);
            if (Crypto.LooksPlaintext(blob))
            {
                File.WriteAllBytes(args[2], blob);
                Console.WriteLine("input is not encrypted; copied verbatim -> " + args[2]);
                return ExitOk;
            }

            var plain = Crypto.TryDecrypt(blob, args[3], 0.90);
            if (plain == null)
            {
                Console.Error.WriteLine("wrong password or not an ES3-encrypted file");
                return ExitNoPassword;
            }

            var content = Crypto.GunzipIfCompressed(plain);
            File.WriteAllBytes(args[2], content);
            Console.WriteLine("ok -> " + args[2] + (Crypto.IsGzip(plain) ? " (gzip-decompressed)" : ""));
            return ExitOk;
        }

        static int Enc(string[] args)
        {
            // enc <in> <out> <password> [--gzip]
            if (args.Length < 4) { Console.Error.WriteLine("enc needs <in> <out> <password> [--gzip]"); return ExitUsage; }

            bool gzip = args.Contains("--gzip");
            var plain = File.ReadAllBytes(args[1]);
            File.WriteAllBytes(args[2], Crypto.Encrypt(plain, args[3], gzip));
            Console.WriteLine("ok -> " + args[2] + (gzip ? " (gzip-compressed)" : ""));
            return ExitOk;
        }

        static int Info(string[] args)
        {
            if (args.Length < 2) { Console.Error.WriteLine("info needs <file>"); return ExitUsage; }

            var blob = File.ReadAllBytes(args[1]);
            Console.WriteLine($"size: {blob.Length} bytes");
            if (blob.Length < 2) return ExitOk;

            if (Crypto.LooksPlaintext(blob))
            {
                Console.WriteLine("format: unencrypted (textual ES3)");
                Console.WriteLine("preview: " + Preview(blob));
                return ExitOk;
            }

            if (blob.Length >= Crypto.SaltSize + 16 && (blob.Length - Crypto.SaltSize) % 16 == 0)
            {
                Console.WriteLine("format: ES3 AES (16-byte salt/IV header + AES-128-CBC body)");
                Console.WriteLine($"salt: {BitConverter.ToString(blob, 0, Crypto.SaltSize).Replace("-", "")}");
                Console.WriteLine($"body: {(blob.Length - Crypto.SaltSize) / 16} AES blocks");
                return ExitOk;
            }

            Console.WriteLine("format: unknown (not textual, not AES-block-aligned)");
            return ExitUsage;
        }

        static int Es3Json(string[] args)
        {
            if (args.Length < 3) { Console.Error.WriteLine("es3json needs <in> <out>"); return ExitUsage; }
            Es3Text.WriteText(args[2], Es3Text.ToJson(Es3Text.ReadText(args[1])));
            Console.WriteLine("ok -> " + args[2]);
            return ExitOk;
        }

        static int JsonEs3(string[] args)
        {
            if (args.Length < 3) { Console.Error.WriteLine("jsones3 needs <in> <out>"); return ExitUsage; }
            Es3Text.WriteText(args[2], Es3Text.FromJson(Es3Text.ReadText(args[1])));
            Console.WriteLine("ok -> " + args[2]);
            return ExitOk;
        }

        static string Preview(byte[] data)
        {
            var text = Encoding.UTF8.GetString(data, 0, Math.Min(data.Length, 200));
            return text.Replace("\r", "\\r").Replace("\n", "\\n");
        }

        static int Usage(int exit = ExitUsage)
        {
            Console.WriteLine(
                "Es3Offline 1.0.0 - offline Easy Save 3 password finder / decryptor\n" +
                "\n" +
                "ES3 AES format: salt[16] + AES-128-CBC(PKCS7(plaintext)); key = PBKDF2-SHA1(password, salt, 100, 16)\n" +
                "\n" +
                "Usage:\n" +
                "  find <save.es3> [--dict words.txt] [game.dll ...]\n" +
                "        brute-force the password using strings extracted from game DLLs and/or\n" +
                "        a wordlist; on success writes <save.es3.dec> (gzip auto-decompressed)\n" +
                "  dec <in> <out> <password>\n" +
                "        decrypt one file\n" +
                "  enc <in> <out> <password> [--gzip]\n" +
                "        re-encrypt an edited save (use --gzip if the original was compressed)\n" +
                "  info <file>\n" +
                "        diagnose a file: encrypted or not, salt, block count, plaintext preview\n" +
                "  es3json <in> <out>\n" +
                "        bare numeric keys -> parseable JSON (\"12:{\" -> \"12_fixed\":{)\n" +
                "  jsones3 <in> <out>\n" +
                "        inverse of es3json\n" +
                "\n" +
                "Run '<command> --help' (or 'help <command>') for per-command details.\n" +
                "Exit codes: 0 ok, 1 usage/input error, 2 password not found, 3 manual review needed\n" +
                "\n" +
                "Unity saves live in %USERPROFILE%\\AppData\\LocalLow\\<company>\\<product>\\.");
            return exit;
        }
    }
}
