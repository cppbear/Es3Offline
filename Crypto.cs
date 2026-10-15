using System;
using System.IO;
using System.IO.Compression;
using System.Security.Cryptography;

namespace Es3Offline
{
    /// <summary>
    /// Easy Save 3 AES file format:
    ///   file = salt[16] || AES-128-CBC(key, IV=salt, PKCS7(plaintext))
    ///   key  = PBKDF2-HMAC-SHA1(password, salt, 100 iterations, 16 bytes)
    /// The plaintext is text (JSON-ish, sometimes GZip-compressed first).
    /// </summary>
    static class Crypto
    {
        public const int SaltSize = 16;

        public static byte[] Decrypt(byte[] blob, string password)
        {
            if (blob.Length < SaltSize + 16 || (blob.Length - SaltSize) % 16 != 0)
                throw new InvalidDataException(
                    "file size is not 16-byte-aligned after the salt header; not an ES3 AES file");

            var salt = new byte[SaltSize];
            Buffer.BlockCopy(blob, 0, salt, 0, SaltSize);

            using var aes = Aes.Create();
            aes.Key = DeriveKey(password, salt);
            aes.IV = salt;
            aes.Mode = CipherMode.CBC;
            aes.Padding = PaddingMode.PKCS7;

            using var dec = aes.CreateDecryptor();
            return dec.TransformFinalBlock(blob, SaltSize, blob.Length - SaltSize);
        }

        public static byte[] Encrypt(byte[] plain, string password, bool gzip)
        {
            if (gzip)
                plain = Gzip(plain);

            var salt = RandomNumberGenerator.GetBytes(SaltSize);
            using var aes = Aes.Create();
            aes.Key = DeriveKey(password, salt);
            aes.IV = salt;
            aes.Mode = CipherMode.CBC;
            aes.Padding = PaddingMode.PKCS7;

            using var enc = aes.CreateEncryptor();
            var body = enc.TransformFinalBlock(plain, 0, plain.Length);

            var blob = new byte[SaltSize + body.Length];
            Buffer.BlockCopy(salt, 0, blob, 0, SaltSize);
            Buffer.BlockCopy(body, 0, blob, SaltSize, body.Length);
            return blob;
        }

        /// <summary>
        /// Decrypt and validate. Returns null when the password is wrong (or the result
        /// is not ES3-like). PKCS7 validity is probabilistic (1/256 per wrong key), so
        /// with large candidate lists we also require textual-looking content:
        /// printableRatio must be >= threshold, and the first byte must be JSON-ish
        /// ('{', '"', '[', digit) or a GZip magic (then decompressed and re-checked).
        /// </summary>
        public static byte[] TryDecrypt(byte[] blob, string password, double printableThreshold)
        {
            try
            {
                var plain = Decrypt(blob, password);
                var content = plain;
                if (IsGzip(plain))
                {
                    try { content = Gunzip(plain); }
                    catch { return null; }
                }

                if (content.Length < 2 || !IsTextualStart(content))
                    return null;

                return PrintableRatio(content) >= printableThreshold ? plain : null;
            }
            catch (CryptographicException) { return null; }  // bad PKCS7 padding: wrong password
            catch (InvalidDataException) { return null; }
        }

        /// <summary>Unencrypted ES3 saves are already textual; detect them so the user is not asked for a password.</summary>
        public static bool LooksPlaintext(byte[] blob)
        {
            return blob.Length >= 2 && IsTextualStart(blob) && PrintableRatio(blob) >= 0.98;
        }

        public static bool IsGzip(byte[] data)
        {
            return data.Length >= 2 && data[0] == 0x1f && data[1] == 0x8b;
        }

        public static byte[] GunzipIfCompressed(byte[] data)
        {
            return IsGzip(data) ? Gunzip(data) : data;
        }

        static bool IsTextualStart(byte[] p)
        {
            var head = p[0];
            return head == '{' || head == '"' || head == '['
                || (head >= '0' && head <= '9')
                || (p.Length >= 3 && head == 'E' && p[1] == 'S' && p[2] == '3');
        }

        static double PrintableRatio(byte[] data)
        {
            if (data.Length == 0) return 0;
            int good = 0;
            foreach (var b in data)
                if (b == 0x09 || b == 0x0a || b == 0x0d || (b >= 0x20 && b < 0x7f) || b >= 0x80) // tab/lf/cr/ascii/utf8
                    good++;
            return (double)good / data.Length;
        }

        static byte[] DeriveKey(string password, byte[] salt)
        {
            return Rfc2898DeriveBytes.Pbkdf2(
                System.Text.Encoding.UTF8.GetBytes(password), salt, 100, HashAlgorithmName.SHA1, 16);
        }

        static byte[] Gzip(byte[] data)
        {
            using var output = new MemoryStream();
            using (var gz = new GZipStream(output, CompressionLevel.Optimal, leaveOpen: true))
                gz.Write(data, 0, data.Length);
            return output.ToArray();
        }

        static byte[] Gunzip(byte[] data)
        {
            using var input = new MemoryStream(data);
            using var gz = new GZipStream(input, CompressionMode.Decompress);
            using var output = new MemoryStream();
            gz.CopyTo(output);
            return output.ToArray();
        }
    }
}
