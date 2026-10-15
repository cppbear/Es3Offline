# Es3Offline

Offline Easy Save 3 password finder / decryptor. No BepInEx, no game patching — works
directly on the save file plus the game's compiled code.

## Format

ES3 AES saves are:

```
file  = salt[16] || AES-128-CBC(key, IV=salt, PKCS7(plaintext))
key   = PBKDF2-HMAC-SHA1(password, salt, 100 iterations, 16 bytes)
```

The plaintext is text (JSON-ish; some games GZip-compress it first — handled automatically).

## Build

Requires the .NET 10 SDK.

```
dotnet build -c Release                 # -> bin/Release/net10.0/Es3Offline.dll
publish.cmd                             # -> publish/Es3Offline.exe (single-file, self-contained, ~37 MB)
```

### Shell syntax (CMD vs PowerShell)

Long commands wrap differently per shell:

```bat
:: CMD - caret continues lines
Es3Offline.exe find "save1.es3" ^
    "...\Assembly-CSharp-firstpass.dll" ^
    "...\Assembly-CSharp.dll" ^
    --dict words.txt
```

```powershell
# PowerShell - backtick continues lines, and an exe in the CURRENT directory needs .\ prefix
.\Es3Offline.exe find "save1.es3" `
    "...\Assembly-CSharp-firstpass.dll" `
    "...\Assembly-CSharp.dll" `
    --dict words.txt

# single-line form works everywhere (no continuation chars, no prefix worries)
Es3Offline.exe find "save1.es3" "...\Assembly-CSharp-firstpass.dll" "...\Assembly-CSharp.dll"
```

Note: `^` does NOT continue lines in PowerShell, and unquoted paths containing spaces
(or Japanese characters) will split - always quote paths.


## Usage

Unity saves live in `%USERPROFILE%\AppData\LocalLow\<company>\<product>\`.

```
# diagnose a file: encrypted or not, salt, block count, plaintext preview
Es3Offline.exe info <file>

# find the password by brute force and decrypt in one step
# candidates = strings inside the game DLLs + optional wordlist + built-ins
Es3Offline.exe find <save.es3> ^
    "<game>_Data\Managed\Assembly-CSharp-firstpass.dll" ^
    "<game>_Data\Managed\Assembly-CSharp.dll" ^
    --dict words.txt
# success writes <save.es3.dec> and prints the password

# edit the .dec, then re-encrypt (use --gzip if the original was compressed)
Es3Offline.exe enc <edited.dec> <save.es3> <password> [--gzip]

# single-file decrypt with a known password
Es3Offline.exe dec <in> <out> <password>

# some ES3 versions emit bare numeric keys ("12:{"), which is not valid JSON:
Es3Offline.exe es3json <in> <out>       # "12:{"  -> "12_fixed":{
Es3Offline.exe jsones3 <in> <out>       # inverse, before re-encrypting
```

Exit codes: `0` ok · `1` usage/input error · `2` password not found · `3` relaxed
candidates found, verify manually with `dec`.

## How brute force works

Wrong AES keys still pass the PKCS7 padding check ~1/256 of the time, so padding alone
cannot decide a winner. A hit additionally requires the plaintext to start like ES3
content (`{`, `"`, `[`, digit, or `ES3`) and be ≥98% printable (GZip payloads are
decompressed and re-checked). With tens of thousands of candidates this yields exactly
the true password; borderline (90–98% printable) candidates are only listed for manual
review, never auto-claimed.

## Limitations

- Passwords computed at runtime (assembled/derived, not stored as constants in the
  game DLLs) cannot be recovered this way — runtime interception (e.g. a BepInEx
  Harmony plugin) is required for those games.
- ES3's legacy "ObsoleteAES" encryption (pre-3.x) uses a different scheme and is not
  supported.

## Credits

- The ES3 AES file format was cross-checked against [fakeyw/EasySave3Tool](https://github.com/fakeyw/EasySave3Tool)
  (MIT); the `es3json`/`jsones3` numeric-key fix follows its approach.
- Unlike runtime dumpers, this tool needs neither BepInEx nor launching the game.
