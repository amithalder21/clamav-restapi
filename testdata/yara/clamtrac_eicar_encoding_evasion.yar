rule ClamTrac_EICAR_Encoding_Evasion
{
   meta:
      description = "Detects canonical EICAR test string across all evasion encodings: Base64, Hex, UTF-16 LE, UTF-16 BE, ROT13, and Null-Padded"
      author = "ClamTrac"
      reference = "https://github.com/amithalder21/clamav-restapi"
      date = "2026-11-02"
      score = 60

   strings:
      // 1. Plain ASCII & UTF-16 LE:
      // 'ascii' matches 8-bit ASCII. 'wide' matches 16-bit Little-Endian (char 0x00).
      $eicar_plain_wide = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*" ascii wide

      // 2. Base64:
      $eicar_b64 = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*" base64

      // 3. Hex literal (PDF hex strings <58354f21...>):
      $eicar_hex_literal = "58354f2150254041505b345c505a58353428505e2937434329377d2445494341522d5354414e444152442d414e544956495255532d544553542d46494c452124482b482a" ascii nocase

      // 4. Null-padded (byte, 00, byte...) without trailing null:
      // Catches evasion files generated with b'\x00'.join(...) where trailing '*' has no trailing 0x00
      $eicar_null_padded_no_trail = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!" wide

      // 5. UTF-16 BE (Big Endian: 00 byte 00 byte ...):
      $eicar_utf16_be = { 00 58 00 35 00 4f 00 21 00 50 00 25 00 40 00 41 00 50 00 5b 00 34 00 5c 00 50 00 5a 00 58 00 35 00 34 00 28 00 50 00 5e 00 29 00 37 00 43 00 43 00 29 00 37 00 7d 00 24 00 45 00 49 00 43 00 41 00 52 00 2d 00 53 00 54 00 41 00 4e 00 44 00 41 00 52 00 44 00 2d 00 41 00 4e 00 54 00 49 00 56 00 49 00 52 00 55 00 53 00 2d 00 54 00 45 00 53 00 54 00 2d 00 46 00 49 00 4c 00 45 00 21 00 24 00 48 00 2b 00 48 00 2a }

      // 6. ROT13 (Plain ASCII & UTF-16 LE):
      $eicar_rot13 = "K5B!C%@NC[4\\CMK54(C^)7PP)7}$RVPNE-FGNAQNEQ-NAGVIVEHF-GRFG-SVYR!$U+U*" ascii wide

      // 7. ROT13 Base64:
      $eicar_rot13_b64 = "K5B!C%@NC[4\\CMK54(C^)7PP)7}$RVPNE-FGNAQNEQ-NAGVIVEHF-GRFG-SVYR!$U+U*" base64

      // 8. ROT13 Hex literal:
      $eicar_rot13_hex = "4b3542214325404e435b345c434d4b353428435e2937505029377d245256504e452d46474e41514e45512d4e41475649564548462d475246472d535659522124552b552a" ascii nocase

      // 9. ROT13 UTF-16 BE:
      $eicar_rot13_utf16_be = { 00 4b 00 35 00 42 00 21 00 43 00 25 00 40 00 4e 00 43 00 5b 00 34 00 5c 00 43 00 4d 00 4b 00 35 00 34 00 28 00 43 00 5e 00 29 00 37 00 50 00 50 00 29 00 37 00 7d 00 24 00 52 00 56 00 50 00 4e 00 45 00 2d 00 46 00 47 00 4e 00 41 00 51 00 4e 00 45 00 51 00 2d 00 4e 00 41 00 47 00 56 00 49 00 56 00 45 00 48 00 46 00 2d 00 47 00 52 00 46 00 47 00 2d 00 53 00 56 00 59 00 52 00 21 00 24 00 55 00 2b 00 55 00 2a }

   condition:
      any of them
}
