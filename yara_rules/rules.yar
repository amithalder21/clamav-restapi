// Custom ClamTrac YARA rules, layered on top of the pinned upstream
// Neo23x0/signature-base ruleset (see the Dockerfile's SIGNATURE_BASE_COMMIT/
// SIGNATURE_BASE_SHA256 build args). This file is COPY'd in at build time as
// signature-base/yara/zz_custom_rules.yar and compiled into compiled.yarc
// alongside everything else, so it's part of the same reviewed, versioned
// build as the Go application code - not a live external fetch.

rule ClamTrac_EICAR_Encoding_Evasion
{
   meta:
      description = "Detects the canonical EICAR test string embedded anywhere in a file (not just as a standalone file), including base64- and hex-encoded forms - closes an evasion gap where upstream's own EICAR rule only matches a raw, standalone EICAR file at offset 0 with a small filesize, so a document format (e.g. a PDF /JavaScript action or hex string literal) carrying an encoded EICAR string was never matched by any YARA rule in this ruleset"
      author = "ClamTrac"
      reference = "https://github.com/amithalder21/clamav-restapi"
      date = "2026-09-30"
      score = 60
   strings:
      // Plain EICAR anywhere in the file (not anchored to offset 0 or a
      // small filesize) - defense in depth alongside ClamAV's own built-in
      // EICAR signature, which already covers this case independently.
      $eicar_plain = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*" ascii

      // base64: YARA's base64 modifier auto-generates all 3 byte-alignment
      // variants of the base64 encoding and matches them, so this catches
      // the EICAR string base64-encoded at any offset in the file.
      $eicar_b64 = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*" base64

      // hex: PDF's own spec allows string literals written as ASCII-hex
      // inside angle brackets (e.g. <58354f21...>). YARA has no auto "hex"
      // modifier equivalent to base64, so this is the literal ASCII-hex
      // representation of the same 68 bytes above.
      $eicar_hex_literal = "58354f2150254041505b345c505a58353428505e2937434329377d2445494341522d5354414e444152442d414e544956495255532d544553542d46494c452124482b482a" ascii nocase

   condition:
      any of them
}
