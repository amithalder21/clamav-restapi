package main

import (
	"archive/zip"
	"bytes"
	"os"
)

var zipMagicPrefixes = [][]byte{
	[]byte("PK\x03\x04"), // local file header (normal, non-empty archive)
	[]byte("PK\x05\x06"), // end of central directory (empty archive)
	[]byte("PK\x07\x08"), // spanned archive data descriptor
}

// IsEncryptedZip reports whether filePath is a ZIP archive containing at
// least one password-protected entry. None of ClamAV/YARA/Maldet can inspect
// encrypted content, so an attacker can smuggle a payload past all three
// simply by encrypting it in a ZIP - this must be rejected before scanning
// is even attempted (2026-09-01 AppSec adversarial test, P1/CRITICAL).
//
// Only ZIP is checked: it's the sole archive-encryption bypass actually
// confirmed in that test (cat2_pwdzip.zip). RAR/7z password-protection
// detection needs either carefully tested binary format parsing or a vetted
// third-party parser - neither could be verified here without a live
// encrypted sample to test against, so this deliberately does not attempt
// it rather than ship unverified detection logic for a security control.
// Follow-up: validate RAR/7z coverage against real samples before relying
// on this check for those formats.
func IsEncryptedZip(filePath string) bool {
	f, err := os.Open(filePath)
	if err != nil {
		return false
	}
	defer f.Close()

	header := make([]byte, 4)
	if _, err := f.Read(header); err != nil {
		return false
	}

	isZip := false
	for _, magic := range zipMagicPrefixes {
		if bytes.Equal(header, magic) {
			isZip = true
			break
		}
	}
	if !isZip {
		return false
	}

	fi, err := f.Stat()
	if err != nil {
		return false
	}
	zr, err := zip.NewReader(f, fi.Size())
	if err != nil {
		// Not a parseable ZIP central directory (truncated/corrupt/not
		// actually ZIP despite the magic bytes) - let the scan engines
		// handle it rather than guessing.
		return false
	}
	for _, zf := range zr.File {
		// Bit 0 of the ZIP general purpose bit flag indicates the entry is
		// encrypted (traditional PKWARE or AES via the 0x9901 extra field).
		if zf.Flags&0x1 != 0 {
			return true
		}
	}
	return false
}

const encryptedArchiveSignature = "POLICY:ENCRYPTED_ARCHIVE_REJECTED"
const encryptedArchiveMessage = "Encrypted/password-protected archives cannot be scanned and are rejected by policy"
