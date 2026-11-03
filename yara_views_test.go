package main

import (
	"bytes"
	"compress/zlib"
	"encoding/base64"
	"encoding/hex"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

const eicarString = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$" + "EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"

func rot13(s string) string {
	out := []byte(s)
	for i, c := range out {
		switch {
		case c >= 'a' && c <= 'z':
			out[i] = 'a' + (c-'a'+13)%26
		case c >= 'A' && c <= 'Z':
			out[i] = 'A' + (c-'A'+13)%26
		}
	}
	return string(out)
}

func utf16(s string, bigEndian bool) []byte {
	var out []byte
	for i := 0; i < len(s); i++ {
		if bigEndian {
			out = append(out, 0, s[i])
		} else {
			out = append(out, s[i], 0)
		}
	}
	return out
}

func eicarVariants() map[string][]byte {
	return map[string][]byte{
		"plain":   []byte(eicarString),
		"base64":  []byte(base64.StdEncoding.EncodeToString([]byte(eicarString))),
		"hex":     []byte(hex.EncodeToString([]byte(eicarString))),
		"utf16le": utf16(eicarString, false),
		"utf16be": utf16(eicarString, true),
		"rot13":   []byte(rot13(eicarString)),
		"null1":   nullPadded(eicarString, 1),
		"null2":   nullPadded(eicarString, 2),
	}
}

func useCompiledTestRules(t *testing.T) {
	t.Helper()
	for _, bin := range []string{"yara", "yarac"} {
		if _, err := exec.LookPath(bin); err != nil {
			t.Skipf("%s not installed; skipping YARA integration test", bin)
		}
	}
	src, _ := filepath.Abs("testdata/yara/clamtrac_eicar_encoding_evasion.yar")
	out := filepath.Join(t.TempDir(), "rules.yarc")
	cmd := exec.Command("yarac", "-d", `filename=`, "-d", `filepath=`, "-d", `extension=`, "-d", `owner=`, "-d", `filetype=`, src, out)
	if b, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("compiling test rules: %v\n%s", err, b)
	}
	prev := yaraCompiledRules
	yaraCompiledRules = out
	t.Cleanup(func() { yaraCompiledRules = prev })
}

func writePDF(t *testing.T, payload []byte, compressed bool) string {
	t.Helper()
	content := append(append([]byte{}, payload...), []byte("\nBT /F1 12 Tf (readable text) Tj ET\n")...)
	dict := ""
	if compressed {
		var buf bytes.Buffer
		w := zlib.NewWriter(&buf)
		w.Write(content)
		w.Close()
		content = buf.Bytes()
		dict = "/Filter /FlateDecode"
	}
	p := filepath.Join(t.TempDir(), "upload.pdf")
	if err := os.WriteFile(p, pdfWithStreams([]string{dict}, [][]byte{content}), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestRawYaraMissesEncodedEicarInCompressedStreams(t *testing.T) {
	useCompiledTestRules(t)
	for name, payload := range eicarVariants() {
		if name == "plain" {
			continue
		}
		res := RunYaraScan(writePDF(t, payload, true), "upload.pdf", "req")
		if res.IsInfected {
			t.Errorf("%s: raw-byte YARA unexpectedly matched inside a compressed stream; the fixture no longer reproduces the original gap", name)
		}
	}
}

func TestYaraWithViewsCatchesEveryEicarEncodingCompressedOrNot(t *testing.T) {
	useCompiledTestRules(t)
	for _, compressed := range []bool{false, true} {
		for name, payload := range eicarVariants() {
			label := name
			if compressed {
				label += "/compressed"
			}
			res := RunYaraScanWithViews(writePDF(t, payload, compressed), "upload.pdf", "req")
			if res.Error != nil {
				t.Errorf("%s: engine error: %v", label, res.Error)
				continue
			}
			if !res.IsInfected {
				t.Errorf("%s: not detected", label)
			}
			if !strings.Contains(res.Signature, "ClamTrac_EICAR_Encoding_Evasion") {
				t.Errorf("%s: unexpected signature %q", label, res.Signature)
			}
		}
	}
}

func TestYaraWithViewsLeavesCleanPDFsAlone(t *testing.T) {
	useCompiledTestRules(t)
	for _, compressed := range []bool{false, true} {
		res := RunYaraScanWithViews(writePDF(t, []byte("An ordinary invoice, total 120.00 EUR."), compressed), "invoice.pdf", "req")
		if res.Error != nil || res.IsInfected {
			t.Errorf("compressed=%v: clean PDF flagged: %+v", compressed, res)
		}
	}
}

func writePaddedPDF(t *testing.T, payload []byte, totalSize int) string {
	t.Helper()
	p := writePDF(t, payload, true)
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	if len(b) > totalSize {
		t.Fatalf("fixture already %d bytes, larger than the %d target", len(b), totalSize)
	}
	b = append(b, bytes.Repeat([]byte("\n"), totalSize-len(b))...)
	if err := os.WriteFile(p, b, 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestDecodedScanAppliesUpToMaxFileSizeAndNotBeyond(t *testing.T) {
	useCompiledTestRules(t)
	payload := eicarVariants()["base64"]
	for setting, limit := range map[string]int{"5M": 5 << 20, "10M": 10 << 20} {
		withMaxFileSize(t, setting)

		atLimit := RunYaraScanWithViews(writePaddedPDF(t, payload, limit), "upload.pdf", "req")
		if atLimit.Error != nil || !atLimit.IsInfected {
			t.Errorf("MAX_FILE_SIZE=%s: a file of exactly the limit must still get the decoded scan: %+v", setting, atLimit)
		}

		overLimit := RunYaraScanWithViews(writePaddedPDF(t, payload, limit+1), "upload.pdf", "req")
		if overLimit.Error != nil {
			t.Fatalf("MAX_FILE_SIZE=%s: an oversized file must be scanned as-is, not fail: %v", setting, overLimit.Error)
		}
		if overLimit.IsInfected {
			t.Errorf("MAX_FILE_SIZE=%s: a file over the limit must not get the decoded scan", setting)
		}
	}
}
