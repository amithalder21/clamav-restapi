package main

import (
	"bytes"
	"compress/zlib"
	"encoding/ascii85"
	"encoding/hex"
	"fmt"
	"runtime"
	"strings"
	"testing"
)

func zlibBytes(t *testing.T, data []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	w := zlib.NewWriter(&buf)
	if _, err := w.Write(data); err != nil {
		t.Fatal(err)
	}
	w.Close()
	return buf.Bytes()
}

func pdfWithStreams(dicts []string, streams [][]byte) []byte {
	var b bytes.Buffer
	b.WriteString("%PDF-1.4\n")
	for i, s := range streams {
		fmt.Fprintf(&b, "%d 0 obj\n<<%s /Length %d>>\nstream\n", i+1, dicts[i], len(s))
		b.Write(s)
		b.WriteString("\nendstream\nendobj\n")
	}
	b.WriteString("trailer<<>>\n%%EOF\n")
	return b.Bytes()
}

func nullPadded(s string, nulls int) []byte {
	var out []byte
	for i := 0; i < len(s); i++ {
		if i > 0 {
			out = append(out, make([]byte, nulls)...)
		}
		out = append(out, s[i])
	}
	return out
}

func TestBundleInflatesFlateStream(t *testing.T) {
	raw := pdfWithStreams([]string{"/Filter /FlateDecode"}, [][]byte{zlibBytes(t, []byte("UNIQUE-MARKER-123"))})
	got := buildDecodedBundle(raw, defaultDecodeLimits())
	if !bytes.Contains(got.data, []byte("UNIQUE-MARKER-123")) {
		t.Errorf("inflated content missing from bundle: %q", got.data)
	}
}

func TestBundleDecodesASCIIHexThenFlate(t *testing.T) {
	inner := []byte(hex.EncodeToString(zlibBytes(t, []byte("HEX-THEN-FLATE-MARKER"))) + ">")
	raw := pdfWithStreams([]string{"/Filter [/ASCIIHexDecode /FlateDecode]"}, [][]byte{inner})
	got := buildDecodedBundle(raw, defaultDecodeLimits())
	if !bytes.Contains(got.data, []byte("HEX-THEN-FLATE-MARKER")) {
		t.Errorf("chained decode missing from bundle: %q", got.data)
	}
}

func TestBundleDecodesASCII85ThenFlate(t *testing.T) {
	z := zlibBytes(t, []byte("A85-THEN-FLATE-MARKER"))
	enc := make([]byte, ascii85.MaxEncodedLen(len(z)))
	n := ascii85.Encode(enc, z)
	inner := append(append([]byte{}, enc[:n]...), []byte("~>")...)
	raw := pdfWithStreams([]string{"/Filter [/ASCII85Decode /FlateDecode]"}, [][]byte{inner})
	got := buildDecodedBundle(raw, defaultDecodeLimits())
	if !bytes.Contains(got.data, []byte("A85-THEN-FLATE-MARKER")) {
		t.Errorf("chained decode missing from bundle: %q", got.data)
	}
}

func TestBundleIgnoresObfuscatedFilterNames(t *testing.T) {
	raw := pdfWithStreams([]string{"/Filter /Fl#61teDecode"}, [][]byte{zlibBytes(t, []byte("OBFUSCATED-NAME-MARKER"))})
	got := buildDecodedBundle(raw, defaultDecodeLimits())
	if !bytes.Contains(got.data, []byte("OBFUSCATED-NAME-MARKER")) {
		t.Errorf("a #xx-escaped filter name must not hide a stream: %q", got.data)
	}
}

func TestBundleStripsNullPaddingFromRawBytes(t *testing.T) {
	for _, nulls := range []int{1, 2, 3} {
		raw := pdfWithStreams([]string{""}, [][]byte{nullPadded("NULL-PADDED-MARKER-TEXT", nulls)})
		got := buildDecodedBundle(raw, defaultDecodeLimits())
		if !bytes.Contains(got.data, []byte("NULL-PADDED-MARKER-TEXT")) {
			t.Errorf("%d nulls per character not normalised: %q", nulls, got.data)
		}
	}
}

func TestBundleStripsNullPaddingInsideCompressedStream(t *testing.T) {
	raw := pdfWithStreams([]string{"/Filter /FlateDecode"}, [][]byte{zlibBytes(t, nullPadded("PADDED-IN-FLATE-MARKER", 2))})
	got := buildDecodedBundle(raw, defaultDecodeLimits())
	if !bytes.Contains(got.data, []byte("PADDED-IN-FLATE-MARKER")) {
		t.Errorf("null padding inside a compressed stream not normalised: %q", got.data)
	}
}

func TestBundleIsEmptyWhenThereIsNothingToDecode(t *testing.T) {
	raw := pdfWithStreams([]string{""}, [][]byte{[]byte("BT (plain readable text) Tj ET")})
	got := buildDecodedBundle(raw, defaultDecodeLimits())
	if len(got.data) != 0 || got.truncated {
		t.Errorf("expected an empty bundle, got %d bytes truncated=%v", len(got.data), got.truncated)
	}
}

func TestBundleBoundsDecompressionBombs(t *testing.T) {
	bomb := zlibBytes(t, make([]byte, 16<<20))
	raw := pdfWithStreams([]string{"/Filter /FlateDecode"}, [][]byte{bomb})
	lim := defaultDecodeLimits()
	lim.maxTotalBytes = 1 << 20
	got := buildDecodedBundle(raw, lim)
	if int64(len(got.data)) > lim.maxTotalBytes+1024 {
		t.Errorf("bundle grew to %d bytes despite a %d byte limit", len(got.data), lim.maxTotalBytes)
	}
	if !got.truncated {
		t.Error("hitting the size limit must be reported as truncated")
	}
}

func TestBundleBoundsStreamCount(t *testing.T) {
	var dicts []string
	var streams [][]byte
	for i := 0; i < 100; i++ {
		dicts = append(dicts, "/Filter /FlateDecode")
		streams = append(streams, zlibBytes(t, []byte(fmt.Sprintf("STREAM-NUMBER-%03d", i))))
	}
	lim := defaultDecodeLimits()
	lim.maxStreams = 10
	got := buildDecodedBundle(pdfWithStreams(dicts, streams), lim)
	if !bytes.Contains(got.data, []byte("STREAM-NUMBER-000")) {
		t.Error("the first streams should still be decoded")
	}
	if bytes.Contains(got.data, []byte("STREAM-NUMBER-050")) || !got.truncated {
		t.Errorf("stream limit not enforced (truncated=%v)", got.truncated)
	}
}

func TestBundleSurvivesMalformedInput(t *testing.T) {
	cases := map[string]string{
		"stream without endstream": "1 0 obj<<>>\nstream\nabcdef",
		"bad zlib header":          "1 0 obj<<>>\nstream\n\x78\x9cgarbage-not-deflate\nendstream",
		"empty stream":             "1 0 obj<<>>\nstream\n\nendstream",
		"only the keyword":         "stream",
		"endstream first":          "endstream\nstream\r\n",
		"truncated hex":            "1 0 obj<<>>\nstream\n4a4b4>\nendstream",
	}
	for name, in := range cases {
		t.Run(name, func(t *testing.T) {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("panicked: %v", r)
				}
			}()
			buildDecodedBundle([]byte(in), defaultDecodeLimits())
		})
	}
}

func TestBundleSeparatesDecodedStreams(t *testing.T) {
	raw := pdfWithStreams([]string{"/Filter /FlateDecode", "/Filter /FlateDecode"}, [][]byte{zlibBytes(t, []byte("FIRST")), zlibBytes(t, []byte("SECOND"))})
	got := string(buildDecodedBundle(raw, defaultDecodeLimits()).data)
	if strings.Contains(got, "FIRSTSECOND") {
		t.Errorf("decoded streams must not run together: %q", got)
	}
}

func TestBundleDoesNotAllocateForHugeDecompressionBombs(t *testing.T) {
	var buf bytes.Buffer
	w := zlib.NewWriter(&buf)
	chunk := make([]byte, 1<<20)
	for i := 0; i < 64; i++ {
		w.Write(chunk)
	}
	w.Close()
	raw := pdfWithStreams([]string{"/Filter /FlateDecode"}, [][]byte{buf.Bytes()})

	lim := defaultDecodeLimits()
	lim.maxTotalBytes = 1 << 20
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	buildDecodedBundle(raw, lim)
	runtime.ReadMemStats(&after)

	if grown := after.TotalAlloc - before.TotalAlloc; grown > 16<<20 {
		t.Errorf("a 64 MiB bomb with a 1 MiB limit allocated %d MiB; decompression must be cut off at the limit, not after it", grown>>20)
	}
}

func withMaxFileSize(t *testing.T, value string) {
	t.Helper()
	prev := opts
	opts = map[string]string{}
	if value != "" {
		opts["MAX_FILE_SIZE"] = value
	}
	t.Cleanup(func() { opts = prev })
}

func TestDecodeLimitFollowsMaxFileSize(t *testing.T) {
	cases := map[string]int64{
		"":        10 << 20,
		"10M":     10 << 20,
		"5M":      5 << 20,
		"25M":     25 << 20,
		"garbage": 10 << 20,
		"0":       10 << 20,
		"1G":      64 << 20,
	}
	for setting, want := range cases {
		withMaxFileSize(t, setting)
		if got := decodeLimitBytes(); got != want {
			t.Errorf("MAX_FILE_SIZE=%q: decode limit = %d, want %d", setting, got, want)
		}
		if got := defaultDecodeLimits().maxTotalBytes; got != want {
			t.Errorf("MAX_FILE_SIZE=%q: decoded-output limit = %d, want %d", setting, got, want)
		}
	}
}

func TestBundleNeverExceedsTenMiBWithDefaultLimits(t *testing.T) {
	withMaxFileSize(t, "10M")
	raw := pdfWithStreams([]string{"/Filter /FlateDecode"}, [][]byte{zlibBytes(t, make([]byte, 32<<20))})
	got := buildDecodedBundle(raw, defaultDecodeLimits())
	if len(got.data) > 10<<20 {
		t.Errorf("bundle is %d bytes, over the %d byte limit", len(got.data), 10<<20)
	}
	if !got.truncated {
		t.Error("output was cut at the limit and must be reported as truncated")
	}
}

func TestBundleKeepsContentFromCorruptedZlibStreams(t *testing.T) {
	good := zlibBytes(t, []byte("CORRUPT-CHECKSUM-MARKER "+strings.Repeat("filler ", 50)))

	badChecksum := append([]byte{}, good...)
	for i := len(badChecksum) - 4; i < len(badChecksum); i++ {
		badChecksum[i] ^= 0xff
	}
	truncated := good[:len(good)-6]

	for name, stream := range map[string][]byte{"bad checksum": badChecksum, "truncated stream": truncated} {
		raw := pdfWithStreams([]string{"/Filter /FlateDecode"}, [][]byte{stream})
		got := buildDecodedBundle(raw, defaultDecodeLimits())
		if !bytes.Contains(got.data, []byte("CORRUPT-CHECKSUM-MARKER")) {
			t.Errorf("%s: content decoded before the damage was dropped: %q", name, got.data)
		}
	}
}
