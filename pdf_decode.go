package main

import (
	"bytes"
	"compress/zlib"
	"encoding/ascii85"
	"encoding/hex"
	"io"
)

type decodeLimits struct {
	maxTotalBytes int64
	maxStreams    int
	maxDepth      int
}

const (
	defaultDecodeBytes = 10 << 20
	decodeBytesCeiling = 64 << 20
)

// decodeLimitBytes is the size limit for the decoded-content scan, applied to
// the uploaded file (larger files are not decoded) and to the decoded output
// (cut off at this size). It follows MAX_FILE_SIZE, the largest file the
// service accepts, falling back to 10 MiB when that is unset or invalid and
// never exceeding a fixed 64 MiB ceiling so a large MAX_FILE_SIZE cannot make
// one scan consume unbounded memory.
func decodeLimitBytes() int64 {
	n := parseSize(opts["MAX_FILE_SIZE"])
	if n <= 0 {
		return defaultDecodeBytes
	}
	if n > decodeBytesCeiling {
		return decodeBytesCeiling
	}
	return n
}

func defaultDecodeLimits() decodeLimits {
	return decodeLimits{maxTotalBytes: decodeLimitBytes(), maxStreams: 4096, maxDepth: 3}
}

type decodedBundle struct {
	data      []byte
	truncated bool
}

const minNullsForStrippedView = 16

type bundleBuilder struct {
	lim       decodeLimits
	out       []byte
	truncated bool
}

func (b *bundleBuilder) remaining() int64 {
	return b.lim.maxTotalBytes - int64(len(b.out))
}

func (b *bundleBuilder) full() bool {
	return b.remaining() <= 0
}

func (b *bundleBuilder) emit(p []byte) {
	room := b.remaining() - 1
	if room <= 0 {
		b.truncated = true
		return
	}
	if int64(len(p)) > room {
		p = p[:room]
		b.truncated = true
	}
	b.out = append(b.out, p...)
	b.out = append(b.out, '\n')
}

// buildDecodedBundle returns the readable form of a PDF's hidden content: every
// stream decompressed or decoded (FlateDecode, ASCIIHex, ASCII85, chained up to
// maxDepth), plus copies of the raw and decoded bytes with NUL bytes removed so
// UTF-16 and any amount of null padding collapse to plain text. It decodes by
// trying each decoder on the stream bytes instead of reading /Filter, so a
// #xx-escaped filter name cannot hide a stream. Output size, stream count and
// depth are bounded; hitting a bound sets truncated and stops decoding.
func buildDecodedBundle(raw []byte, lim decodeLimits) decodedBundle {
	b := &bundleBuilder{lim: lim}

	streams := 0
	for pos := 0; pos < len(raw) && !b.full(); {
		start, ok := nextStreamStart(raw, pos)
		if !ok {
			break
		}
		body := raw[start:]
		pos = len(raw)
		if end := bytes.Index(body, []byte("endstream")); end >= 0 {
			body = body[:end]
			pos = start + end + len("endstream")
		}
		if streams >= lim.maxStreams {
			b.truncated = true
			break
		}
		streams++
		b.decodeStream(bytes.TrimRight(body, "\r\n"), 0)
	}

	decoded := b.out[:len(b.out):len(b.out)]
	b.addNullStripped(raw)
	b.addNullStripped(decoded)

	return decodedBundle{data: b.out, truncated: b.truncated}
}

func nextStreamStart(raw []byte, from int) (int, bool) {
	for from < len(raw) {
		i := bytes.Index(raw[from:], []byte("stream"))
		if i < 0 {
			return 0, false
		}
		i += from
		from = i + len("stream")
		if i >= 3 && string(raw[i-3:i]) == "end" {
			continue
		}
		switch {
		case bytes.HasPrefix(raw[from:], []byte("\r\n")):
			return from + 2, true
		case bytes.HasPrefix(raw[from:], []byte("\n")), bytes.HasPrefix(raw[from:], []byte("\r")):
			return from + 1, true
		}
	}
	return 0, false
}

func (b *bundleBuilder) decodeStream(data []byte, depth int) {
	if depth >= b.lim.maxDepth || b.full() {
		return
	}
	decoded, hitLimit := decodeOnce(data, b.remaining())
	if hitLimit {
		b.truncated = true
	}
	if len(decoded) == 0 {
		return
	}
	b.emit(decoded)
	b.decodeStream(decoded, depth+1)
}

func decodeOnce(data []byte, limit int64) ([]byte, bool) {
	if out, hit, ok := inflate(data, limit); ok {
		return out, hit
	}
	if out, hit, ok := decodeASCII85(data, limit); ok {
		return out, hit
	}
	if out, ok := decodeASCIIHex(data); ok {
		return out, false
	}
	return nil, false
}

func readBounded(r io.Reader, limit int64) ([]byte, bool) {
	out, _ := io.ReadAll(io.LimitReader(r, limit+1))
	if int64(len(out)) > limit {
		return out[:limit], true
	}
	return out, false
}

func inflate(data []byte, limit int64) ([]byte, bool, bool) {
	if len(data) < 2 || data[0]&0x0f != 8 || (int(data[0])<<8|int(data[1]))%31 != 0 {
		return nil, false, false
	}
	r, err := zlib.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, false, false
	}
	defer r.Close()
	out, hit := readBounded(r, limit)
	return out, hit, len(out) > 0
}

func decodeASCII85(data []byte, limit int64) ([]byte, bool, bool) {
	t := bytes.TrimSpace(data)
	if !bytes.HasSuffix(t, []byte("~>")) {
		return nil, false, false
	}
	t = bytes.TrimSuffix(bytes.TrimPrefix(t, []byte("<~")), []byte("~>"))
	out, hit := readBounded(ascii85.NewDecoder(bytes.NewReader(t)), limit)
	return out, hit, len(out) > 0
}

func decodeASCIIHex(data []byte) ([]byte, bool) {
	t := bytes.TrimSuffix(bytes.TrimSpace(data), []byte(">"))
	digits := make([]byte, 0, len(t))
	for _, c := range t {
		switch {
		case c == ' ' || c == '\t' || c == '\r' || c == '\n':
		case c >= '0' && c <= '9', c >= 'a' && c <= 'f', c >= 'A' && c <= 'F':
			digits = append(digits, c)
		default:
			return nil, false
		}
	}
	if len(digits) < 8 {
		return nil, false
	}
	if len(digits)%2 == 1 {
		digits = append(digits, '0')
	}
	out := make([]byte, hex.DecodedLen(len(digits)))
	if _, err := hex.Decode(out, digits); err != nil {
		return nil, false
	}
	return out, true
}

func (b *bundleBuilder) addNullStripped(src []byte) {
	if bytes.Count(src, []byte{0}) < minNullsForStrippedView {
		return
	}
	stripped := make([]byte, 0, len(src))
	for _, c := range src {
		if c != 0 {
			stripped = append(stripped, c)
		}
	}
	b.emit(stripped)
}
