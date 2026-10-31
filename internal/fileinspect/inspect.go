// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

// Package fileinspect recovers bounded text views from ZIP and Office packages.
// It makes no traffic-direction or enforcement decision and never rewrites input.
package fileinspect

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/binary"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"math"
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/luckyPipewrench/pipelock/internal/media"
)

// Limits are supplied by the consumer's existing byte and extraction-depth caps.
type Limits struct {
	MaxBytes int
	MaxDepth int
}

// Result distinguishes unsupported input from a recognized but incomplete file.
// Texts remain available on an incomplete read so findings are not lost.
type Result struct {
	Type       string
	Recognized bool
	Complete   bool
	Reason     string
	Texts      []string
	ReadBytes  int
}

// Kind uses format signatures, independently of filenames and MIME labels.
func Kind(data []byte) string {
	switch {
	// PKWARE APPNOTE 4.3.7 and 4.3.16 (local file / empty archive).
	case bytes.HasPrefix(data, []byte("PK\x03\x04")), bytes.HasPrefix(data, []byte("PK\x05\x06")):
		return "ZIP"
	// 7-Zip's 7zFormat.txt, SignatureHeader.Signature[6].
	// https://www.7-zip.org/sdk.html (7z specification in the LZMA SDK).
	case bytes.HasPrefix(data, []byte{'7', 'z', 0xbc, 0xaf, 0x27, 0x1c}):
		return "7z"
	// RAR format specification, archive signature, RAR 4.x and 5.0:
	// https://www.rarlab.com/technote.htm#rarsign
	case bytes.HasPrefix(data, []byte("Rar!\x1a\x07\x00")), bytes.HasPrefix(data, []byte("Rar!\x1a\x07\x01\x00")):
		return "RAR"
	default:
		return ""
	}
}

type walk struct {
	ctx       context.Context
	limits    Limits
	remaining int
	entries   int
	result    *Result
}

// Inspect reads every member through EOF, including checksums, before reporting
// completion. Images are verified as ZIP members but aren't interpreted as text.
// PDF input has no reader here and retains the consumer's raw scanning behavior.
func Inspect(ctx context.Context, data []byte, limits Limits) Result {
	r := Result{Type: Kind(data)}
	if r.Type == "" {
		return r
	}
	r.Recognized = true
	if r.Type != "ZIP" {
		r.Reason = "format has no upload reader"
		return r
	}
	if ctx == nil || limits.MaxBytes <= 0 || limits.MaxDepth <= 0 {
		r.Reason = "invalid inspection budget"
		return r
	}
	w := walk{ctx: ctx, limits: limits, remaining: limits.MaxBytes, entries: limits.MaxBytes / centralHeaderBytes, result: &r}
	if err := w.archive(data, 0); err != nil {
		r.ReadBytes = limits.MaxBytes - w.remaining
		r.Reason = err.Error()
		return r
	}
	r.ReadBytes = limits.MaxBytes - w.remaining
	r.Complete = true
	return r
}

// APPNOTE 4.3.12: fixed central header is 46 bytes. Charging records before
// zip.NewReader prevents attacker-controlled counts from allocating an index
// beyond the caller's metadata byte budget. No independent member cap is guessed.
const (
	centralHeaderBytes = 46
	endHeaderBytes     = 22 // APPNOTE 4.3.16.
)

func (w *walk) preflight(data []byte) error {
	if len(data) > w.limits.MaxBytes {
		return fmt.Errorf("archive exceeds max_body_bytes")
	}
	// APPNOTE: archive comments have a 16-bit length. Find only an EOCD that
	// consumes the entire source, so trailing/truncated trailers aren't clean.
	for i := len(data) - endHeaderBytes; i >= max(0, len(data)-endHeaderBytes-65535); i-- {
		if !bytes.HasPrefix(data[i:], []byte("PK\x05\x06")) {
			continue
		}
		e := data[i:]
		if int(binary.LittleEndian.Uint16(e[20:])) != len(e)-endHeaderBytes {
			continue
		}
		count := int(binary.LittleEndian.Uint16(e[10:]))
		if binary.LittleEndian.Uint32(e[4:]) != 0 || int(binary.LittleEndian.Uint16(e[8:])) != count {
			return fmt.Errorf("multi-volume archive is not readable")
		}
		size := int64(binary.LittleEndian.Uint32(e[12:]))
		offset := int64(binary.LittleEndian.Uint32(e[16:]))
		if count == 65535 || size == 0xffffffff || offset == 0xffffffff {
			return fmt.Errorf("ZIP64 archive is not readable")
		}
		if count > w.entries || int64(count)*centralHeaderBytes > size {
			return fmt.Errorf("member count exceeds metadata budget")
		}
		if offset+size != int64(i) {
			return fmt.Errorf("invalid central directory trailer")
		}
		if offset > math.MaxInt32 {
			return fmt.Errorf("ZIP directory exceeds addressable index")
		}
		p := int(offset)
		for range count {
			if p > i-centralHeaderBytes || !bytes.HasPrefix(data[p:], []byte("PK\x01\x02")) {
				return fmt.Errorf("invalid central directory record")
			}
			n := centralHeaderBytes + int(binary.LittleEndian.Uint16(data[p+28:])) + int(binary.LittleEndian.Uint16(data[p+30:])) + int(binary.LittleEndian.Uint16(data[p+32:]))
			if n > i-p {
				return fmt.Errorf("truncated central directory record")
			}
			// The local and central headers describe the same member (APPNOTE
			// 4.3.7/4.3.12). archive/zip trusts the central flags, so verify the
			// local encryption flag too before accepting any derived view.
			local := int64(binary.LittleEndian.Uint32(data[p+42:]))
			if local > math.MaxInt32 || local+30 > offset {
				return fmt.Errorf("invalid local member header")
			}
			l := int(local)
			if !bytes.HasPrefix(data[l:], []byte("PK\x03\x04")) || binary.LittleEndian.Uint16(data[l+6:]) != binary.LittleEndian.Uint16(data[p+8:]) || binary.LittleEndian.Uint16(data[l+8:]) != binary.LittleEndian.Uint16(data[p+10:]) {
				return fmt.Errorf("local member flags or method disagree with directory")
			}
			nameLen := int(binary.LittleEndian.Uint16(data[p+28:]))
			localNameLen := int(binary.LittleEndian.Uint16(data[l+26:]))
			headerEnd := l + 30 + localNameLen + int(binary.LittleEndian.Uint16(data[l+28:]))
			if headerEnd > int(offset) || localNameLen != nameLen || !bytes.Equal(data[l+30:l+30+localNameLen], data[p+centralHeaderBytes:p+centralHeaderBytes+nameLen]) {
				return fmt.Errorf("local member name or length disagrees with directory")
			}
			if int64(headerEnd)+int64(binary.LittleEndian.Uint32(data[p+20:])) > offset {
				return fmt.Errorf("compressed member overlaps ZIP directory")
			}
			if binary.LittleEndian.Uint16(data[p+8:])&8 == 0 &&
				(binary.LittleEndian.Uint32(data[l+14:]) != binary.LittleEndian.Uint32(data[p+16:]) ||
					binary.LittleEndian.Uint32(data[l+18:]) != binary.LittleEndian.Uint32(data[p+20:]) ||
					binary.LittleEndian.Uint32(data[l+22:]) != binary.LittleEndian.Uint32(data[p+24:])) {
				return fmt.Errorf("local member checksum or size disagrees with directory")
			}
			p += n
		}
		if p != i {
			return fmt.Errorf("unread central directory data")
		}
		w.entries -= count
		return nil
	}
	return fmt.Errorf("missing or damaged ZIP trailer")
}

func (w *walk) archive(data []byte, depth int) error {
	if err := w.ctx.Err(); err != nil {
		return err
	}
	if depth >= w.limits.MaxDepth {
		return fmt.Errorf("nested archive exceeds extraction depth budget")
	}
	if err := w.preflight(data); err != nil {
		return err
	}
	z, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return fmt.Errorf("opening archive: %w", err)
	}
	// ECMA-376 Part 2 OPC [Content_Types].xml and ODF 1.3 Part 2
	// mimetype/manifest identify package semantics, not the upload's extension.
	for _, f := range z.File {
		if f.Name == "[Content_Types].xml" && depth == 0 {
			w.result.Type = "Office/ZIP"
		}
		if f.Name == "META-INF/manifest.xml" && depth == 0 {
			w.result.Type = "OpenDocument/ZIP"
		}
	}
	w.result.Texts = append(w.result.Texts, z.Comment)
	var parts packageParts
	sort.SliceStable(z.File, func(i, j int) bool { return declarationPriority(z.File[i].Name) < declarationPriority(z.File[j].Name) })
	for _, f := range z.File {
		if err := w.ctx.Err(); err != nil {
			return err
		}
		// APPNOTE 4.4.4 bit 0 is encryption, including on deflate members.
		if f.Flags&1 != 0 {
			return fmt.Errorf("encrypted member")
		}
		if f.Method != zip.Store && f.Method != zip.Deflate {
			return fmt.Errorf("unsupported ZIP compression method %d", f.Method)
		}
		// The byte ceiling also bounds expansion ratio: for C compressed bytes
		// at most remaining/C expansion is admitted. Charge the advertised size
		// before allocation, and read one extra byte to reject understated sizes.
		if w.remaining < 0 || f.UncompressedSize64 > math.MaxInt32 || f.UncompressedSize64 > uint64(w.remaining) {
			return fmt.Errorf("expanded member exceeds max_body_bytes / compression-ratio budget")
		}
		n := int(f.UncompressedSize64)
		w.remaining -= n
		reader, openErr := f.Open()
		if openErr != nil {
			return fmt.Errorf("opening member: %w", openErr)
		}
		member, readErr := io.ReadAll(io.LimitReader(&contextReader{w.ctx, reader}, int64(n)+1))
		closeErr := reader.Close()
		if readErr != nil {
			return fmt.Errorf("reading member: %w", readErr)
		}
		if closeErr != nil {
			return fmt.Errorf("closing member: %w", closeErr)
		}
		if len(member) != n {
			return fmt.Errorf("member size does not match ZIP directory")
		}
		w.result.Texts = append(w.result.Texts, f.Name, f.Comment)
		if f.FileInfo().IsDir() {
			continue
		}
		if kind := Kind(member); kind != "" {
			if kind != "ZIP" {
				return fmt.Errorf("embedded %s format has no upload reader", kind)
			}
			if err := w.archive(member, depth+1); err != nil {
				return err
			}
			continue
		}
		// Container members contribute their recursively recovered views,
		// not another speculative text scan of compressed bytes. The original
		// request still receives its existing raw DLP scan.
		w.result.Texts = append(w.result.Texts, string(member))
		if bytes.HasPrefix(member, []byte("%PDF-")) {
			continue
		}
		if err := parts.metadata(f.Name, member); err != nil {
			return err
		}
		contentType := parts.contentType(f.Name)
		if image(member) || strings.HasPrefix(contentType, "image/") {
			continue
		} // Non-text, including ODF Thumbnails/thumbnail.png.
		if !utf8.Valid(member) {
			// ECMA-376 binary macro/printer parts aren't text and aren't executed.
			if strings.HasPrefix(f.Name, "word/printerSettings/") || strings.HasSuffix(f.Name, "/vbaProject.bin") {
				continue
			}
			return fmt.Errorf("non-text member has no reader")
		}
		if isXMLPart(f.Name, contentType) {
			text, xmlErr := xmlText(member, w.limits.MaxDepth)
			if xmlErr != nil {
				return xmlErr
			}
			w.result.Texts = append(w.result.Texts, text)
		}
	}
	return nil
}

type contextReader struct {
	ctx    context.Context
	reader io.Reader
}

func (r *contextReader) Read(p []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	return r.reader.Read(p)
}

// image joins the existing media.DetectType signature contract. Its detector
// and dependencies use only the standard library; no image decoder is added.
func image(data []byte) bool {
	return strings.HasPrefix(media.DetectType(data), "image/")
}

// XML character data joins formatting runs within paragraphs/cells. Paragraph,
// row and cell boundaries remain separators (ECMA-376 w:p/a:p and ODF text:p).
// All XML parts are scanned, including relationships, hidden sheets, notes,
// comments and metadata; no relationship is fetched and no macro is executed.
func xmlText(data []byte, maxDepth int) (string, error) {
	d := xml.NewDecoder(bytes.NewReader(data))
	var out strings.Builder
	depth := 0
	for {
		token, err := d.Token()
		if errors.Is(err, io.EOF) {
			return out.String(), nil
		}
		if err != nil {
			// SyntaxError may quote element names or entity text from the file.
			// Reasons can reach logs and receipts; retain the failure class,
			// never document content.
			return "", fmt.Errorf("malformed package XML")
		}
		switch t := token.(type) {
		case xml.StartElement:
			depth++
			if depth > maxDepth {
				return "", fmt.Errorf("package XML exceeds extraction depth budget")
			}
		case xml.EndElement:
			depth--
			switch t.Name.Local {
			case "p", "h", "c", "row", "table-cell", "table-row":
				out.WriteByte('\n')
			}
		case xml.CharData:
			out.Write(t)
		case xml.Directive:
			return "", fmt.Errorf("package XML directive is not readable")
		}
	}
}
