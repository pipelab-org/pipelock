// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

// Package fileinspect recovers bounded text views from ZIP and Office packages.
// It makes no traffic-direction or enforcement decision and never rewrites input.
package fileinspect

import (
	"archive/zip"
	"bufio"
	"bytes"
	"compress/flate"
	"context"
	"encoding/binary"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"math"
	"net/url"
	"path"
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
	odfDrawingNamespace = "urn:oasis:names:tc:opendocument:xmlns:drawing:1.0"
	xlinkNamespace      = "http://www.w3.org/1999/xlink"
)

const (
	centralHeaderBytes = 46
	endHeaderBytes     = 22 // APPNOTE 4.3.16.

	// APPNOTE 6.3.10 4.4.4 general purpose bits 0, 6 and 13, and bit 5.
	encryptionFlags = 1 | 1<<6 | 1<<13
	patchedDataFlag = 1 << 5
	// APPNOTE 6.3.10 extra field IDs: 0x0001 ZIP64 extended information
	// (4.5.3), 0x0017 Strong Encryption Header (4.5.12) and 0x9901 AE-x
	// encryption structure (4.6.1, APPENDIX E).
	zip64ExtraID            = 0x0001
	strongEncryptionExtraID = 0x0017
	aexEncryptionExtraID    = 0x9901
)

// MS-CFB 2.2 Compound File Header: Header Signature.
var compoundFileSignature = []byte{0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1}

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
		spans := make([][2]int, 0, count)
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
			// An encryption extra record marks an encrypted member even when
			// a writer leaves the flag bits clear. APPNOTE 7.2.3 places 0x0017
			// in the central header; AE-x records appear in both headers.
			centralExtra := data[p+centralHeaderBytes+nameLen : p+centralHeaderBytes+nameLen+int(binary.LittleEndian.Uint16(data[p+30:]))]
			if hasExtra(centralExtra, strongEncryptionExtraID, aexEncryptionExtraID) ||
				hasExtra(data[l+30+localNameLen:headerEnd], strongEncryptionExtraID, aexEncryptionExtraID) {
				return fmt.Errorf("encrypted member")
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
			end := headerEnd + int(binary.LittleEndian.Uint32(data[p+20:]))
			if binary.LittleEndian.Uint16(data[p+8:])&8 != 0 {
				// APPNOTE 4.3.9: a data descriptor follows the data, with an
				// optional signature. Its sizes are 8 bytes when the local
				// header has a ZIP64 extended information field (4.3.9.2).
				descriptor := 12
				if hasExtra(data[l+30+localNameLen:headerEnd], zip64ExtraID) {
					descriptor = 20
				}
				if end+4 <= int(offset) && bytes.HasPrefix(data[end:], []byte("PK\x07\x08")) {
					descriptor += 4
				}
				end += descriptor
			}
			spans = append(spans, [2]int{l, end})
			p += n
		}
		if p != i {
			return fmt.Errorf("unread central directory data")
		}
		// APPNOTE 4.3.6: member records precede the central directory. A byte
		// range no listed member covers, such as a local record the directory
		// omits, is input a streaming reader can extract and this walk would skip.
		sort.Slice(spans, func(a, b int) bool { return spans[a][0] < spans[b][0] })
		next := 0
		for _, s := range spans {
			if s[0] != next {
				return fmt.Errorf("ZIP data outside listed members")
			}
			next = s[1]
		}
		if next != int(offset) {
			return fmt.Errorf("ZIP data outside listed members")
		}
		w.entries -= count
		return nil
	}
	return fmt.Errorf("missing or damaged ZIP trailer")
}

// hasExtra walks APPNOTE 4.5.1 extra-field records (2-byte header ID, 2-byte
// data size) for any of the given header IDs.
func hasExtra(extra []byte, ids ...uint16) bool {
	for len(extra) >= 4 {
		id, size := binary.LittleEndian.Uint16(extra), int(binary.LittleEndian.Uint16(extra[2:]))
		for _, want := range ids {
			if id == want {
				return true
			}
		}
		if 4+size > len(extra) {
			return false
		}
		extra = extra[4+size:]
	}
	return false
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
	// Non-text members are decided after every package XML part is read, so a
	// replacement image referenced later in the archive is still recognized.
	var binary []string
	images := make(map[string]bool)
	sort.SliceStable(z.File, func(i, j int) bool { return declarationPriority(z.File[i].Name) < declarationPriority(z.File[j].Name) })
	for _, f := range z.File {
		if err := w.ctx.Err(); err != nil {
			return err
		}
		// APPNOTE 6.3.10 4.4.4: bit 0 is encryption, bit 6 strong encryption
		// and bit 13 local header values masked by central directory
		// encryption. archive/zip reads none of them and returns the stored
		// bytes as if they were the member. Bit 5 marks compressed patched
		// data, a delta against another file rather than the member itself.
		if f.Flags&encryptionFlags != 0 {
			return fmt.Errorf("encrypted member")
		}
		if f.Flags&patchedDataFlag != 0 {
			return fmt.Errorf("patched data member has no reader")
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
		// APPNOTE treats a directory as a zero-length name ending in slash.
		// archive/zip Open returns EOF when the uncompressed size is 0 and
		// does not read CompressedSize64, which is how some writers store an
		// empty deflate stream. A nonempty payload is still a member body:
		// scan it, and refuse completion when it disagrees with the claimed size.
		// Directory status is the trailing slash Open tests. External attributes
		// are host-dependent (APPNOTE 4.4.15), and Open, Python zipfile, Info-ZIP
		// and LibreOffice all read a slashless member marked as a directory as a
		// file, so it gets the file member checks.
		if strings.HasSuffix(f.Name, "/") {
			w.result.Texts = append(w.result.Texts, f.Name, f.Comment)
			if f.CompressedSize64 == 0 {
				continue
			}
			payload, err := w.directoryPayload(f)
			if err != nil {
				return err
			}
			if kind := Kind(payload); kind != "" {
				if kind != "ZIP" {
					return fmt.Errorf("embedded %s format has no upload reader", kind)
				}
				if err := w.archive(payload, depth+1); err != nil {
					return err
				}
			} else if len(payload) > 0 {
				w.result.Texts = append(w.result.Texts, string(payload))
			}
			if uint64(len(payload)) != f.UncompressedSize64 {
				return fmt.Errorf("directory member has unread data")
			}
			continue
		}
		if f.Method == zip.Deflate {
			if err := w.deflateConsumesMember(f); err != nil {
				return err
			}
		}
		w.result.Texts = append(w.result.Texts, f.Name, f.Comment)
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
		// An OLE compound file (MS-CFB) is a sector-allocated container: a
		// stream can be fragmented across sectors, and VBA project source is
		// compressed inside it (MS-OVBA). The signature decides, not a name,
		// a declared type, or a replacement-image reference.
		if bytes.HasPrefix(member, compoundFileSignature) {
			return fmt.Errorf("OLE compound file member has no reader")
		}
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
			// ECMA-376 binary printer parts aren't text and aren't executed.
			// Part 1 defines the Printer Settings part for WordprocessingML,
			// SpreadsheetML and PresentationML packages alike. A VBA project
			// part is not on this list: its macro source is compressed.
			if strings.HasPrefix(f.Name, "word/printerSettings/") || strings.HasPrefix(f.Name, "xl/printerSettings/") ||
				strings.HasPrefix(f.Name, "ppt/printerSettings/") {
				continue
			}
			// A declared font, media, or ActiveX binary is not a text container.
			// Its raw bytes were appended above and stay on the request DLP view.
			if declaredNonTextBinary(contentType) {
				continue
			}
			binary = append(binary, f.Name)
			continue
		}
		if isXMLPart(f.Name, contentType) {
			text, xmlErr := xmlText(member, w.limits.MaxDepth, func(href string) { images[odfImagePath(f.Name, href)] = true })
			if xmlErr != nil {
				return xmlErr
			}
			w.result.Texts = append(w.result.Texts, text)
		}
	}
	for _, name := range binary {
		if !images[name] {
			return fmt.Errorf("non-text member has no reader")
		}
	}
	return nil
}

// odfImagePath resolves a draw:image xlink:href against the directory of the
// XML part that names it; embedded sub-documents use their own directory.
func odfImagePath(part, href string) string {
	if decoded, err := url.PathUnescape(href); err == nil {
		href = decoded
	}
	return strings.TrimPrefix(path.Join(path.Dir(part), href), "/")
}

// directoryPayload reads the compressed bytes Open skips for a zero-length
// directory. Inflation stops at the remaining byte budget. A deflate stream
// must consume the listed compressed size, same as a file member.
func (w *walk) directoryPayload(f *zip.File) ([]byte, error) {
	raw, err := f.OpenRaw()
	if err != nil {
		return nil, fmt.Errorf("opening member: %w", err)
	}
	var reader io.Reader
	var compressed *bufio.Reader
	switch f.Method {
	case zip.Store:
		reader = raw
	case zip.Deflate:
		compressed = bufio.NewReader(raw)
		reader = flate.NewReader(compressed)
	default:
		return nil, fmt.Errorf("unsupported ZIP compression method %d", f.Method)
	}
	if w.remaining < 0 {
		return nil, fmt.Errorf("expanded member exceeds max_body_bytes / compression-ratio budget")
	}
	payload, err := io.ReadAll(io.LimitReader(&contextReader{w.ctx, reader}, int64(w.remaining)+1))
	if closer, ok := reader.(io.Closer); ok {
		closeErr := closer.Close()
		if err == nil {
			err = closeErr
		}
	}
	if err != nil {
		return nil, fmt.Errorf("reading member: %w", err)
	}
	if len(payload) > w.remaining {
		kept := payload[:w.remaining]
		w.result.Texts = append(w.result.Texts, string(kept))
		w.remaining = 0
		return nil, fmt.Errorf("expanded member exceeds max_body_bytes / compression-ratio budget")
	}
	w.remaining -= len(payload)
	if compressed != nil {
		if _, err = compressed.ReadByte(); !errors.Is(err, io.EOF) {
			if len(payload) > 0 {
				w.result.Texts = append(w.result.Texts, string(payload))
			}
			return nil, fmt.Errorf("compressed member has data after its deflate stream")
		}
	}
	return payload, nil
}

// deflateConsumesMember re-reads the member's compressed bytes. archive/zip
// stops at the end of the deflate stream, so bytes after it inside the listed
// compressed size are never read; a streaming reader can treat them as another
// record. The decompressor reads a bufio.Reader one byte at a time, so anything
// still readable afterwards follows the stream. The first read already bounded
// the output to the charged size.
func (w *walk) deflateConsumesMember(f *zip.File) error {
	raw, err := f.OpenRaw()
	if err != nil {
		return fmt.Errorf("opening member: %w", err)
	}
	compressed := bufio.NewReader(raw)
	inflater := flate.NewReader(compressed)
	_, err = io.Copy(io.Discard, &contextReader{w.ctx, inflater})
	closeErr := inflater.Close()
	if err != nil {
		return fmt.Errorf("reading member: %w", err)
	}
	if closeErr != nil {
		return fmt.Errorf("closing member: %w", closeErr)
	}
	if _, err = compressed.ReadByte(); !errors.Is(err, io.EOF) {
		return fmt.Errorf("compressed member has data after its deflate stream")
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
//
// OASIS ODF 1.3 Part 3 gives draw:frame alternative representations of one
// object; its draw:image is the replacement image for an embedded draw:object.
// The member an image href names is reported to onImage. Its raw bytes still
// reach request DLP; only the non-text refusal is lifted for that member.
func xmlText(data []byte, maxDepth int, onImage func(string)) (string, error) {
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
			if t.Name.Space == odfDrawingNamespace && t.Name.Local == "image" {
				for _, a := range t.Attr {
					if a.Name.Space == xlinkNamespace && a.Name.Local == "href" && !strings.Contains(a.Value, ":") {
						onImage(a.Value)
					}
				}
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
