// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

// Package fileinspect recovers bounded text views from ZIP and Office packages.
// It makes no traffic-direction or enforcement decision and never rewrites input.
package fileinspect

import (
	"bytes"
	"context"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"strings"
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

// Archive signatures. PKWARE APPNOTE 4.3.7 (local file header) and 4.3.16
// (end of central directory record); 7-Zip's 7zFormat.txt,
// SignatureHeader.Signature[6] (https://www.7-zip.org/sdk.html); RAR 4.x and
// 5.0 archive signatures (https://www.rarlab.com/technote.htm#rarsign).
var (
	zipLocalSignature = []byte("PK\x03\x04")
	zipEndSignature   = []byte("PK\x05\x06")
	sevenZipSignature = []byte{'7', 'z', 0xbc, 0xaf, 0x27, 0x1c}
	rar4Signature     = []byte("Rar!\x1a\x07\x00")
	rar5Signature     = []byte("Rar!\x1a\x07\x01\x00")
)

// Kind uses format signatures, independently of filenames and MIME labels.
func Kind(data []byte) string {
	switch {
	case bytes.HasPrefix(data, zipLocalSignature), bytes.HasPrefix(data, zipEndSignature):
		return "ZIP"
	case bytes.HasPrefix(data, sevenZipSignature):
		return "7z"
	case bytes.HasPrefix(data, rar4Signature), bytes.HasPrefix(data, rar5Signature):
		return "RAR"
	// APPNOTE 4.1.9 allows data before the archive (a self-extractor stub).
	// Readers find it from the end record, which starts within the final
	// 65535+22 bytes because its comment length is a 2-byte field (4.3.16).
	// Info-ZIP unzip also extracts a prefixed archive whose end record is
	// further from EOF, so a local header signature anywhere is a ZIP too.
	// The canonical layout check then leaves either form not fully read.
	case bytes.Contains(data[max(0, len(data)-endHeaderBytes-65535):], zipEndSignature), bytes.Contains(data, zipLocalSignature):
		return "ZIP"
	// A self-extracting module may also precede a RAR archive (the RAR
	// technote's SFX block) or a 7z archive; 7-Zip and libarchive extract a
	// 7-Zip SFX executable. These formats have no reader either way.
	case bytes.Contains(data, sevenZipSignature):
		return "7z"
	case bytes.Contains(data, rar4Signature), bytes.Contains(data, rar5Signature):
		return "RAR"
	default:
		return ""
	}
}

// embeddedArchive reports an archive signature anywhere in data. A published
// signature at offset zero accepts a binary member, but says nothing about
// the bytes after it, and an archive appended to an image remains readable.
func embeddedArchive(data []byte) bool {
	for _, sig := range [][]byte{zipLocalSignature, zipEndSignature, sevenZipSignature, rar4Signature, rar5Signature} {
		if bytes.Contains(data, sig) {
			return true
		}
	}
	return false
}

type walk struct {
	ctx       context.Context
	limits    Limits
	remaining int
	entries   int
	result    *Result
	parsed    *zipArchive
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
// the directory is parsed prevents attacker-controlled counts from allocating
// an index beyond the caller's metadata byte budget. No independent member cap is guessed.
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

// XML character data joins formatting runs within paragraphs/cells. Paragraph,
// row and cell boundaries remain separators (ECMA-376 w:p/a:p and ODF text:p).
// All XML parts are scanned, including relationships, hidden sheets, notes,
// comments and metadata; no relationship is fetched and no macro is executed.
//
// OASIS ODF 1.3 Part 3 gives draw:frame alternative representations of one
// object. onImage reports a draw:image href and does not accept that member:
// a non-text member is read only when its bytes match a published signature.
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
			if onImage != nil && t.Name.Space == odfDrawingNamespace && t.Name.Local == "image" {
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
