// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"mime"
	"mime/multipart"
	"strings"

	"github.com/luckyPipewrench/pipelock/internal/extract"
	"github.com/luckyPipewrench/pipelock/internal/fileinspect"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

// inspectUploadTextViews supplements request DLP only. The original body and
// generic injection/entropy views stay unchanged. Incomplete files retain their
// recovered views, so an early parser error can't conceal an existing finding.
func inspectUploadTextViews(ctx context.Context, body []byte, req BodyScanRequest, extracted bodyDLPTextExtraction) ([]string, string) {
	remaining := req.MaxBytes
	var views []string
	var incomplete string
	inspect := func(data []byte) {
		if fileinspect.Kind(data) == "" {
			return
		}
		r := fileinspect.Inspect(ctx, data, fileinspect.Limits{MaxBytes: remaining, MaxDepth: extract.MaxExtractDepth})
		views = append(views, r.Texts...)
		remaining -= r.ReadBytes
		if !r.Complete && incomplete == "" {
			incomplete = fmt.Sprintf("%s upload not fully read: %s; %s", r.Type, r.Reason, scanner.IncompleteFileGovernedSuffix)
		}
	}
	mediaType, _, _ := mime.ParseMediaType(req.ContentType)
	switch {
	case mediaType == "multipart/form-data":
		// A multipart reader skips the preamble and the epilogue, but an
		// archive reader given the raw body reads an archive placed in either,
		// so that archive is the whole body. An epilogue archive is also read
		// on its own, as an archive reader corrects for the bytes before it.
		// An archive inside a part is that part, below; the body of an
		// ordinary form whose last part is a document is not read as a
		// damaged archive.
		// Request extraction located both regions in these same bytes and
		// refused the body when it could not find the closing delimiter.
		preamble, epilogue := extracted.MultipartPreamble, extracted.MultipartEpilogue
		if fileinspect.Kind(preamble) != "" || fileinspect.Kind(epilogue) != "" {
			inspect(body)
		}
		if fileinspect.Kind(epilogue) != "" {
			inspect(epilogue)
		}
		// The existing multipart parser exposes raw and transfer-decoded parts.
		for _, part := range extracted.FileParts {
			inspect(part)
		}
	case fileinspect.Kind(body) != "":
		inspect(body)
	case mediaType == contentTypeJSON || strings.HasSuffix(mediaType, "+json"):
		for _, text := range extracted.GenericTexts {
			// These are the same bounded candidates used by text DLP today.
			// No attachment-name, MIME, or provider-specific carrier rule is added.
			for _, decoded := range scanner.DecodedTextDLPViews(text) {
				if fileinspect.Kind([]byte(decoded)) != "" {
					inspect([]byte(decoded))
					// A recognized binary format owns its bytes. Later text
					// decoder candidates can alter percent escapes or Unicode
					// inside compressed bytes; they aren't additional files.
					break
				}
			}
		}
	}
	return views, incomplete
}

// multipartPreamble returns the bytes before the first delimiter line, which
// a multipart reader skips (RFC 2046 section 5.1.1). It applies the line tests
// of Go's mime/multipart reader, which the request parser uses: "--" and the
// boundary, optional spaces or tabs, then CRLF or LF; or the final "--"
// boundary "--", optional spaces or tabs, then CRLF or the end of the body.
// Ending earlier than the reader would leave preamble bytes unchecked.
func multipartPreamble(body []byte, boundary string) []byte {
	dash := []byte("--" + boundary)
	for off := 0; off < len(body); {
		line := body[off:]
		if i := bytes.IndexByte(line, '\n'); i >= 0 {
			line = line[:i+1]
		}
		if rest, ok := bytes.CutPrefix(line, dash); ok {
			if final, ok := bytes.CutPrefix(rest, []byte("--")); ok {
				final = bytes.TrimLeft(final, " \t")
				if len(final) == 0 || string(final) == "\r\n" {
					return body[:off]
				}
			}
			rest = bytes.TrimLeft(rest, " \t")
			if string(rest) == "\r\n" || string(rest) == "\n" {
				return body[:off]
			}
		}
		off += len(line)
	}
	return body
}

// multipartEpilogue returns the bytes after the final delimiter of a complete
// form. The same reader that extracts parts decides where the form ends,
// including its accepted line endings and empty parts. Limiting each input
// read to one line keeps its buffer from reading ahead into the epilogue. It
// reports false when the form does not parse or the consumed input does not
// end with a final delimiter line; callers must then fail closed rather than
// treat the epilogue as empty.
func multipartEpilogue(body []byte, boundary string, preamble int) ([]byte, bool) {
	source := &multipartLineReader{body: body[preamble:]}
	reader := multipart.NewReader(source, boundary)
	for {
		part, err := reader.NextRawPart()
		if err == io.EOF {
			if !endsWithFinalDelimiter(source.body[:source.offset], boundary) {
				return nil, false
			}
			return source.body[source.offset:], true
		}
		if err != nil {
			return nil, false
		}
		if _, err := io.Copy(io.Discard, part); err != nil {
			return nil, false
		}
	}
}

// endsWithFinalDelimiter reports whether consumed ends with a final delimiter
// line: "--" boundary "--", optional spaces or tabs, then CRLF, LF or the end
// of the input (RFC 2046 section 5.1.1). It guards the line-capped reader
// assumption: a reader that buffered past that line would fail this check
// instead of hiding epilogue bytes.
func endsWithFinalDelimiter(consumed []byte, boundary string) bool {
	line := bytes.TrimSuffix(bytes.TrimSuffix(consumed, []byte("\n")), []byte("\r"))
	if i := bytes.LastIndexByte(line, '\n'); i >= 0 {
		line = line[i+1:]
	}
	line = bytes.TrimRight(line, " \t")
	return bytes.Equal(line, []byte("--"+boundary+"--"))
}

// multipartLineReader never returns bytes past the next LF. Go's multipart
// reader consumes the final delimiter line without needing the next line, so
// offset identifies the epilogue even though that reader buffers its input.
type multipartLineReader struct {
	body   []byte
	offset int
}

func (r *multipartLineReader) Read(p []byte) (int, error) {
	if r.offset == len(r.body) {
		return 0, io.EOF
	}
	n := min(len(p), len(r.body)-r.offset)
	if i := bytes.IndexByte(r.body[r.offset:r.offset+n], '\n'); i >= 0 {
		n = i + 1
	}
	copy(p, r.body[r.offset:r.offset+n])
	r.offset += n
	return n, nil
}
