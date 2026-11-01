// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"bytes"
	"context"
	"fmt"
	"mime"
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
	mediaType, params, _ := mime.ParseMediaType(req.ContentType)
	switch {
	case mediaType == "multipart/form-data":
		// A multipart reader skips the preamble and the epilogue, but an
		// archive reader given the raw body reads an archive placed in either,
		// so that archive is the whole body. An epilogue archive is also read
		// on its own, as an archive reader corrects for the bytes before it.
		// An archive inside a part is that part, below; the body of an
		// ordinary form whose last part is a document is not read as a
		// damaged archive.
		preamble := multipartPreamble(body, params["boundary"])
		epilogue := multipartEpilogue(body, params["boundary"], len(preamble))
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

// multipartEpilogue returns the bytes after the final delimiter line, which a
// multipart reader ignores (RFC 2046 section 5.1.1). It follows Go's
// mime/multipart reader, which the request parser uses: the first delimiter
// line fixes the line ending (CRLF, or LF when that line ends in a bare LF), a
// part ends only at that line ending followed by "--" and the boundary, and the
// form ends at the first such line that is "--" boundary "--", optional spaces
// or tabs, then that line ending or the end of the body. A bare LF before
// "--" boundary "--" inside a CRLF form is part content, not the epilogue, so
// starting there would scan part bytes twice and invent an epilogue.
func multipartEpilogue(body []byte, boundary string, preamble int) []byte {
	dash := []byte("--" + boundary)
	final := append(append([]byte(nil), dash...), "--"...)
	rest := body[preamble:]
	lineAt := func(off int) []byte {
		line := rest[off:]
		if i := bytes.IndexByte(line, '\n'); i >= 0 {
			line = line[:i+1]
		}
		return line
	}
	first := lineAt(0)
	nl := []byte("\r\n")
	if !bytes.HasSuffix(first, nl) {
		nl = nl[1:]
	}
	isFinal := func(line []byte) bool {
		tail, ok := bytes.CutPrefix(line, final)
		if !ok {
			return false
		}
		tail = bytes.TrimLeft(tail, " \t")
		return len(tail) == 0 || bytes.Equal(tail, nl)
	}
	if isFinal(first) {
		return rest[len(first):]
	}
	sep := append(append([]byte(nil), nl...), dash...)
	for off := 0; ; {
		i := bytes.Index(rest[off:], sep)
		if i < 0 {
			return nil
		}
		off += i + len(nl)
		line := lineAt(off)
		if isFinal(line) {
			if !bytes.HasSuffix(line, []byte("\n")) {
				return nil
			}
			return rest[off+len(line):]
		}
	}
}
