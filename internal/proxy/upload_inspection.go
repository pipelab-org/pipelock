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
// multipart reader ignores (RFC 2046 section 5.1.1). Go's reader ends the form
// at the first line after the preamble that starts with "--" boundary "--";
// a request that parsed has one. Taking the first such line, whether or not
// the reader treated it as final, can only start the epilogue earlier, so it
// checks more bytes, never fewer.
func multipartEpilogue(body []byte, boundary string, preamble int) []byte {
	final := []byte("--" + boundary + "--")
	rest := body[preamble:]
	start := 0
	if !bytes.HasPrefix(rest, final) {
		i := bytes.Index(rest, append([]byte("\n"), final...))
		if i < 0 {
			return nil
		}
		start = i + 1
	}
	line := rest[start:]
	if i := bytes.IndexByte(line, '\n'); i >= 0 {
		return line[i+1:]
	}
	return nil
}
