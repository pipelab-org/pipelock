// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
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
	mediaType, _, _ := mime.ParseMediaType(req.ContentType)
	if fileinspect.Kind(body) != "" {
		inspect(body)
		// A multipart preamble may begin with a file signature; its parts are
		// still what the receiver reads, so they are inspected as well.
		if mediaType != "multipart/form-data" {
			return views, incomplete
		}
	}
	if mediaType == "multipart/form-data" {
		// The existing multipart parser exposes raw and transfer-decoded parts.
		for _, part := range extracted.FileParts {
			inspect(part)
		}
	} else if mediaType == contentTypeJSON || strings.HasSuffix(mediaType, "+json") {
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
