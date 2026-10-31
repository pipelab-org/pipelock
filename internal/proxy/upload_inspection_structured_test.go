// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"archive/zip"
	"bytes"
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/fileinspect"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

// A receiver parses a structured body as its declared type, so archive bytes
// don't replace that parse. A JSON body that doesn't decode keeps the
// fail-closed parse error, and a form that does decode keeps its decoded
// fields beside the raw archive view.
func TestUploadInspectionStructuredArchiveBody(t *testing.T) {
	cfg := config.Defaults()
	cfg.Internal = nil
	sc := scanner.MustNew(cfg)
	defer sc.Close()
	clean := uploadArchive(t, map[string][]byte{"note.txt": []byte("ordinary text")})
	if fileinspect.Kind(clean) != "ZIP" {
		t.Fatal("fixture is not recognized as ZIP")
	}
	for _, auditMode := range []bool{false, true} {
		for _, action := range []string{config.ActionBlock, config.ActionWarn} {
			for _, contentType := range []string{contentTypeJSON, "application/vnd.api+json"} {
				body, result := scanRequestBody(context.Background(), BodyScanRequest{Body: bytes.NewReader(clean), Scanner: sc, MaxBytes: 1 << 20, ContentType: contentType, Action: action, AuditMode: auditMode})
				if result.Clean || !strings.Contains(result.Reason, "JSON") || !isFailClosedBodyResult(result, body) {
					t.Fatalf("%s action=%s audit=%t: result=%+v", contentType, action, auditMode, result)
				}
			}
		}
	}

	// Stored member text is the form the receiver decodes. The raw bytes and
	// the member text hold the credential only in percent-encoded form. The
	// padding varies the CRC until no header byte is a form separator or
	// escape.
	var polyglot []byte
	for pad := 0; pad < 4096 && polyglot == nil; pad++ {
		var buf bytes.Buffer
		z := zip.NewWriter(&buf)
		member, err := z.CreateHeader(&zip.FileHeader{Name: "f", Method: zip.Store})
		if err != nil {
			t.Fatal(err)
		}
		if _, err = fmt.Fprintf(member, "&k=AKIA%%51%%39W8E7R6T5Y4U3I2&pad=%d&", pad); err != nil {
			t.Fatal(err)
		}
		if err = z.Close(); err != nil {
			t.Fatal(err)
		}
		candidate := buf.Bytes()
		if _, errText := extractFormURLEncoded(candidate); errText == "" && bytes.Count(candidate, []byte("%")) == 2 {
			polyglot = candidate
		}
	}
	if polyglot == nil {
		t.Fatal("no form-valid archive fixture")
	}
	if bytes.Contains(polyglot, []byte("AKIA"+"Q9W8")) {
		t.Fatal("credential must appear only percent-encoded")
	}
	_, result := scanRequestBody(context.Background(), BodyScanRequest{Body: bytes.NewReader(polyglot), Scanner: sc, MaxBytes: 1 << 20, ContentType: "application/x-www-form-urlencoded", Action: config.ActionWarn, AuditMode: true})
	if result.Clean || !containsCoreFloorMatch(result.DLPMatches) {
		t.Fatalf("decoded form field in an archive body: %+v", result)
	}
	broken := append(bytes.Clone(clean[:len(clean)-1]), ';')
	body, result := scanRequestBody(context.Background(), BodyScanRequest{Body: bytes.NewReader(broken), Scanner: sc, MaxBytes: 1 << 20, ContentType: "application/x-www-form-urlencoded", Action: config.ActionWarn})
	if result.Clean || result.Reason != invalidFormURLEncodedBody || !isFailClosedBodyResult(result, body) {
		t.Fatalf("malformed form archive body: %+v", result)
	}
}
