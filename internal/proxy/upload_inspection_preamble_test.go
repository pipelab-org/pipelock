// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"archive/zip"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

// preambleOnlyForms returns two bodies that a multipart reader sees as a form
// with no parts (RFC 2046 section 5.1.1 skips the preamble). In the first, the
// archive comment reaches EOF, so the same bytes are a complete ZIP whose
// deflated member carries a credential. The second is a RAR signature, which
// has no reader.
func preambleOnlyForms(t *testing.T) (credential, unreadable []byte) {
	t.Helper()
	const closing = "\r\n--B--\r\n"
	var buf bytes.Buffer
	z := zip.NewWriter(&buf)
	member, err := z.Create("word/document.xml")
	if err != nil {
		t.Fatal(err)
	}
	// Repeated text makes deflate emit coded data rather than a stored block,
	// so the credential is not visible in the raw bytes.
	if _, err = io.WriteString(member, "<p>"+"AKIA"+"Q9W8E7R6T5Y4U3I2"+"</p>"+strings.Repeat("<p>ordinary text</p>", 64)); err != nil {
		t.Fatal(err)
	}
	if err = z.SetComment(closing); err != nil {
		t.Fatal(err)
	}
	if err = z.Close(); err != nil {
		t.Fatal(err)
	}
	credential = buf.Bytes()
	if bytes.Contains(credential, []byte("AKIA"+"Q9W8")) {
		t.Fatal("credential must not be visible in the raw archive bytes")
	}
	unreadable = append([]byte("Rar!\x1a\x07\x01\x00"), closing...)
	for _, body := range [][]byte{credential, unreadable} {
		if _, err := multipart.NewReader(bytes.NewReader(body), "B").NextPart(); !errors.Is(err, io.EOF) {
			t.Fatalf("receiver must see a form with no parts, got err=%v", err)
		}
	}
	if _, err := zip.NewReader(bytes.NewReader(credential), int64(len(credential))); err != nil {
		t.Fatalf("archive reader must open the preamble archive: %v", err)
	}
	return credential, unreadable
}

func TestUploadInspectionPreambleOnlyResult(t *testing.T) {
	credential, unreadable := preambleOnlyForms(t)
	cfg := config.Defaults()
	cfg.Internal = nil
	sc := scanner.MustNew(cfg)
	defer sc.Close()
	const contentType = "multipart/form-data; boundary=B"

	_, result := scanRequestBody(context.Background(), BodyScanRequest{Body: bytes.NewReader(credential), Scanner: sc, MaxBytes: 1 << 20, ContentType: contentType, Action: config.ActionBlock})
	if result.Clean || len(result.DLPMatches) == 0 {
		t.Fatalf("credential in a preamble archive: %+v", result)
	}
	for _, auditMode := range []bool{false, true} {
		for _, action := range []string{config.ActionBlock, config.ActionWarn} {
			body, result := scanRequestBody(context.Background(), BodyScanRequest{Body: bytes.NewReader(unreadable), Scanner: sc, MaxBytes: 1 << 20, ContentType: contentType, Action: action, AuditMode: auditMode})
			want := action == config.ActionBlock && !auditMode
			if result.Clean || result.FileInspectionIncomplete == "" || isFailClosedBodyResult(result, body) != want || !bytes.Equal(body, unreadable) {
				t.Fatalf("action=%s audit=%t result=%+v", action, auditMode, result)
			}
		}
	}
}

func TestUploadInspectionPreambleOnlyTransports(t *testing.T) {
	credential, unreadable := preambleOnlyForms(t)
	for _, surface := range []string{"forward", "intercept", "reverse"} {
		for _, tc := range []struct {
			name    string
			body    []byte
			policy  uploadPolicy
			deliver bool
		}{
			{"credential enforce", credential, uploadPolicy{config.ActionBlock, false}, false},
			// The core credential floor applies in audit mode once the member
			// text reaches request DLP.
			{"credential audit", credential, uploadPolicy{config.ActionWarn, true}, false},
			{"unreadable enforce", unreadable, uploadPolicy{config.ActionBlock, false}, false},
			{"unreadable warn", unreadable, uploadPolicy{config.ActionWarn, false}, true},
		} {
			t.Run(fmt.Sprintf("%s/%s", surface, tc.name), func(t *testing.T) {
				status, hits, intact, message, _ := exerciseUpload(t, surface, tc.policy, "multipart/form-data; boundary=B", tc.body)
				if tc.deliver {
					if status != http.StatusCreated || hits != 1 || !intact {
						t.Fatalf("delivery: status=%d hits=%d intact=%t body=%s", status, hits, intact, message)
					}
					return
				}
				if status != http.StatusForbidden || hits != 0 {
					t.Fatalf("hold: status=%d hits=%d body=%s", status, hits, message)
				}
			})
		}
	}
}
