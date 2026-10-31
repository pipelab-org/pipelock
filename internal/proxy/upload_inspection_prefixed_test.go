// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"archive/zip"
	"bytes"
	"errors"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

// prefixedCredentialArchive is a stub followed by a ZIP whose deflated member
// carries a credential. archive/zip opens it, as Info-ZIP unzip, Python
// zipfile and libarchive do.
func prefixedCredentialArchive(t *testing.T, comment string) []byte {
	t.Helper()
	var buf bytes.Buffer
	buf.WriteString("#!/bin/sh\nexit 0\n")
	z := zip.NewWriter(&buf)
	z.SetOffset(int64(buf.Len()))
	member, err := z.Create("word/document.xml")
	if err != nil {
		t.Fatal(err)
	}
	// Repeated text makes deflate emit coded data rather than a stored block,
	// so the credential is not visible in the raw bytes.
	if _, err = io.WriteString(member, "<p>"+"sk_live_"+"abcdefghijklmnopqrstuvwx"+"</p>"+strings.Repeat("<p>ordinary text</p>", 64)); err != nil {
		t.Fatal(err)
	}
	if err = z.SetComment(comment); err != nil {
		t.Fatal(err)
	}
	if err = z.Close(); err != nil {
		t.Fatal(err)
	}
	data := buf.Bytes()
	if bytes.Contains(data, []byte("sk_live_")) {
		t.Fatal("credential must not be visible in the raw archive bytes")
	}
	if _, err = zip.NewReader(bytes.NewReader(data), int64(len(data))); err != nil {
		t.Fatalf("archive reader must open the prefixed archive: %v", err)
	}
	return data
}

func TestUploadInspectionPrefixedArchive(t *testing.T) {
	raw := prefixedCredentialArchive(t, "")
	preamble := prefixedCredentialArchive(t, "\r\n--B--\r\n")
	if _, err := multipart.NewReader(bytes.NewReader(preamble), "B").NextPart(); !errors.Is(err, io.EOF) {
		t.Fatalf("receiver must see a form with no parts, got err=%v", err)
	}
	partType, part := uploadMultipart(t, raw)
	for _, surface := range []string{"forward", "intercept", "reverse"} {
		for _, tc := range []struct {
			name        string
			contentType string
			body        []byte
		}{
			{"raw", "application/octet-stream", raw},
			{"multipart part", partType, part},
			{"multipart preamble", "multipart/form-data; boundary=B", preamble},
		} {
			for _, policy := range []uploadPolicy{{config.ActionBlock, false}, {config.ActionWarn, false}} {
				t.Run(fmt.Sprintf("%s/%s/%s", surface, tc.name, policy.action), func(t *testing.T) {
					status, hits, intact, message, _ := exerciseUpload(t, surface, policy, tc.contentType, tc.body)
					if policy.action == config.ActionBlock {
						if status != http.StatusForbidden || hits != 0 {
							t.Fatalf("hold: status=%d hits=%d body=%s", status, hits, message)
						}
						return
					}
					if status != http.StatusCreated || hits != 1 || !intact {
						t.Fatalf("warn delivery: status=%d hits=%d intact=%t body=%s", status, hits, intact, message)
					}
				})
			}
		}
	}
}
