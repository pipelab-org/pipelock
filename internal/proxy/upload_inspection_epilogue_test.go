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

// A multipart reader ignores the bytes after the final delimiter (RFC 2046
// section 5.1.1), but an archive reader given the raw body extracts an archive
// placed there, correcting for the form before it.
func TestUploadInspectionEpilogueArchive(t *testing.T) {
	var archive bytes.Buffer
	z := zip.NewWriter(&archive)
	member, err := z.Create("word/document.xml")
	if err != nil {
		t.Fatal(err)
	}
	// Repeated text makes deflate emit coded data rather than a stored block,
	// so the credential is not visible in the raw bytes.
	if _, err = io.WriteString(member, "<p>"+"AKIA"+"Q9W8E7R6T5Y4U3I2"+"</p>"+strings.Repeat("<p>ordinary text</p>", 64)); err != nil {
		t.Fatal(err)
	}
	if err = z.Close(); err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(archive.Bytes(), []byte("AKIA"+"Q9W8")) {
		t.Fatal("credential must not be visible in the raw archive bytes")
	}
	form := "--B\r\nContent-Disposition: form-data; name=\"note\"\r\n\r\nordinary\r\n--B--\r\n"
	credential := append([]byte(form), archive.Bytes()...)
	unreadable := append([]byte(form), "Rar!\x1a\x07\x01\x00"...)
	// The epilogue archive alone reads completely, but the body is a ZIP behind
	// prepended data, which is not fully read.
	clean := append([]byte(form), uploadArchive(t, map[string][]byte{"note.txt": []byte("ordinary text")})...)
	for _, body := range [][]byte{credential, unreadable} {
		reader := multipart.NewReader(bytes.NewReader(body), "B")
		if _, err := reader.NextPart(); err != nil {
			t.Fatal(err)
		}
		if _, err := reader.NextPart(); !errors.Is(err, io.EOF) {
			t.Fatalf("receiver must see one part, got err=%v", err)
		}
	}
	if _, err := zip.NewReader(bytes.NewReader(credential), int64(len(credential))); err != nil {
		t.Fatalf("archive reader must open the epilogue archive: %v", err)
	}
	for _, surface := range []string{"forward", "intercept", "reverse"} {
		for _, tc := range []struct {
			name    string
			body    []byte
			policy  uploadPolicy
			deliver bool
		}{
			{"credential enforce", credential, uploadPolicy{config.ActionBlock, false}, false},
			// The core credential floor applies in audit mode only if the
			// epilogue archive's member text reaches request DLP.
			{"credential audit", credential, uploadPolicy{config.ActionWarn, true}, false},
			{"unreadable enforce", unreadable, uploadPolicy{config.ActionBlock, false}, false},
			{"unreadable warn", unreadable, uploadPolicy{config.ActionWarn, false}, true},
			{"clean enforce", clean, uploadPolicy{config.ActionBlock, false}, false},
			{"clean warn", clean, uploadPolicy{config.ActionWarn, false}, true},
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
