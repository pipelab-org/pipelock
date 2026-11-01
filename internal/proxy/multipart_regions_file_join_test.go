// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"bytes"
	"mime/multipart"
	"net/http"
	"net/textproto"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

// The existing part reading joins form fields with the text recovered from
// uploaded files. A preamble or epilogue that sorts between two halves of a
// credential in that join must not break it.
func TestMultipartRegionsKeepFileTextJoin(t *testing.T) {
	first, second := "AKIA", "B9W8E7R6T5Y4U3I2"
	var form bytes.Buffer
	w := multipart.NewWriter(&form)
	if err := w.SetBoundary("B"); err != nil {
		t.Fatal(err)
	}
	for _, part := range []struct {
		disposition string
		content     []byte
	}{
		{`form-data; name="z"`, []byte(first)},
		{`form-data; name="file"; filename="upload.bin"`, uploadArchive(t, map[string][]byte{"a.txt": []byte(second)})},
	} {
		h := textproto.MIMEHeader{}
		h.Set("Content-Disposition", part.disposition)
		p, err := w.CreatePart(h)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := p.Write(part.content); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	// "AKIZ!" sorts between the halves and cannot complete either one.
	interposer := "AKIZ!"
	cases := []struct {
		name string
		body []byte
	}{
		{"control", form.Bytes()},
		{"preamble", append([]byte(interposer+"\r\n"), form.Bytes()...)},
		{"epilogue", append(bytes.Clone(form.Bytes()), interposer...)},
		// In a form with no parts, the raw archive bytes ("PK...") sort
		// between halves recovered from that archive.
		{"archive epilogue", append([]byte("--B--\r\n"), uploadArchive(t, map[string][]byte{"a.txt": []byte(first), "b.txt": []byte("Q9W8E7R6T5Y4U3I2")})...)},
		// Two plain fields keep the same join without any file.
		{"fields preamble", []byte(interposer + "\r\n--B\r\nX: " + first + "\r\n\r\n" + second + "\r\n--B--\r\n")},
	}
	sc := scanner.MustNew(testScannerConfig())
	defer sc.Close()
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, got := scanRequestBody(t.Context(), BodyScanRequest{Body: bytes.NewReader(tc.body), ContentType: multipartHeaderType, MaxBytes: 1 << 20, Scanner: sc, Action: config.ActionBlock})
			if len(got.DLPMatches) == 0 {
				t.Fatalf("credential split between a field and file text missed: %+v", got)
			}
		})
	}
	for _, surface := range []string{"forward", "intercept", "reverse"} {
		t.Run(surface, func(t *testing.T) {
			h := newUploadHarness(t, surface, uploadPolicy{config.ActionWarn, true})
			for _, tc := range cases[1:] {
				status, hits, _, message, headers := h.exercise(t, http.Header{"Content-Type": {multipartHeaderType}}, tc.body)
				if status != http.StatusForbidden || hits != 0 || headers.Get("X-Pipelock-Block-Reason") != "dlp_match" {
					t.Fatalf("%s: status=%d hits=%d body=%s", tc.name, status, hits, message)
				}
			}
		})
	}
}
