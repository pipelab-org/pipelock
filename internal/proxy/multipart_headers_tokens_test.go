// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"bytes"
	"mime"
	"slices"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

func TestMultipartHeaderWireTokenEntropy(t *testing.T) {
	sc := scanner.MustNew(testScannerConfig())
	defer sc.Close()
	opaque := strings.Join([]string{"aAbBcCdDeEfFgGhHiIjJ", "kKlLmMnNoOpPqQrRsStT"}, "")
	for _, header := range []string{
		"Content-Type: " + opaque + "/x\r\n",
		"Content-Disposition: " + opaque + "\r\n",
		"Content-Disposition: form-data; " + opaque + "=x\r\n",
	} {
		t.Run(header, func(t *testing.T) {
			req := BodyScanRequest{ContentType: multipartHeaderType, MaxBytes: 4096, Scanner: sc, Action: config.ActionBlock}
			applyContentEntropyConfig(&req, config.Defaults())
			req.ContentEntropyAction = config.ActionBlock
			if scanBodyTextsForContentEntropy([]string{opaque}, req) == nil {
				t.Fatal("wire-token positive control must exceed the configured threshold")
			}
			req.Body = bytes.NewReader([]byte("--B\r\n" + header + "\r\n\r\n--B--\r\n"))
			_, got := scanRequestBody(t.Context(), req)
			if got.Clean || got.EntropyFinding == nil || got.Action != config.ActionBlock {
				t.Fatalf("wire token skipped content entropy: %+v", got)
			}
		})
	}
}

func TestMultipartHeaderValueTokens(t *testing.T) {
	for _, tc := range []struct {
		value string
		want  []string
	}{
		{"Text/Plain", []string{"Text/Plain"}},
		{"form-data; NaMe=f; FiLeNaMe=hello.txt;", []string{"form-data", "NaMe", "FiLeNaMe"}},
		{`form-data; name="a;fake=value"; X-Test=1`, []string{"form-data", "name", "X-Test"}},
		{`form-data; name="a\";fake=value"; X-Test=1`, []string{"form-data", "name", "X-Test"}},
		{`form-data; name="a\\"; X-Test=1`, []string{"form-data", "name", "X-Test"}},
		{"form-data; NaMe*0*=UTF-8''hello; NaMe*1*=world", []string{"form-data", "NaMe*0*", "NaMe*1*"}},
	} {
		t.Run(tc.value, func(t *testing.T) {
			if _, _, err := mime.ParseMediaType(tc.value); err != nil {
				t.Fatalf("fixture must satisfy the production parser: %v", err)
			}
			if got := multipartHeaderValueTokens(tc.value); !slices.Equal(got, tc.want) {
				t.Fatalf("tokens=%q want=%q", got, tc.want)
			}
		})
	}
}
