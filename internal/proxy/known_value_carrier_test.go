// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"encoding/base64"
	"encoding/hex"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

func TestRequestKnownValueCarrierContent(t *testing.T) {
	value := strings.Join([]string{"fixture", "Q7m2", "X9z4", "R8v3", "N6p1"}, "-")
	path := filepath.Join(t.TempDir(), "values")
	if err := os.WriteFile(path, []byte(value+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := testScannerConfig()
	cfg.DLP.ScanEnv = false
	cfg.DLP.SecretsFile = path
	cfg.DLP.IncludeDefaults = new(false)
	cfg.DLP.Patterns = nil
	sc := scanner.MustNew(cfg)
	t.Cleanup(sc.Close)
	for _, tc := range []struct {
		name, text string
		clean      bool
	}{
		{"configured", value, false},
		{"ordinary", "ordinary documentation", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			carrier := hex.EncodeToString([]byte(base64.StdEncoding.EncodeToString([]byte("label:"+tc.text)))) + "ZZ"
			header := scanRequestHeaders(t.Context(), http.Header{"Authorization": []string{carrier}}, cfg, sc)
			if clean := header == nil || header.Clean; clean != tc.clean {
				t.Errorf("header clean=%t want=%t", clean, tc.clean)
			}
			for _, body := range []struct{ contentType, text string }{
				{"application/json", `{"note":"` + carrier + `"}`},
				{"application/x-www-form-urlencoded", "note=" + url.QueryEscape(carrier)},
			} {
				_, result := scanRequestBody(t.Context(), BodyScanRequest{Body: strings.NewReader(body.text), ContentType: body.contentType, MaxBytes: cfg.RequestBodyScanning.MaxBodyBytes, Scanner: sc})
				if result.Clean != tc.clean || (!tc.clean && len(result.DLPMatches) == 0) {
					t.Errorf("%s clean=%t want=%t matches=%d", body.contentType, result.Clean, tc.clean, len(result.DLPMatches))
				}
			}
		})
	}
}
