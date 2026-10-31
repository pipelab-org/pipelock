// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"bytes"
	"encoding/base64"
	"os"
	"path/filepath"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

// WebSocket messages consume the same body scanner. This checks that boundary
// directly; the HTTP tests separately prove actual upstream delivery/withhold.
func TestUploadInspectionWebSocketBodyParity(t *testing.T) {
	for _, tc := range []struct {
		name, file, action string
		audit, clean, held bool
	}{
		{"clean", "clean.odt", config.ActionBlock, false, true, false},
		{"credential", "libreoffice-seeded.docx", config.ActionBlock, false, false, true},
		{"RAR block", "", config.ActionBlock, false, false, true},
		{"RAR warn", "", config.ActionWarn, false, false, false},
		{"RAR audit", "", config.ActionBlock, true, false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := config.Defaults()
			cfg.Internal = nil
			cfg.RequestBodyScanning.Action = tc.action
			cfg.RequestBodyScanning.ContentEntropyEnabled = false
			enforce := !tc.audit
			cfg.Enforce = &enforce
			sc := scanner.MustNew(cfg)
			defer sc.Close()
			data := []byte("Rar!\x1a\x07\x01\x00")
			if tc.file != "" {
				var err error
				data, err = os.ReadFile(filepath.Clean(filepath.Join("..", "fileinspect", "testdata", tc.file)))
				if err != nil {
					t.Fatal(err)
				}
			}
			msg := []byte(`{"contentBytes":"` + base64.StdEncoding.EncodeToString(data) + `"}`)
			relay := &wsRelay{cfg: cfg, maxMsg: cfg.RequestBodyScanning.MaxBodyBytes, scanner: sc, hostname: "upload.vendor.example", path: "/socket", targetURL: "wss://upload.vendor.example/socket"}
			original, result := relay.scanClientMessageBody(t.Context(), msg)
			held := isFailClosedBodyResult(result, original) || shouldHardBlockBodyCriticalDLP(result, relay.hostname, cfg) || (result.Action == config.ActionBlock && cfg.EnforceEnabled())
			if result.Clean != tc.clean || held != tc.held || !bytes.Equal(original, msg) {
				t.Fatalf("clean=%t held=%t reason=%s", result.Clean, held, result.Reason)
			}
		})
	}
}
