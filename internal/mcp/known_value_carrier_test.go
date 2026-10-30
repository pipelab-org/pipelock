// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"encoding/base64"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

func TestScanRequestKnownValueCarrierContent(t *testing.T) {
	value := strings.Join([]string{"fixture", "Q7m2", "X9z4", "R8v3", "N6p1"}, "-")
	path := filepath.Join(t.TempDir(), "values")
	if err := os.WriteFile(path, []byte(value+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := config.Defaults()
	cfg.Internal = nil
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
			line := makeRequest(1, "tools/call", map[string]any{"name": "echo", "arguments": map[string]string{"note": carrier}})
			result := ScanRequest(t.Context(), []byte(line), sc, config.ActionBlock, config.ActionBlock)
			if result.Clean != tc.clean || result.Error != "" || (!tc.clean && len(result.Matches) == 0) {
				t.Fatalf("clean=%t want=%t matches=%d error=%q", result.Clean, tc.clean, len(result.Matches), result.Error)
			}
		})
	}
}
