// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

func TestInputURLUserinfoAndWIFAdmission(t *testing.T) {
	cfg := config.Defaults()
	cfg.Internal = nil
	sc := scanner.MustNew(cfg)
	defer sc.Close()
	key := "gh" + "p_" + strings.Repeat("aB3c", 9)
	wif := "K" + "KwdMAjGmer" + "Yanjeui5SHS7Jkmp" + "ZvVipYvB2LJGU1ZxJwYvP98617"
	for _, method := range []string{"tools/call", "resources/read"} {
		for _, tc := range []struct {
			name, value string
			block       bool
		}{
			{"userinfo", "https://" + hex.EncodeToString([]byte(key)) + "@api.vendor.example/read", true},
			{"wif", "https://api.vendor.example/" + wif, true},
			{"benign", "https://api.vendor.example/read", false},
		} {
			t.Run(method+"/"+tc.name, func(t *testing.T) {
				var params any = map[string]any{"name": "fetch", "arguments": map[string]string{"url": tc.value}}
				if method == "resources/read" {
					params = map[string]string{"uri": tc.value}
				}
				line, err := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 1, "method": method, "params": params})
				if err != nil {
					t.Fatal(err)
				}
				verdict := ScanRequest(context.Background(), line, sc, config.ActionBlock, config.ActionBlock)
				if verdict.Clean == tc.block {
					t.Fatalf("verdict clean=%v want block=%v: %+v", verdict.Clean, tc.block, verdict)
				}
				var forwarded, log bytes.Buffer
				blocked := make(chan BlockedRequest, 1)
				fwdScannedInput(strings.NewReader(string(line)+"\n"), &forwarded, &log, sc, config.ActionBlock, config.ActionBlock, blocked)
				if (forwarded.Len() == 0) != tc.block {
					t.Fatalf("stdio forwarded=%d want block=%v", forwarded.Len(), tc.block)
				}
				var upstreamHits atomic.Int32
				upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					_, _ = io.Copy(io.Discard, r.Body)
					upstreamHits.Add(1)
					w.Header().Set("Content-Type", "application/json")
					_, _ = io.WriteString(w, `{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"ordinary"}]}}`)
				}))
				defer upstream.Close()
				var output, errors bytes.Buffer
				err = RunHTTPProxy(context.Background(), strings.NewReader(string(line)+"\n"), &output, &errors, upstream.URL, nil, MCPProxyOpts{
					Scanner: sc, InputCfg: &InputScanConfig{Enabled: true, Action: config.ActionBlock, OnParseError: config.ActionBlock},
				})
				if err != nil {
					t.Fatal(err)
				}
				if (upstreamHits.Load() == 0) != tc.block {
					t.Fatalf("HTTP upstream hits=%d want block=%v", upstreamHits.Load(), tc.block)
				}
			})
		}
	}
}
