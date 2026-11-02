// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

func TestWorkspaceCredentialExactRouteSuppression(t *testing.T) {
	for _, tc := range []struct{ name, pattern, key, header, host, other, path string }{
		{"Databricks", "Databricks Token", "dapi" + strings.Repeat("a", 32), "Authorization", "workspace-a.cloud.databricks.com", "workspace-b.cloud.databricks.com", "/api/2.0/clusters/list"},
		{"Pinecone", "Pinecone API Key", "pcsk_" + strings.Repeat("a", 36), "Api-Key", "index-a.svc.us-east1-gcp.pinecone.io", "index-b.svc.us-east1-gcp.pinecone.io", "/query"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			target := "https://" + tc.host + tc.path
			cfg, err := config.LoadBytes([]byte(fmt.Sprintf("version: 1\nmode: balanced\nsuppress:\n  - rule: %s\n    path: %s\n    reason: operator-approved API endpoint\n", tc.pattern, target)))
			if err != nil {
				t.Fatal(err)
			}
			cfg.Internal = nil
			cfg.RequestBodyScanning.Action = config.ActionBlock
			if err := cfg.Validate(); err != nil {
				t.Fatal(err)
			}
			sc := scanner.MustNew(cfg)
			defer sc.Close()
			headerValue := tc.key
			if tc.header == "Authorization" {
				headerValue = "Bearer " + tc.key
			}
			headers := http.Header{}
			headers.Set(tc.header, headerValue)
			for _, destination := range []struct {
				target string
				allow  bool
			}{
				{target, true}, {"https://" + tc.other + tc.path, false}, {"https://" + tc.host + tc.path + "/other", false},
			} {
				result := scanRequestHeadersForTarget(context.Background(), headers, cfg, sc, destination.target)
				clean := result == nil || result.Clean
				if clean != destination.allow {
					t.Fatalf("header at %s: clean=%v want %v", destination.target, clean, destination.allow)
				}
				_, body := scanRequestBody(context.Background(), BodyScanRequest{
					Body: strings.NewReader(tc.key), ContentType: "text/plain", MaxBytes: cfg.RequestBodyScanning.MaxBodyBytes,
					Scanner: sc, Target: destination.target, AudienceSurface: "body", Action: config.ActionBlock, Suppress: cfg.Suppress,
				})
				if body.Clean != destination.allow {
					t.Fatalf("body at %s: clean=%v want %v", destination.target, body.Clean, destination.allow)
				}
				// A body/header suppression is never a URL-DLP exception.
				if got := sc.Scan(context.Background(), destination.target+"?value="+tc.key); got.Allowed {
					t.Fatal("header/body suppression allowed a URL credential")
				}
			}
			noSuppression := cfg.Clone()
			noSuppression.Suppress = nil
			baseline := scanRequestHeadersForTarget(context.Background(), headers, noSuppression, sc, target)
			if baseline == nil || baseline.Clean {
				t.Fatal("control: workspace header allowed without explicit policy")
			}
		})
	}
}

func TestWIFBodyAndWebSocketAdmission(t *testing.T) {
	cfg := config.Defaults()
	cfg.Internal = nil
	cfg.RequestBodyScanning.Action = config.ActionBlock
	sc := scanner.MustNew(cfg)
	defer sc.Close()
	key := "KwdMAjGmer" + "Yanjeui5SHS7Jkmp" + "ZvVipYvB2LJGU1ZxJwYvP98617"
	for _, prefix := range []string{"K", "L", "5"} {
		value := prefix + key
		_, body := scanRequestBody(context.Background(), BodyScanRequest{Body: strings.NewReader(value), ContentType: "text/plain", MaxBytes: cfg.RequestBodyScanning.MaxBodyBytes, Scanner: sc, Target: "https://api.vendor.example/submit", Action: config.ActionBlock})
		if body.Clean || body.Action != config.ActionBlock {
			t.Fatalf("body not blocked after %s prefix", prefix)
		}
		relay := newCredentialAudienceWebSocketRelay(sc, cfg, "wss://api.vendor.example/socket")
		_, frame := relay.scanClientMessageBody(context.Background(), []byte(value))
		if frame.Clean {
			t.Fatalf("WebSocket frame not blocked after %s prefix", prefix)
		}
	}
}
