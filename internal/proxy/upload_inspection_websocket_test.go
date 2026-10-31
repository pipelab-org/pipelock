// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"bytes"
	"encoding/base64"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gobwas/ws"

	"github.com/luckyPipewrench/pipelock/internal/audit"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/metrics"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

func TestUploadInspectionWebSocketFileHoldClose(t *testing.T) {
	cfg := config.Defaults()
	cfg.Internal = nil
	enforce := true
	cfg.Enforce = &enforce
	cfg.RequestBodyScanning.Action = config.ActionBlock
	cfg.AdaptiveEnforcement.Enabled = false
	client, clientPeer := net.Pipe()
	upstream, upstreamPeer := net.Pipe()
	t.Cleanup(func() {
		_ = client.Close()
		_ = clientPeer.Close()
		_ = upstream.Close()
		_ = upstreamPeer.Close()
	})
	go func() { _, _ = io.Copy(io.Discard, upstreamPeer) }()
	relay := &wsRelay{
		clientConn:   client,
		upstreamConn: upstream,
		proxy:        &Proxy{logger: audit.NewNop(), metrics: metrics.New()},
		cfg:          cfg,
		hostname:     "upload.vendor.example",
		targetURL:    "wss://upload.vendor.example/socket",
	}
	reason := "RAR upload not fully read: no reader; " + scanner.IncompleteFileGovernedSuffix
	type frame struct {
		payload string
		err     error
	}
	frames := make(chan frame, 1)
	go func() {
		hdr, err := ws.ReadHeader(clientPeer)
		if err != nil {
			frames <- frame{err: err}
			return
		}
		payload := make([]byte, hdr.Length)
		if _, err = io.ReadFull(clientPeer, payload); err != nil {
			frames <- frame{err: err}
			return
		}
		frames <- frame{payload: string(payload)}
	}()
	blocked := relay.handleClientMessageBodyResult(audit.NewNop(), []byte("Rar!"), BodyScanResult{
		Clean:                    false,
		Action:                   config.ActionBlock,
		Reason:                   reason,
		FileInspectionIncomplete: reason,
		FileInspectionBlock:      true,
	})
	got := <-frames
	if !blocked || got.err != nil || !strings.Contains(got.payload, `"block_reason":"parse_error"`) || strings.Contains(got.payload, "dlp_match") {
		t.Fatalf("blocked=%t err=%v payload=%s", blocked, got.err, got.payload)
	}
	credential := "request body contains secret: AWS Access Key"
	client2, clientPeer2 := net.Pipe()
	upstream2, upstreamPeer2 := net.Pipe()
	t.Cleanup(func() {
		_ = client2.Close()
		_ = clientPeer2.Close()
		_ = upstream2.Close()
		_ = upstreamPeer2.Close()
	})
	go func() { _, _ = io.Copy(io.Discard, upstreamPeer2) }()
	relay.clientConn = client2
	relay.upstreamConn = upstream2
	frames = make(chan frame, 1)
	go func() {
		hdr, err := ws.ReadHeader(clientPeer2)
		if err != nil {
			frames <- frame{err: err}
			return
		}
		payload := make([]byte, hdr.Length)
		if _, err = io.ReadFull(clientPeer2, payload); err != nil {
			frames <- frame{err: err}
			return
		}
		frames <- frame{payload: string(payload)}
	}()
	blocked = relay.handleClientMessageBodyResult(audit.NewNop(), []byte("Rar!"), BodyScanResult{
		Clean:                    false,
		Action:                   config.ActionBlock,
		Reason:                   credential,
		FileInspectionIncomplete: reason,
		FileInspectionBlock:      true,
		DLPMatches:               []scanner.TextDLPMatch{{PatternName: "AWS Access Key", Severity: config.SeverityCritical}},
	})
	got = <-frames
	if !blocked || got.err != nil || !strings.Contains(got.payload, `"block_reason":"dlp_match"`) || strings.Contains(got.payload, "parse_error") {
		t.Fatalf("credential close blocked=%t err=%v payload=%s", blocked, got.err, got.payload)
	}
}

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
