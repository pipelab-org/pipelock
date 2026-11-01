// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"bytes"
	"encoding/base64"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/gobwas/ws"

	"github.com/luckyPipewrench/pipelock/internal/audit"
	"github.com/luckyPipewrench/pipelock/internal/blockreason"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/metrics"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

// Escalate only when the body scanner reads the upload, after admission. Starting
// locked would exercise session_deny without reaching the upload refusal at all.
type adaptiveUploadReader struct {
	io.Reader
	beforeRead func()
}

func (r *adaptiveUploadReader) Read(p []byte) (int, error) {
	if r.beforeRead != nil {
		r.beforeRead()
		r.beforeRead = nil
	}
	return r.Reader.Read(p)
}

func adaptiveUploadCases(t *testing.T) map[string][]byte {
	t.Helper()
	document, err := os.ReadFile("../fileinspect/testdata/libreoffice-seeded.docx")
	if err != nil {
		t.Fatal(err)
	}
	archive := uploadArchive(t, map[string][]byte{"ordinary.txt": []byte("ordinary text")})
	return map[string][]byte{"credential": document, "incomplete": archive[:len(archive)-1]}
}

func TestAdaptiveUniformRefusalUploadInspectionHTTP(t *testing.T) {
	for _, surface := range []string{TransportForward, "intercept", TransportReverse} {
		for name, data := range adaptiveUploadCases(t) {
			t.Run(surface+"/"+name, func(t *testing.T) {
				cfg := adaptiveConfigBlockAll()
				cfg.Enforce = ptrBool(true)
				cfg.DefaultAgentIdentity = ""
				cfg.BindDefaultAgentIdentity = false
				cfg.ExplainBlocks = ptrBool(true)
				cfg.RequestBodyScanning.Enabled = true
				cfg.RequestBodyScanning.Action = config.ActionBlock
				cfg.RequestBodyScanning.ContentEntropyEnabled = false
				cfg.TLSInterception.MaxResponseBytes = 1 << 20
				var logs bytes.Buffer
				logger, err := audit.NewWithStream("json", "stdout", "", false, true, &logs)
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(logger.Close)
				sc := scanner.MustNew(cfg)
				t.Cleanup(sc.Close)
				p, err := New(cfg, logger, sc, metrics.New())
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(p.Close)
				rec := p.sessionMgrPtr.Load().GetOrCreate(adaptiveSessionKeyHTTPTest)
				const target = "https://api.vendor.example/upload"
				var handler http.HandlerFunc
				switch surface {
				case TransportForward:
					handler = p.handleForwardHTTP
				case "intercept":
					handler = newInterceptHandler(&InterceptContext{Proxy: p, TargetHost: "api.vendor.example", TargetPort: "443", Config: cfg, Scanner: sc, Logger: logger, Metrics: p.metrics, ClientIP: adaptiveSessionKeyHTTPTest, Agent: agentAnonymous, SessionMgr: p.sessionMgrPtr.Load(), Recorder: rec}, &interceptMockRT{}).ServeHTTP
				case TransportReverse:
					upstream, _ := url.Parse(target)
					rp := NewReverseProxy(upstream, p.ConfigPtr(), p.ScannerPtr(), logger, p.metrics, nil, nil, nil)
					rp.SetOwnerProxy(p)
					handler = rp.ServeHTTP
				}
				send := func(escalate bool) *httptest.ResponseRecorder {
					t.Helper()
					read := false
					r := httptest.NewRequestWithContext(t.Context(), http.MethodPut, target, bytes.NewReader(data))
					r.Header.Set("Content-Type", "application/octet-stream")
					r.Body = io.NopCloser(&adaptiveUploadReader{Reader: bytes.NewReader(data), beforeRead: func() {
						read = true
						if escalate {
							escalateRec(rec, 1)
						}
					}})
					w := httptest.NewRecorder()
					handler(w, r)
					if !read {
						t.Fatal("upload never reached the body scanner")
					}
					return w
				}
				below := send(false)
				want := blockreason.DLPMatch
				if name == "incomplete" {
					want = blockreason.ParseError
				}
				if below.Code != http.StatusForbidden || below.Header().Get(blockreason.HeaderReason) != string(want) {
					t.Fatalf("below block_all: %d %v %s", below.Code, below.Header(), below.Body.String())
				}
				_, _ = rec.Reset(false)
				logs.Reset()
				caught := send(true)
				if surface != TransportReverse && (!strings.Contains(logs.String(), `"event":"blocked"`) || (name == "incomplete" && !strings.Contains(logs.String(), "not fully read"))) {
					t.Fatalf("upload evidence missing: %s", logs.String())
				}
				clean := httptest.NewRecorder()
				handler(clean, httptest.NewRequestWithContext(t.Context(), http.MethodGet, target, nil))
				if caught.Code != http.StatusForbidden || caught.Header().Get(blockreason.HeaderReason) != string(blockreason.EscalationLevel) || !reflect.DeepEqual(clean.Result().Header, caught.Result().Header) || !bytes.Equal(clean.Body.Bytes(), caught.Body.Bytes()) {
					t.Fatalf("upload refusal differs from session denial: upload=%d %v %s; clean=%d %v %s", caught.Code, caught.Header(), caught.Body.String(), clean.Code, clean.Header(), clean.Body.String())
				}
			})
		}
	}
}

func TestAdaptiveUniformRefusalUploadInspectionWebSocket(t *testing.T) {
	for name, data := range adaptiveUploadCases(t) {
		for _, locked := range []bool{false, true} {
			state := "below"
			if locked {
				state = "block_all"
			}
			t.Run(name+"/"+state, func(t *testing.T) {
				relay, _ := newAdaptiveWSRelay(t, 0)
				relay.cfg.AdaptiveEnforcement.Levels.Elevated.BlockAll = ptrBool(true)
				relay.cfg.Enforce = ptrBool(true)
				relay.cfg.RequestBodyScanning.Action = config.ActionBlock
				relay.cfg.RequestBodyScanning.ContentEntropyEnabled = false
				relay.hostname = "api.vendor.example"
				relay.maxMsg = 1 << 20
				relay.scanner = scanner.MustNew(relay.cfg)
				t.Cleanup(relay.scanner.Close)
				message := []byte(`{"contentBytes":"` + base64.StdEncoding.EncodeToString(data) + `"}`)
				body, result := relay.scanClientMessageBody(t.Context(), message)
				if result.Clean || (name == "incomplete" && !result.FileInspectionBlock) || (name == "credential" && len(result.DLPMatches) == 0) {
					t.Fatalf("fixture did not reach upload inspection: %+v", result)
				}
				if locked {
					escalateRec(relay.rec, 1)
				}
				client, upstream := &receiptFrameConn{}, &receiptFrameConn{}
				relay.clientConn, relay.upstreamConn = client, upstream
				if !relay.handleClientMessageBodyResult(audit.NewNop(), body, result) {
					t.Fatal("upload finding was allowed")
				}
				var closes [][]byte
				for i, conn := range []*receiptFrameConn{client, upstream} {
					wire := bytes.NewReader(conn.output.Bytes())
					hdr, err := ws.ReadHeader(wire)
					if err != nil {
						t.Fatal(err)
					}
					payload, err := io.ReadAll(wire)
					if err != nil {
						t.Fatal(err)
					}
					if hdr.Masked {
						ws.Cipher(payload, hdr.Mask, 0)
					}
					want := blockreason.DLPMatch
					if name == "incomplete" {
						want = blockreason.ParseError
					}
					if locked {
						want = blockreason.EscalationLevel
					}
					if hdr.OpCode != ws.OpClose || hdr.Masked != (i == 1) || len(payload) < 2 || ws.StatusCode(payload[0])<<8|ws.StatusCode(payload[1]) != ws.StatusPolicyViolation || !bytes.Contains(payload[2:], []byte(`"block_reason":"`+string(want)+`"`)) {
						t.Fatalf("unexpected close: header=%+v payload=%s", hdr, payload)
					}
					closes = append(closes, payload)
				}
				if locked && (!bytes.Equal(closes[0], closes[1]) || bytes.Contains(closes[0], []byte(relay.requestID)) || bytes.Contains(closes[0], []byte("parse_error")) || bytes.Contains(closes[0], []byte("dlp_match"))) {
					t.Fatalf("nonuniform closes: %q / %q", closes[0], closes[1])
				}
			})
		}
	}
}
