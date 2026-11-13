// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gobwas/ws"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

type reviewReloadReader struct {
	p    *Proxy
	done bool
}

func (r *reviewReloadReader) Read(b []byte) (int, error) {
	if !r.done {
		r.done = true
		cfg := config.Defaults()
		_ = r.p.setupRequestPolicy(cfg)
		return copy(b, "partial"), io.ErrUnexpectedEOF
	}
	return 0, io.EOF
}

func TestReviewReloadDuringBodyRead(t *testing.T) {
	cfg := reqPolicyConfig(graphqlBlockRule())
	p := newTestProxyWithConfig(t, cfg)
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "http://"+rpTestHost+"/graphql", strings.NewReader("payload"))
	req.Body = io.NopCloser(&reviewReloadReader{p: p})
	in := requestPolicyInput{Host: rpTestHost, Method: http.MethodPost, Path: "/graphql", ContentType: "application/json", Config: cfg}
	if result := p.prepareRequestPolicyBody(req, &in); !result.Block {
		t.Fatal("partially consumed body allowed after policy reload")
	}
}

func TestReviewWSAnchoredProtocolDLP(t *testing.T) {
	target, _, hits := wsSelectingBackend(t, func(string) bool { return true })
	proxyAddr, cleanup := setupWSProxy(t, func(cfg *config.Config) {
		cfg.DLP.Patterns = append(cfg.DLP.Patterns, config.DLPPattern{Name: "anchored credential", Regex: `^private-token-123456$`, Severity: config.SeverityHigh})
		cfg.RequestBodyScanning.Action = config.ActionBlock
		if result := scanner.MustNew(cfg).ScanTextForDLP(t.Context(), "private-token-123456"); result.Clean {
			t.Fatalf("positive control did not match: %+v", result)
		}
	})
	defer cleanup()
	resp, conn := rawWSHandshake(t, ws.HandshakeHeaderHTTP(http.Header{headerNameWSProtocol: []string{"private-token-123456", "other"}}), wsProxyURL(proxyAddr, target), true)
	defer func() { _ = conn.Close() }()
	if resp.StatusCode != http.StatusForbidden || hits.Load() != 0 {
		t.Fatalf("status %d, upstream hits %d; want 403 and zero", resp.StatusCode, hits.Load())
	}
}
