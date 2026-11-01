// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"net"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gobwas/ws"

	"github.com/luckyPipewrench/pipelock/internal/blockreason"
	"github.com/luckyPipewrench/pipelock/internal/config"
)

func blockAllAdaptiveConfig() *config.AdaptiveEnforcement {
	cfg := config.Defaults().AdaptiveEnforcement
	cfg.Enabled = true
	cfg.Levels.Elevated.BlockAll = boolPtr(true)
	return &cfg
}

func TestAdaptiveRefusalWriterPassThrough(t *testing.T) {
	cfg := blockAllAdaptiveConfig()
	t.Run("informational status does not commit", func(t *testing.T) {
		rec := httptest.NewRecorder()
		w := &adaptiveRefusalWriter{ResponseWriter: rec, cfg: cfg, level: func() int { return 1 }}
		w.WriteHeader(http.StatusEarlyHints)
		if w.wroteHeader {
			t.Fatal("1xx committed the final response")
		}
		w.WriteHeader(http.StatusForbidden)
		if !w.refused || rec.Header().Get(blockreason.HeaderReason) != string(blockreason.EscalationLevel) {
			t.Fatalf("final refusal after 1xx not projected: refused=%v headers=%v", w.refused, rec.Header())
		}
	})
	t.Run("write before header passes a success through", func(t *testing.T) {
		rec := httptest.NewRecorder()
		w := &adaptiveRefusalWriter{ResponseWriter: rec, cfg: cfg, level: func() int { return 1 }}
		if _, err := w.Write([]byte("ok")); err != nil {
			t.Fatal(err)
		}
		if rec.Code != http.StatusOK || rec.Body.String() != "ok" {
			t.Fatalf("success altered: %d %q", rec.Code, rec.Body.String())
		}
	})
	t.Run("flush before header commits a success", func(t *testing.T) {
		rec := httptest.NewRecorder()
		w := &adaptiveRefusalWriter{ResponseWriter: rec, cfg: cfg, level: func() int { return 1 }}
		w.Flush()
		if !w.wroteHeader || rec.Code != http.StatusOK || !rec.Flushed {
			t.Fatalf("flush did not commit 200: wrote=%v code=%d flushed=%v", w.wroteHeader, rec.Code, rec.Flushed)
		}
	})
	t.Run("refused body is discarded and a second header ignored", func(t *testing.T) {
		rec := httptest.NewRecorder()
		w := &adaptiveRefusalWriter{ResponseWriter: rec, cfg: cfg, level: func() int { return 1 }}
		w.WriteHeader(http.StatusForbidden)
		body := rec.Body.String()
		w.WriteHeader(http.StatusTeapot)
		if n, err := w.Write([]byte("detector reason")); err != nil || n != len("detector reason") {
			t.Fatalf("refused write = %d, %v", n, err)
		}
		if rec.Code != http.StatusForbidden || rec.Body.String() != body {
			t.Fatalf("refusal changed after commit: %d %q", rec.Code, rec.Body.String())
		}
	})
	t.Run("unwrap returns the underlying writer", func(t *testing.T) {
		rec := httptest.NewRecorder()
		w := &adaptiveRefusalWriter{ResponseWriter: rec}
		if w.Unwrap() != rec {
			t.Fatal("Unwrap did not return the wrapped writer")
		}
	})
}

func TestAdaptiveRefusalWrappersSkipDisabledAdaptive(t *testing.T) {
	disabled := config.Defaults()
	disabled.AdaptiveEnforcement.Enabled = false
	rec := httptest.NewRecorder()
	var p *Proxy
	if got := p.withAdaptiveRefusal(rec, adaptiveRefusalOptions{config: disabled}); got != rec {
		t.Fatal("nil proxy wrapped the writer")
	}
	if got := (&Proxy{}).withAdaptiveRefusal(rec, adaptiveRefusalOptions{config: disabled}); got != rec {
		t.Fatal("disabled adaptive wrapped the writer")
	}
	conn, peer := net.Pipe()
	defer func() { _ = conn.Close() }()
	defer func() { _ = peer.Close() }()
	if got := (&Proxy{}).withAdaptiveClose(conn, adaptiveRefusalOptions{config: disabled}); got != conn {
		t.Fatal("disabled adaptive wrapped the connection")
	}
	if got := (&Proxy{}).withAdaptiveClose(nil, adaptiveRefusalOptions{config: config.Defaults()}); got != nil {
		t.Fatal("nil connection was wrapped")
	}
	if got := unprojectedConn(conn); got != conn {
		t.Fatal("unprojectedConn changed a plain connection")
	}
	if got := unprojectedConn(&adaptiveCloseConn{Conn: conn}); got != conn {
		t.Fatal("unprojectedConn did not unwrap the projecting connection")
	}
}

func TestAdaptiveRefusalLevelWithoutSession(t *testing.T) {
	p := &Proxy{}
	if got := p.adaptiveRefusalLevel(adaptiveRefusalOptions{config: config.Defaults(), host: func() string { return "api.vendor.example" }}); got != 0 {
		t.Fatalf("level without a session manager = %d, want 0", got)
	}
	if got := p.adaptiveRefusalLevel(adaptiveRefusalOptions{level: func() int { return 2 }}); got != 2 {
		t.Fatalf("level override = %d, want 2", got)
	}
	if got := refusalURLHost("http://[::1"); got != "" {
		t.Fatalf("unparseable target host = %q, want empty", got)
	}
	relay := &wsRelay{}
	if code, reason := relay.refusalClose(ws.StatusNormalClosure, "bye"); code != ws.StatusNormalClosure || reason != "bye" {
		t.Fatalf("relay without config changed close: %d %q", code, reason)
	}
}
