// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

func TestWatchReverseRangeAndSize(t *testing.T) {
	for _, watch := range []bool{false, true} {
		t.Run(map[bool]string{false: "enforce", true: "watch"}[watch], func(t *testing.T) {
			cfg := config.Defaults()
			cfg.Internal = nil
			cfg.WatchOnly = watch
			var reached atomic.Bool
			payload := strings.Repeat("unchanged response ", 20)
			srv, handler := reverseTestSetupWithHandler(t, cfg, func(w http.ResponseWriter, r *http.Request) {
				reached.Store(true)
				if r.Header.Get("Range") != "bytes=10-20" {
					t.Error("range header changed")
				}
				w.Header().Set("Etag", "original")
				w.Header().Set("Content-Type", "text/plain")
				w.WriteHeader(http.StatusPartialContent)
				_, _ = io.WriteString(w, payload)
			})
			handler.responseBodyLimit = 64
			req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, srv.URL+"/download", nil)
			if err != nil {
				t.Fatal(err)
			}
			req.Header.Set("Range", "bytes=10-20")
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = resp.Body.Close() }()
			body, err := io.ReadAll(resp.Body)
			if err != nil {
				t.Fatal(err)
			}
			if watch {
				if resp.StatusCode != http.StatusPartialContent || string(body) != payload || resp.Header.Get("Etag") != "original" {
					t.Fatalf("changed response status=%d body=%q", resp.StatusCode, body)
				}
			} else if reached.Load() || resp.StatusCode != http.StatusForbidden {
				t.Fatalf("default range guard lost: %d", resp.StatusCode)
			}
		})
	}
}

func TestWatchReverseCredentialAndKillFloors(t *testing.T) {
	for _, tc := range []struct {
		name string
		kill bool
		body string
	}{
		{name: "credential", body: "AKIA" + "IOSFODNN7" + testWSExample},
		{name: "kill", kill: true, body: "ordinary request"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := config.Defaults()
			cfg.WatchOnly = true
			cfg.Internal = nil
			cfg.KillSwitch.Enabled = tc.kill
			var reached atomic.Bool
			srv := reverseTestSetup(t, cfg, func(w http.ResponseWriter, _ *http.Request) { reached.Store(true); w.WriteHeader(http.StatusOK) })
			resp := testPost(t, srv.URL, "text/plain", tc.body)
			defer func() { _ = resp.Body.Close() }()
			if resp.StatusCode < 400 || reached.Load() {
				t.Fatalf("floor released request: %d", resp.StatusCode)
			}
		})
	}
}

func TestWatchReverseUninspectableRequestRefused(t *testing.T) {
	cfg := config.Defaults()
	cfg.WatchOnly = true
	cfg.Internal = nil
	cfg.RequestBodyScanning.MaxBodyBytes = 32
	payload := bytes.Repeat([]byte("ordinary request "), 20)
	srv := reverseTestSetup(t, cfg, func(w http.ResponseWriter, r *http.Request) {
		t.Error("uninspectable request reached upstream")
		got, err := io.ReadAll(r.Body)
		if err != nil {
			t.Error(err)
		}
		if !bytes.Equal(got, payload) {
			t.Errorf("body changed: %q", got)
		}
		w.WriteHeader(http.StatusOK)
	})
	resp := testPost(t, srv.URL, "text/plain", string(payload))
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status %d", resp.StatusCode)
	}
}
