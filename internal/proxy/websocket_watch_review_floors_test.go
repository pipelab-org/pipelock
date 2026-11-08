// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"net/url"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

// A WebSocket relay that follows a URL-shaped query value reaches that
// destination without this proxy dialing it, so a nested metadata destination
// is refused at the handshake, as on the HTTP watch path.
func TestWatchWebSocketNestedSSRFRefusal(t *testing.T) {
	for _, tc := range []struct {
		name, query string
		refused     bool
	}{
		{name: "nested metadata", query: "?next=" + url.QueryEscape("http://169.254.169.254/latest/meta-data"), refused: true},
		{name: "nested public destination", query: "?next=" + url.QueryEscape("http://api.vendor.example/ok")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			backend, closeBackend := wsEchoServer(t)
			defer closeBackend()
			addr, cleanup := setupWSProxy(t, func(cfg *config.Config) { cfg.WatchOnly = true })
			defer cleanup()
			conn, err := dialWSConnToTarget(addr, "ws://"+backend+"/relay"+tc.query)
			if conn != nil {
				_ = conn.Close()
			}
			if tc.refused && err == nil {
				t.Fatal("nested metadata destination reached the WebSocket relay")
			}
			if !tc.refused && err != nil {
				t.Fatalf("ordinary nested destination refused: %v", err)
			}
		})
	}
}
