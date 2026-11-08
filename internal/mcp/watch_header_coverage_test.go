// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"context"
	"encoding/base64"
	"net/http"
	"reflect"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

func TestWatchHeaderCoverageFloors(t *testing.T) {
	token := coreCredentialToken()
	for _, tc := range []struct {
		name                           string
		headers                        http.Header
		missing, canceled, a2a, refuse bool
	}{
		{name: "unavailable scanner", missing: true, refuse: true},
		{name: "ordinary headers", headers: http.Header{"X-Vendor": {"safe"}, "Authorization": {"Bearer ordinary"}}},
		{name: "credential in name", headers: http.Header{token: {"safe"}}, refuse: true},
		{name: "encoded parameter", headers: http.Header{"Mcp-Param-Value": {"=?base64?" + base64.StdEncoding.EncodeToString([]byte(token)) + "?="}}, refuse: true},
		{name: "A2A ordinary", headers: http.Header{"A2A-Extensions": {"https://api.vendor.example/extension"}}, a2a: true},
		{name: "A2A credential", headers: http.Header{"A2A-Extensions": {"https://api.vendor.example/extension?token=" + token}}, a2a: true, refuse: true},
		{name: "canceled A2A inspection", headers: http.Header{"A2A-Extensions": {"https://api.vendor.example/extension"}}, a2a: true, canceled: true, refuse: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			opts := testOpts(testInputScanner(t))
			opts.WatchOnly = true
			if tc.missing {
				opts = MCPProxyOpts{WatchOnly: true}
			}
			opts.RequestBodyCfg = &config.RequestBodyScanning{Enabled: true, ScanHeaders: true, HeaderMode: config.HeaderModeAll}
			if tc.a2a {
				cfg := config.Defaults().A2AScanning
				cfg.Enabled = true
				opts.A2ACfg = &cfg
			}
			logs := watchCoverageExtraLogger(t, &opts)
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			if tc.canceled {
				cancel()
			}
			before := tc.headers.Clone()
			got := watchMCPHeaders(ctx, tc.headers, "https://api.vendor.example/mcp", opts)
			if got != tc.refuse {
				t.Fatalf("refusal=%v want=%v observations=%s", got, tc.refuse, logs.String())
			}
			if !reflect.DeepEqual(tc.headers, before) {
				t.Fatal("header inspection mutated the original")
			}
			if tc.refuse && !strings.Contains(logs.String(), "watch_only_enforced") {
				t.Fatalf("refusal omitted enforcement observation: %s", logs.String())
			}
		})
	}
}
