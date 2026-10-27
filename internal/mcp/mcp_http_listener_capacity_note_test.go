// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"bytes"
	"fmt"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

func TestListenerCapacityNote(t *testing.T) {
	doc, err := os.ReadFile("../../docs/configuration.md")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(doc), "> "+listenerCapacityNote+"\n") {
		t.Fatal("configuration docs do not match the emitted capacity note")
	}
	if listenerLegacyIdleTTL != 24*time.Hour {
		t.Fatal("update capacity note and docs for the listener idle expiry")
	}
	for _, tc := range []struct {
		name                   string
		store, controls, token bool
		auth                   string
		want                   bool
	}{
		{"no-store", false, true, false, "", false},
		{"stateless", true, false, false, "", false},
		{"legacy", true, true, false, "", true},
		{"token-only", true, false, true, "", true},
		{"token-controls", true, true, true, "", true},
		{"bearer", true, true, false, "bearer", false},
		{"token-bearer", true, false, true, "bearer", false},
		{"bearer-live", true, true, false, "bearer-live", false},
		{"principal", true, true, false, "principal", false},
		{"token-principal", true, false, true, "principal", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			opts := MCPProxyOpts{}
			if tc.store {
				opts.Store = &listenerStateBoundedStore{}
			}
			if tc.controls {
				opts.TaintCfg = &config.TaintConfig{Enabled: true}
			}
			opts.listenerStateTokenRequired = &tc.token
			switch tc.auth {
			case "bearer":
				opts.ListenerBearerToken = principalStateTestBearer
			case "bearer-live":
				opts.ListenerBearerTokenFn = func() (string, error) { return principalStateTestBearer, nil }
			case "principal":
				opts.ListenerPrincipalResolver = func(*http.Request) (ListenerPrincipal, error) { return ListenerPrincipal{}, nil }
			}
			word := func(value bool, yes, no string) string {
				if value {
					return yes
				}
				return no
			}
			row := fmt.Sprintf("| %s | %s | %s | %s | %s |", word(tc.store, "present", "absent"), word(tc.controls, "enabled", "disabled"), word(tc.token, "enabled", "disabled"), word(tc.auth != "", "configured", "absent"), word(tc.want, "yes", "no"))
			if !strings.Contains(string(doc), row) {
				t.Fatalf("docs missing tested condition: %s", row)
			}
			for _, live := range []bool{false, true} {
				if live {
					opts.ListenerStateTokenRequiredFn = func() *bool { return &tc.token }
				}
				var out bytes.Buffer
				logListenerCapacityNote(&out, opts)
				want := ""
				if tc.want {
					want = listenerCapacityNote + "\n"
				}
				if out.String() != want {
					t.Fatalf("live=%t: note=%q, want %q", live, out.String(), want)
				}
			}
		})
	}
}
