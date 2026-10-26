// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"bytes"
	"net/http"
	"strings"
	"testing"
)

func TestListenerCapacityNote(t *testing.T) {
	for _, kind := range []string{"legacy", "profiling-off", "token-required", "token-required-live", "bearer", "bearer-live", "principal"} {
		t.Run(kind, func(t *testing.T) {
			opts := MCPProxyOpts{Store: &listenerStateBoundedStore{}}
			required := true
			switch kind {
			case "profiling-off":
				opts.Store = nil
			case "token-required":
				opts.listenerStateTokenRequired = &required
			case "token-required-live":
				opts.ListenerStateTokenRequiredFn = func() *bool { return &required }
			case "bearer":
				opts.ListenerBearerToken = principalStateTestBearer
			case "bearer-live":
				opts.ListenerBearerTokenFn = func() (string, error) { return principalStateTestBearer, nil }
			case "principal":
				opts.ListenerPrincipalResolver = func(*http.Request) (ListenerPrincipal, error) { return ListenerPrincipal{}, nil }
			}
			var out bytes.Buffer
			logListenerCapacityNote(&out, opts)
			if got := strings.Contains(out.String(), "retained sessions can exhaust shared capacity"); got != (kind == "legacy") {
				t.Fatalf("capacity note=%t, kind=%s: %s", got, kind, out.String())
			}
			if kind == "legacy" && (!strings.Contains(out.String(), "authenticated principal") || !strings.Contains(out.String(), "listener_require_state_token") || !strings.Contains(out.String(), "not a per-caller quota")) {
				t.Fatalf("capacity note omitted recovery limits: %s", out.String())
			}
		})
	}
}
