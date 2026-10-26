// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
)

func TestHTTPListener_ContractDiscoverySSEFramingBudget(t *testing.T) {
	for _, tc := range []struct {
		name                    string
		commentMiB, pages, want int
	}{
		{"within budget", 1, 1, http.StatusOK},
		{"single response over budget", 12, 1, http.StatusServiceUnavailable},
		{"cumulative responses over budget", 6, 2, http.StatusServiceUnavailable},
	} {
		t.Run(tc.name, func(t *testing.T) {
			comment := ":" + strings.Repeat("x", 1024*1024) + "\n\n"
			f := newDiscoveryFixture(t, paramContractOpts(t), func(w http.ResponseWriter, _ *http.Request, frame MCPFrame, n int) {
				w.Header().Set("Content-Type", "text/event-stream")
				for range tc.commentMiB {
					if _, err := io.WriteString(w, comment); err != nil {
						return
					}
				}
				_, _ = io.WriteString(w, "data: ")
				if n < tc.pages {
					discoveryList(w, frame, `[]`, fmt.Sprint(n))
				} else {
					discoveryList(w, frame, headerStateDefs(headerStateSchema, "Echo input"), "")
				}
				_, _ = io.WriteString(w, "\n\n")
			})
			status, body := f.call(t, "body", "first")
			if status != tc.want || int(f.lists.Load()) != tc.pages {
				t.Fatalf("status=%d lists=%d body=%s", status, f.lists.Load(), body)
			}
			if tc.want != http.StatusOK && (f.calls.Load() != 0 || !strings.Contains(body, "response byte budget")) {
				t.Fatalf("over-budget discovery did not refuse execution: calls=%d body=%s", f.calls.Load(), body)
			}
		})
	}
}
