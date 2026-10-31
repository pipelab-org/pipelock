// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/deferred"
	"github.com/luckyPipewrench/pipelock/internal/mcp/tools"
	"github.com/luckyPipewrench/pipelock/internal/mcp/transport"
	"github.com/luckyPipewrench/pipelock/internal/receipt"
	"github.com/luckyPipewrench/pipelock/internal/testwait"
)

type discoveryFixture struct {
	url   string
	lists atomic.Int32
	calls atomic.Int32
	list  func(http.ResponseWriter, *http.Request, MCPFrame, int)
}

func newDiscoveryFixture(t *testing.T, opts MCPProxyOpts, list func(http.ResponseWriter, *http.Request, MCPFrame, int)) *discoveryFixture {
	t.Helper()
	f := &discoveryFixture{list: list}
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		frame := ParseMCPFrame(body)
		w.Header().Set("Content-Type", "application/json")
		if frame.Method == "tools/list" {
			n := int(f.lists.Add(1))
			f.list(w, r, frame, n)
			return
		}
		f.calls.Add(1)
		_, _ = fmt.Fprintf(w, `{"jsonrpc":"2.0","id":%s,"result":{"content":[]}}`, frame.ID)
	}))
	t.Cleanup(up.Close)
	f.url, _ = startListenerProxyWithOpts(t, up.URL, opts)
	return f
}

func discoveryList(w http.ResponseWriter, frame MCPFrame, defs, cursor string) {
	if cursor == "" {
		_, _ = fmt.Fprintf(w, `{"jsonrpc":"2.0","id":%s,"result":{"tools":%s}}`, frame.ID, defs)
		return
	}
	_, _ = fmt.Fprintf(w, `{"jsonrpc":"2.0","id":%s,"result":{"tools":%s,"nextCursor":%q}}`, frame.ID, defs, cursor)
}

func (f *discoveryFixture) call(t *testing.T, mirror, principal string) (int, string) {
	t.Helper()
	h := currentWireHeaders(methodToolsCall, "echo")
	h.Set("Proxy-Authorization", headerStateBearer)
	h.Set("Authorization", "Bearer upstream-"+principal)
	if mirror != "" {
		h.Set("Mcp-Param-Region", mirror)
	}
	status, _, body := postWireContractRequest(t, f.url, currentWireBody(2, methodToolsCall, `"name":"echo","arguments":{"region":"body"}`), h)
	return status, body
}

func TestHTTPListener_ContractDiscoveryOutcomes(t *testing.T) {
	for _, tc := range []struct {
		name, defs, mirror string
		want               int
		text               string
	}{
		{"matching", headerStateDefs(headerStateSchema, "Echo input"), "body", 200, ""},
		{"mismatch", headerStateDefs(headerStateSchema, "Echo input"), "different", 400, "parameter header"},
		{"missing", headerStateDefs(headerStateSchema, "Echo input"), "", 400, "parameter header"},
		{"unannotated", headerStateDefs(`{"type":"object"}`, "Echo input"), "", 200, ""},
		{"invalid", headerStateDefs(headerStateInvalid, "Echo input"), "", 400, "schema is invalid"},
		{"absent", `[]`, "", 503, "absent from complete"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newDiscoveryFixture(t, paramContractOpts(t), func(w http.ResponseWriter, r *http.Request, frame MCPFrame, _ int) {
				if r.Header.Get("Authorization") != "Bearer upstream-first" || r.Header.Get("Proxy-Authorization") != "" || r.Header.Get(listenerMCPMethod) != "tools/list" || r.Header.Get(listenerMCPName) != "" || hasMCPParamHeaders(r.Header) || r.Header.Get(listenerProtocolVersion) != currentMCPVersion || frame.ProtocolVersion != currentMCPVersion {
					t.Errorf("discovery lost authentication or routing separation: %v frame=%+v", r.Header, frame)
				}
				discoveryList(w, frame, tc.defs, "")
			})
			status, body := f.call(t, tc.mirror, "first")
			if status != tc.want || !strings.Contains(body, tc.text) {
				t.Fatalf("status=%d body=%s", status, body)
			}
			wantCalls := int32(0)
			if tc.want == 200 {
				wantCalls = 1
			}
			if f.lists.Load() != 1 || f.calls.Load() != wantCalls {
				t.Fatalf("lists=%d calls=%d", f.lists.Load(), f.calls.Load())
			}
			// Persistent observations, including rejection, do not require rediscovery.
			if tc.name != "absent" {
				_, _ = f.call(t, tc.mirror, "first")
				if f.lists.Load() != 1 {
					t.Fatal("known contract rediscovered")
				}
			}
		})
	}
}

func TestContractDiscoveryDoesNotRecoverAdaptiveState(t *testing.T) {
	for _, private := range []bool{false, true} {
		t.Run(strconv.FormatBool(private), func(t *testing.T) {
			rec := &mockRecoverer{level: 1, score: 20}
			timerCalls, cleanCalls := 0, 0
			rec.recoverFunc = func(func(int) bool) (bool, int, int) {
				timerCalls++
				return false, 0, 0
			}
			rec.cleanRecoverFunc = func(float64, int, func(int) bool) (bool, int, int) {
				cleanCalls++
				return false, 0, 0
			}
			opts := paramContractOpts(t)
			opts.Rec = rec
			opts.AdaptiveCfg = adaptiveCfgEnabled()
			opts.toolContractDiscovery = private
			tracker := NewStrictRequestTracker()
			tracker.TrackRequest(json.RawMessage("1"), "tools/list")
			var out strings.Builder
			message := `{"jsonrpc":"2.0","id":1,"result":{"tools":` + headerStateDefs(headerStateSchema, "Echo input") + `}}`
			_, err := ForwardScanned(&transport.SingleMessageReader{Body: io.NopCloser(strings.NewReader(message))}, transport.NewStdioWriter(&out), io.Discard, tracker, opts)
			if err != nil || !strings.Contains(out.String(), `"tools"`) {
				t.Fatalf("inventory inspection failed: %v output=%s", err, out.String())
			}
			want := 1
			if private {
				want = 0
			}
			if timerCalls != want || cleanCalls != 0 || rec.recordCleanCalls != 0 {
				t.Fatalf("private=%v timer=%d clean=%d fallback=%d", private, timerCalls, cleanCalls, rec.recordCleanCalls)
			}
		})
	}
}

func TestHTTPListener_ContractDiscoveryPagination(t *testing.T) {
	filler := func(n int) string {
		return fmt.Sprintf(`[{"name":"filler-%d","description":"Filler","inputSchema":{"type":"object"}}]`, n)
	}
	// Page size belongs to the server: a long list of small pages, an empty
	// page, or a page repeating an earlier definition all lead on to the tool.
	const longInventory = 150
	tests := []struct {
		mode  string
		pages int32
		want  int
	}{
		{"second page", 2, 200},
		{"long inventory", longInventory, 200},
		{"empty page", 3, 200},
		{"repeat only page", 3, 200},
		{"cursor cycle", 2, 503},
	}
	for _, tt := range tests {
		t.Run(tt.mode, func(t *testing.T) {
			f := newDiscoveryFixture(t, paramContractOpts(t), func(w http.ResponseWriter, r *http.Request, frame MCPFrame, n int) {
				var request struct {
					Params struct {
						Cursor string `json:"cursor"`
					} `json:"params"`
				}
				// frame.Raw retains the request already consumed by the fixture.
				_ = json.Unmarshal(frame.Raw, &request)
				if n > 1 && tt.mode != "cursor cycle" && request.Params.Cursor != strconv.Itoa(n-1) {
					t.Errorf("page %d cursor=%q", n, request.Params.Cursor)
				}
				switch {
				case tt.mode == "second page" && n == 2, tt.mode == "long inventory" && n == longInventory,
					(tt.mode == "empty page" || tt.mode == "repeat only page") && n == 3:
					discoveryList(w, frame, headerStateDefs(headerStateSchema, "Echo input"), "")
				case tt.mode == "empty page" && n == 2:
					discoveryList(w, frame, `[]`, strconv.Itoa(n))
				case tt.mode == "repeat only page":
					discoveryList(w, frame, filler(1), strconv.Itoa(n))
				case tt.mode == "cursor cycle":
					discoveryList(w, frame, filler(n), "1")
				default:
					discoveryList(w, frame, filler(n), strconv.Itoa(n))
				}
			})
			status, body := f.call(t, "body", "first")
			if status != tt.want || f.lists.Load() != tt.pages {
				t.Fatalf("status=%d lists=%d body=%s", status, f.lists.Load(), body)
			}
			if tt.want != 200 && (f.calls.Load() != 0 || !strings.Contains(body, "contract")) {
				t.Fatalf("incomplete discovery forwarded call: %s", body)
			}
		})
	}
}

func TestHTTPListener_ContractDiscoveryFailures(t *testing.T) {
	for _, mode := range []string{"5xx", "auth", "empty", "malformed", "scan block", "wrong id", "missing tools", "duplicate keys", "compressed stream", "unsupported encoding", "redirect", "capacity"} {
		t.Run(mode, func(t *testing.T) {
			f := newDiscoveryFixture(t, paramContractOpts(t), func(w http.ResponseWriter, _ *http.Request, frame MCPFrame, _ int) {
				switch mode {
				case "5xx":
					w.WriteHeader(http.StatusInternalServerError)
					discoveryList(w, frame, headerStateDefs(headerStateSchema, "Echo input"), "")
				case "auth":
					w.WriteHeader(http.StatusUnauthorized)
					discoveryList(w, frame, headerStateDefs(headerStateSchema, "Echo input"), "")
				case "redirect":
					w.WriteHeader(http.StatusFound)
					discoveryList(w, frame, headerStateDefs(headerStateSchema, "Echo input"), "")
				case "malformed":
					_, _ = io.WriteString(w, `{"result":`)
				case "wrong id":
					discoveryList(w, ParseMCPFrame([]byte(`{"id":999}`)), headerStateDefs(headerStateSchema, "Echo input"), "")
				case "missing tools":
					_, _ = io.WriteString(w, `{"jsonrpc":"2.0","id":1,"result":{}}`)
				case "duplicate keys":
					_, _ = fmt.Fprintf(w, `{"jsonrpc":"2.0","id":1,"result":{"tools":[],"tools":%s}}`, headerStateDefs(headerStateSchema, "Echo input"))
				case "scan block":
					discoveryList(w, frame, headerStateDefs(headerStateSchema, headerStateWarning), "")
				case "compressed stream":
					w.Header().Set("Content-Type", "text/event-stream")
					w.Header().Set("Content-Encoding", "gzip")
					_, _ = io.WriteString(w, "data: ")
					discoveryList(w, frame, headerStateDefs(headerStateSchema, "Echo input"), "")
					_, _ = io.WriteString(w, "\n\n")
				case "unsupported encoding":
					w.Header().Set("Content-Encoding", "unknown")
					discoveryList(w, frame, headerStateDefs(headerStateSchema, "Echo input"), "")
				case "capacity":
					defs := make([]string, 10001) // docs/configuration.md: 10,000-tool baseline cap.
					for i := range defs {
						defs[i] = fmt.Sprintf(`{"name":"t%d","inputSchema":{"type":"object"}}`, i)
					}
					defs[0] = `{"name":"echo","inputSchema":{"type":"object"}}`
					discoveryList(w, frame, "["+strings.Join(defs, ",")+"]", "")
				}
			})
			status, body := f.call(t, "body", "first")
			if status != 503 || f.calls.Load() != 0 || !strings.Contains(body, "cannot establish tool header contract") {
				t.Fatalf("status=%d calls=%d body=%s", status, f.calls.Load(), body)
			}
		})
	}
}

func TestHTTPListener_ContractDiscoveryPinnedCredentials(t *testing.T) {
	opts := paramContractOpts(t)
	opts.UpstreamHeaders = http.Header{"Authorization": {"Bearer service-credential"}, "X-Service-Context": {"service"}}
	f := newDiscoveryFixture(t, opts, func(w http.ResponseWriter, r *http.Request, frame MCPFrame, _ int) {
		if r.Header.Get("Authorization") != "Bearer service-credential" || r.Header.Get("X-Service-Context") != "service" {
			t.Error("discovery did not preserve operator-pinned upstream credentials")
		}
		discoveryList(w, frame, headerStateDefs(headerStateSchema, "Echo input"), "")
	})
	if status, body := f.call(t, "different", "client-credential"); status != http.StatusBadRequest || f.calls.Load() != 0 {
		t.Fatalf("mismatch forwarded under pinned credentials: status=%d body=%s", status, body)
	}
	if status, body := f.call(t, "body", "client-credential"); status != http.StatusOK || f.calls.Load() != 1 || f.lists.Load() != 1 {
		t.Fatalf("matching call failed under pinned credentials: status=%d body=%s", status, body)
	}
}

func TestHTTPListener_ContractDiscoveryCumulativeCapacity(t *testing.T) {
	f := newDiscoveryFixture(t, paramContractOpts(t), func(w http.ResponseWriter, _ *http.Request, frame MCPFrame, n int) {
		switch n {
		case 1:
			// docs/configuration.md publishes the 10,000-tool baseline cap.
			defs := make([]string, 10000)
			for i := range defs {
				defs[i] = fmt.Sprintf(`{"name":"tool%d","inputSchema":{"type":"object"}}`, i)
			}
			discoveryList(w, frame, "["+strings.Join(defs, ",")+"]", "next")
		case 2:
			discoveryList(w, frame, `[{"name":"additional","inputSchema":{"type":"object"}}]`, "last")
		default:
			discoveryList(w, frame, headerStateDefs(headerStateSchema, "Echo input"), "")
		}
	})
	status, body := f.call(t, "body", "first")
	if status != http.StatusServiceUnavailable || f.calls.Load() != 0 || f.lists.Load() != 2 || !strings.Contains(body, "capacity") {
		t.Fatalf("cumulative inventory capacity: status=%d lists=%d calls=%d body=%s", status, f.lists.Load(), f.calls.Load(), body)
	}
}

func TestHTTPListener_ContractDiscoverySSEAndWarn(t *testing.T) {
	for _, sse := range []bool{false, true} {
		t.Run(strconv.FormatBool(sse), func(t *testing.T) {
			opts := paramContractOpts(t)
			opts.ToolCfg.Action = config.ActionWarn
			f := newDiscoveryFixture(t, opts, func(w http.ResponseWriter, _ *http.Request, frame MCPFrame, _ int) {
				if sse {
					w.Header().Set("Content-Type", "text/event-stream")
					_, _ = io.WriteString(w, "data: ")
				}
				discoveryList(w, frame, headerStateDefs(headerStateSchema, headerStateWarning), "")
				if sse {
					_, _ = io.WriteString(w, "\n\n")
					w.(http.Flusher).Flush()
				}
			})
			status, body := f.call(t, "different", "first")
			if status != 400 || f.calls.Load() != 0 {
				t.Fatalf("warn disabled mirrors: %d %s", status, body)
			}
		})
	}
}

func TestHTTPListener_ContractDiscoveryCoalesces(t *testing.T) {
	entered := make(chan struct{})
	release := make(chan struct{})
	var once sync.Once
	defer once.Do(func() { close(release) })
	opts := paramContractOpts(t)
	var admitted atomic.Int32
	opts.ListenerPrincipalResolver = func(*http.Request) (ListenerPrincipal, error) {
		admitted.Add(1)
		return ListenerPrincipal{Provider: "test", Subject: "one"}, nil
	}
	f := newDiscoveryFixture(t, opts, func(w http.ResponseWriter, _ *http.Request, frame MCPFrame, _ int) {
		close(entered)
		<-release
		discoveryList(w, frame, headerStateDefs(headerStateSchema, "Echo input"), "")
	})
	const callers = 8
	done := make(chan int, callers)
	for range callers {
		go func() { status, _ := f.call(t, "body", "first"); done <- status }()
	}
	<-entered
	testwait.For(t, 2*time.Second, func() bool { return admitted.Load() >= callers }, "concurrent callers admitted")
	once.Do(func() { close(release) })
	for range callers {
		if status := <-done; status != 200 {
			t.Fatalf("status=%d", status)
		}
	}
	if f.lists.Load() != 1 || f.calls.Load() != callers {
		t.Fatalf("lists=%d calls=%d", f.lists.Load(), f.calls.Load())
	}
}

func TestHTTPListener_ContractDiscoveryPrincipalsAndAnonymous(t *testing.T) {
	for _, anonymous := range []bool{false, true} {
		t.Run(strconv.FormatBool(anonymous), func(t *testing.T) {
			opts := paramContractOpts(t)
			if anonymous {
				opts.ListenerBearerToken = ""
			} else {
				opts.ListenerPrincipalResolver = func(r *http.Request) (ListenerPrincipal, error) {
					return ListenerPrincipal{Provider: "test", Subject: r.Header.Get("Authorization")}, nil
				}
			}
			f := newDiscoveryFixture(t, opts, func(w http.ResponseWriter, r *http.Request, frame MCPFrame, _ int) {
				schema := headerStateSchema
				if strings.HasSuffix(r.Header.Get("Authorization"), "second") {
					schema = `{"type":"object"}`
				}
				discoveryList(w, frame, headerStateDefs(schema, "Echo input"), "")
			})
			if status, body := f.call(t, "different", "first"); status != 400 {
				t.Fatalf("first=%d %s", status, body)
			}
			if status, body := f.call(t, "", "second"); status != 200 {
				t.Fatalf("second=%d %s", status, body)
			}
			if status, body := f.call(t, "different", "first"); status != 400 {
				t.Fatalf("first reused second=%d %s", status, body)
			}
			want := int32(2)
			if anonymous {
				want = 3
			}
			if f.lists.Load() != want || f.calls.Load() != 1 {
				t.Fatalf("lists=%d calls=%d", f.lists.Load(), f.calls.Load())
			}
		})
	}
}

func TestHTTPListener_ContractDiscoveryPreservesSessionBinding(t *testing.T) {
	for _, binding := range []bool{false, true} {
		t.Run(strconv.FormatBool(binding), func(t *testing.T) {
			opts := paramContractOpts(t)
			if binding {
				opts.ToolCfg.BindingNoBaselineAction = config.ActionBlock
				opts.ToolCfg.BindingUnknownAction = config.ActionBlock
			}
			f := newDiscoveryFixture(t, opts, func(w http.ResponseWriter, _ *http.Request, frame MCPFrame, _ int) {
				discoveryList(w, frame, headerStateDefs(headerStateSchema, "Echo input"), "")
			})
			status, body := f.call(t, "body", "first")
			if binding {
				if f.calls.Load() != 0 || f.lists.Load() != 0 || !strings.Contains(body, "baseline") {
					t.Fatalf("binding bypass: %d %s", status, body)
				}
			} else if status != 200 || f.lists.Load() != 1 {
				t.Fatalf("status=%d %s", status, body)
			}
		})
	}
}

func TestHTTPListener_ContractDiscoveryLegacyUnchanged(t *testing.T) {
	f := newDiscoveryFixture(t, paramContractOpts(t), func(http.ResponseWriter, *http.Request, MCPFrame, int) { t.Error("legacy triggered discovery") })
	status, _, body := postWireContractRequest(t, f.url, `{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"echo","arguments":{}}}`, http.Header{"Proxy-Authorization": {headerStateBearer}})
	if status != 200 || f.calls.Load() != 1 || f.lists.Load() != 0 {
		t.Fatalf("status=%d body=%s lists=%d calls=%d", status, body, f.lists.Load(), f.calls.Load())
	}
}

// A server may omit x-mcp-header for older clients. That legacy inventory
// is delivered, but it must not stand in for the current contract: a modern
// call still discovers or keeps the annotated contract and refuses mirrors
// that disagree with the body.
func TestHTTPListener_ContractDiscoveryIgnoresLegacyInventory(t *testing.T) {
	for _, modernFirst := range []bool{false, true} {
		t.Run(fmt.Sprintf("modern_first=%v", modernFirst), func(t *testing.T) {
			f := newDiscoveryFixture(t, paramContractOpts(t), func(w http.ResponseWriter, r *http.Request, frame MCPFrame, _ int) {
				schema := headerStateSchema
				if r.Header.Get(listenerProtocolVersion) != currentMCPVersion {
					schema = `{"type":"object"}`
				}
				discoveryList(w, frame, headerStateDefs(schema, "Echo input"), "")
			})
			if modernFirst {
				h := currentWireHeaders("tools/list", "")
				h.Set("Proxy-Authorization", headerStateBearer)
				if status, _, body := postWireContractRequest(t, f.url, currentWireBody(1, "tools/list", ""), h); status != http.StatusOK {
					t.Fatalf("modern list status=%d body=%s", status, body)
				}
			}
			legacy := http.Header{"Proxy-Authorization": {headerStateBearer}, "Mcp-Protocol-Version": {"2025-11-25"}}
			if status, _, body := postWireContractRequest(t, f.url, `{"jsonrpc":"2.0","id":3,"method":"tools/list","params":{}}`, legacy); status != http.StatusOK {
				t.Fatalf("legacy list status=%d body=%s", status, body)
			}
			listed := f.lists.Load()
			for _, mirror := range []string{"different", ""} {
				if status, body := f.call(t, mirror, "first"); status != http.StatusBadRequest || f.calls.Load() != 0 {
					t.Fatalf("mirror %q: status=%d upstream=%d body=%s", mirror, status, f.calls.Load(), body)
				}
			}
			wantLists := listed
			if !modernFirst {
				wantLists++ // the legacy inventory left the contract unknown
			}
			if f.lists.Load() != wantLists {
				t.Fatalf("lists=%d want %d", f.lists.Load(), wantLists)
			}
			if status, body := f.call(t, "body", "first"); status != http.StatusOK || f.calls.Load() != 1 {
				t.Fatalf("matching call: status=%d upstream=%d body=%s", status, f.calls.Load(), body)
			}
		})
	}
}

// Pagination can repeat an unchanged definition on a later page. That is one
// contract, as for a client reading each page; a conflicting or same-page
// repeat cannot name one contract and is refused locally.
func TestHTTPListener_ContractDiscoveryRepeatedDefinitionAcrossPages(t *testing.T) {
	echo := `{"name":"echo","description":"Echo input","inputSchema":` + headerStateSchema + `}`
	sibling := func(schema string) string {
		return `{"name":"sibling","description":"Echo input","inputSchema":` + schema + `}`
	}
	for _, tc := range []struct {
		name, first, second string
		want                int
	}{
		{"identical", "[" + sibling(`{"type":"object"}`) + "]", "[" + sibling(`{"type":"object"}`) + "," + echo + "]", http.StatusOK},
		{"reordered keys", "[" + sibling(`{"type":"object","properties":{}}`) + "]", "[" + sibling(`{ "properties":{}, "type":"object" }`) + "," + echo + "]", http.StatusOK},
		{"conflicting", "[" + sibling(`{"type":"object"}`) + "]", "[" + sibling(headerStateSchema) + "," + echo + "]", http.StatusBadRequest},
		{"same page", "[" + sibling(`{"type":"object"}`) + "]", "[" + sibling(`{"type":"object"}`) + "," + sibling(`{"type":"object"}`) + "," + echo + "]", http.StatusBadRequest},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newDiscoveryFixture(t, paramContractOpts(t), func(w http.ResponseWriter, _ *http.Request, frame MCPFrame, n int) {
				if n == 1 {
					discoveryList(w, frame, tc.first, "page-2")
					return
				}
				discoveryList(w, frame, tc.second, "")
			})
			if status, body := f.call(t, "body", "first"); status != http.StatusOK || f.calls.Load() != 1 {
				t.Fatalf("echo status=%d upstream=%d body=%s", status, f.calls.Load(), body)
			}
			h := currentWireHeaders(methodToolsCall, "sibling")
			h.Set("Proxy-Authorization", headerStateBearer)
			status, _, body := postWireContractRequest(t, f.url, currentWireBody(3, methodToolsCall, `"name":"sibling","arguments":{}`), h)
			wantCalls := int32(1)
			if tc.want == http.StatusOK {
				wantCalls = 2
			} else {
				requireWireHeaderMismatch(t, status, body)
			}
			if status != tc.want || f.calls.Load() != wantCalls || f.lists.Load() != 2 {
				t.Fatalf("sibling status=%d upstream=%d lists=%d body=%s", status, f.calls.Load(), f.lists.Load(), body)
			}
		})
	}
}

// Discovery refuses after the input scan has written the call's allowed
// intent, so each refusal must close that intent as blocked.
func TestHTTPListener_ContractDiscoveryRefusalClosesIntent(t *testing.T) {
	for _, tc := range []struct {
		name, defs, mirror, reason string
		want                       int
	}{
		{"absent", `[]`, "", "tool_header_contract_unavailable", http.StatusServiceUnavailable},
		{"mismatch", headerStateDefs(headerStateSchema, "Echo input"), "different", "mcp_param_header_mismatch", http.StatusBadRequest},
		{"invalid", headerStateDefs(headerStateInvalid, "Echo input"), "", "tool_header_contract_invalid", http.StatusBadRequest},
		{"matching", headerStateDefs(headerStateSchema, "Echo input"), "body", "reason=complete", http.StatusOK},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newMCPDecisionReceiptHarness(t)
			opts := paramContractOpts(t)
			opts.InputCfg = newHTTPInputCfg(config.ActionBlock)
			opts.ReceiptEmitter, opts.V2ReceiptEmitter, opts.PolicyHash, opts.RequireReceipts = h.v1, h.v2, mcpTestPolicyHash, true
			f := newDiscoveryFixture(t, opts, func(w http.ResponseWriter, _ *http.Request, frame MCPFrame, _ int) {
				discoveryList(w, frame, tc.defs, "")
			})
			if status, body := f.call(t, tc.mirror, "first"); status != tc.want {
				t.Fatalf("status=%d body=%s", status, body)
			}
			if err := h.rec.Close(); err != nil {
				t.Fatal(err)
			}
			var intent, outcome *receipt.ActionRecord
			for _, r := range readActionReceipts(t, h.dir) {
				record := r.ActionRecord
				switch record.DecisionPhase {
				case receipt.DecisionPhaseIntent:
					intent = &record
				case receipt.DecisionPhaseOutcome:
					if outcome != nil {
						t.Fatal("more than one outcome")
					}
					outcome = &record
				}
			}
			if intent == nil || outcome == nil || outcome.ActionID != intent.ActionID || !strings.Contains(outcome.Pattern, tc.reason) {
				t.Fatalf("intent=%+v outcome=%+v", intent, outcome)
			}
			if tc.want != http.StatusOK && (outcome.Verdict != config.ActionBlock || outcome.Layer != mcpReceiptLayerHeaderContract || f.calls.Load() != 0) {
				t.Fatalf("refusal not recorded as blocked: %+v upstream=%d", outcome, f.calls.Load())
			}
		})
	}
}

func TestHTTPListener_ContractDiscoveryCancellation(t *testing.T) {
	entered := make(chan struct{})
	canceled := make(chan struct{})
	f := newDiscoveryFixture(t, paramContractOpts(t), func(_ http.ResponseWriter, r *http.Request, _ MCPFrame, _ int) {
		close(entered)
		<-r.Context().Done()
		close(canceled)
	})
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, f.url, currentWireBodyReader())
	req.Header = currentWireHeaders(methodToolsCall, "echo")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Proxy-Authorization", headerStateBearer)
	done := make(chan error, 1)
	go func() {
		resp, err := http.DefaultClient.Do(req)
		if resp != nil {
			_ = resp.Body.Close()
		}
		done <- err
	}()
	<-entered
	cancel()
	if err := <-done; err == nil {
		t.Fatal("canceled call succeeded")
	}
	select {
	case <-canceled:
	case <-time.After(testwait.Deadline(2 * time.Second)):
		t.Fatal("discovery outlived caller")
	}
	if f.calls.Load() != 0 {
		t.Fatal("canceled discovery executed call")
	}
}

func currentWireBodyReader() io.Reader {
	return strings.NewReader(currentWireBody(2, methodToolsCall, `"name":"echo","arguments":{"region":"body"}`))
}

// The drift and delivery registries must remain independent of structural
// observations, including a scan-clean internal discovery.
func TestContractDiscoveryDoesNotDeliverOrAdopt(t *testing.T) {
	baseline := tools.NewToolBaseline()
	drift := tools.NewToolBaseline()
	opts := paramContractOpts(t)
	opts.ToolCfg.Baseline = baseline
	opts.ToolCfg.DriftBaseline = drift
	opts.ToolCfg.DetectDrift = true
	state := newMCPListenerClientState("", "test")
	state.baseline = baseline
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		discoveryList(w, ParseMCPFrame([]byte(`{"id":1}`)), headerStateDefs(headerStateSchema, "Echo input"), "")
	}))
	defer up.Close()
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "http://proxy.vendor.example/", nil)
	req.Header = currentWireHeaders(methodToolsCall, "echo")
	err := discoverMCPToolContract(mcpContractDiscoveryRequest{request: req, client: up.Client(), upstream: up.URL, opts: opts, state: state, log: io.Discard, tool: "echo"})
	if err != nil {
		t.Fatal(err)
	}
	if baseline.HasBaseline() || baseline.IsKnownTool("echo") || drift.HasDriftBaseline() {
		t.Fatal("discovery became delivery or drift approval")
	}
	if baseline.HeaderContract("echo").State != tools.HeaderContractValidWithBindings {
		t.Fatal("discovery did not establish structural contract")
	}
}

func TestHTTPListener_ContractDiscoveryListOrdering(t *testing.T) {
	entered := make(chan struct{})
	release := make(chan struct{})
	var once sync.Once
	defer once.Do(func() { close(release) })
	admitted := make(chan struct{})
	opts := paramContractOpts(t)
	opts.ListenerPrincipalResolver = func(r *http.Request) (ListenerPrincipal, error) {
		if r.Header.Get(listenerMCPMethod) == "tools/list" {
			close(admitted)
		}
		return ListenerPrincipal{Provider: "test", Subject: "one"}, nil
	}
	f := newDiscoveryFixture(t, opts, func(w http.ResponseWriter, _ *http.Request, frame MCPFrame, n int) {
		if n == 1 {
			close(entered)
			<-release
			discoveryList(w, frame, headerStateDefs(`{"type":"object"}`, "Echo input"), "")
		} else {
			discoveryList(w, frame, headerStateDefs(headerStateSchema, "Echo input"), "")
		}
	})
	callDone := make(chan int, 1)
	go func() { status, _ := f.call(t, "different", "first"); callDone <- status }()
	<-entered
	listDone := make(chan int, 1)
	go func() {
		h := currentWireHeaders("tools/list", "")
		h.Set("Proxy-Authorization", headerStateBearer)
		status, _, _ := postWireContractRequest(t, f.url, currentWireBody(3, "tools/list", ""), h)
		listDone <- status
	}()
	<-admitted
	once.Do(func() { close(release) })
	if status := <-listDone; status != 200 {
		t.Fatalf("list status=%d", status)
	}
	<-callDone // The first call may compare before the queued list takes the lock.
	before := f.calls.Load()
	if status, body := f.call(t, "different", "first"); status != 400 || f.calls.Load() != before {
		t.Fatalf("stale discovery replaced newer list: %d %s", status, body)
	}
	if f.lists.Load() != 2 {
		t.Fatalf("lists=%d", f.lists.Load())
	}
}

type contractWaitBody struct {
	io.ReadCloser
	read chan struct{}
	once sync.Once
}

func (b *contractWaitBody) Read(p []byte) (int, error) {
	n, err := b.ReadCloser.Read(p)
	if errors.Is(err, io.EOF) {
		b.once.Do(func() { close(b.read) })
	}
	return n, err
}

type contractWaitLog struct {
	refused chan struct{}
	once    sync.Once
}

func (l *contractWaitLog) Write(p []byte) (int, error) {
	if strings.Contains(string(p), "request ended while waiting for tool contract state") {
		l.once.Do(func() { close(l.refused) })
	}
	return len(p), nil
}

func TestHTTPListener_HeaderContractCanceledLockWait(t *testing.T) {
	for _, method := range []string{methodToolsCall, "tools/list"} {
		t.Run(method, func(t *testing.T) {
			entered := make(chan struct{})
			release := make(chan struct{})
			var once sync.Once
			defer once.Do(func() { close(release) })
			var lists, calls atomic.Int32
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				body, _ := io.ReadAll(r.Body)
				frame := ParseMCPFrame(body)
				if frame.Method != "tools/list" {
					calls.Add(1)
					return
				}
				n := lists.Add(1)
				if n == 2 {
					close(entered)
					<-release
				}
				discoveryList(w, frame, headerStateDefs(headerStateSchema, "Echo input"), "")
			}))
			t.Cleanup(upstream.Close)
			waiting := make(chan struct{})
			opts := paramContractOpts(t)
			opts.ListenerBearerToken = ""
			opts.ListenerPrincipalResolver = func(r *http.Request) (ListenerPrincipal, error) {
				if r.Header.Get("X-Test-Waiter") == "yes" {
					r.Body = &contractWaitBody{ReadCloser: r.Body, read: waiting}
				}
				return ListenerPrincipal{Provider: "test", Subject: "one"}, nil
			}
			ln, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			ctx, stop := context.WithCancel(t.Context())
			defer stop()
			log := &contractWaitLog{refused: make(chan struct{})}
			stopped := make(chan error, 1)
			go func() { stopped <- RunHTTPListenerProxy(ctx, ln, upstream.URL, log, opts) }()
			baseURL := "http://" + ln.Addr().String()
			waitForHTTPHealth(t, baseURL)
			t.Cleanup(func() { once.Do(func() { close(release) }); stop(); waitForListenerProxyStop(t, stopped) })
			h0 := currentWireHeaders("tools/list", "")
			if status, _, body := postWireContractRequest(t, baseURL, currentWireBody(0, "tools/list", ""), h0); status != 200 {
				t.Fatalf("seed list status=%d body=%s", status, body)
			}
			listDone := make(chan int, 1)
			go func() {
				h := currentWireHeaders("tools/list", "")

				status, _, _ := postWireContractRequest(t, baseURL, currentWireBody(1, "tools/list", ""), h)
				listDone <- status
			}()
			<-entered
			h := currentWireHeaders(method, "")
			params := ""
			if method == methodToolsCall {
				h.Set(listenerMCPName, "echo")
				params = `"name":"echo","arguments":{}`
			}

			h.Set("X-Test-Waiter", "yes")
			h.Set("Content-Type", "application/json")
			waiterCtx, cancel := context.WithCancel(t.Context())
			defer cancel()
			req, _ := http.NewRequestWithContext(waiterCtx, http.MethodPost, baseURL, strings.NewReader(currentWireBody(2, method, params)))
			req.Header = h
			done := make(chan error, 1)
			go func() {
				resp, err := http.DefaultClient.Do(req)
				if resp != nil {
					_ = resp.Body.Close()
				}
				done <- err
			}()
			<-waiting
			cancel()
			if err := <-done; err == nil {
				t.Fatal("canceled waiter succeeded")
			}
			select {
			case <-log.refused:
			case <-time.After(testwait.Deadline(2 * time.Second)):
				t.Fatal("handler did not take contract-wait 503 refusal path")
			}
			if calls.Load() != 0 || lists.Load() != 2 {
				t.Fatalf("canceled waiter reached upstream: lists=%d calls=%d", lists.Load(), calls.Load())
			}
			once.Do(func() { close(release) })
			if status := <-listDone; status != 200 {
				t.Fatalf("held list status=%d", status)
			}
		})
	}
}

func TestHTTPListener_ContractDiscoveryTimeout(t *testing.T) {
	canceled := make(chan struct{})
	f := newDiscoveryFixture(t, paramContractOpts(t), func(_ http.ResponseWriter, r *http.Request, _ MCPFrame, _ int) { <-r.Context().Done(); close(canceled) })
	status, body := f.call(t, "body", "first")
	if status != 503 || f.calls.Load() != 0 || !strings.Contains(body, "upstream discovery request failed") {
		t.Fatalf("timeout status=%d calls=%d body=%s", status, f.calls.Load(), body)
	}
	select {
	case <-canceled:
	case <-time.After(testwait.Deadline(2 * time.Second)):
		t.Fatal("timed out discovery still running")
	}
}

func TestContractDiscoveryCannotOverwriteKnownSiblingOrRevokedState(t *testing.T) {
	for _, revoked := range []bool{false, true} {
		t.Run(strconv.FormatBool(revoked), func(t *testing.T) {
			state := newMCPListenerClientState("", "test")
			if err := state.baseline.SetToolHeaderBindings([]tools.ToolDef{{Name: "sibling", InputSchema: json.RawMessage(headerStateInvalid)}}); err != nil {
				t.Fatal(err)
			}
			opts := paramContractOpts(t)
			up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				if revoked {
					state.revoke()
				}
				// A valid sibling on this private list must not erase a rejection
				// already established by a client-visible definition.
				discoveryList(w, ParseMCPFrame([]byte(`{"id":1}`)), headerStateDefs(headerStateSchema, "Echo input"), "")
			}))
			defer up.Close()
			req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "http://proxy.vendor.example/", nil)
			req.Header = currentWireHeaders(methodToolsCall, "echo")
			err := discoverMCPToolContract(mcpContractDiscoveryRequest{request: req, client: up.Client(), upstream: up.URL, opts: opts, state: state, log: io.Discard, tool: "echo"})
			if revoked {
				if err == nil || state.baseline.HeaderContract("echo").State != tools.HeaderContractUnknown {
					t.Fatalf("revoked completion committed: %v", err)
				}
			} else if err != nil {
				t.Fatal(err)
			}
			if state.baseline.HeaderContract("sibling").State != tools.HeaderContractInvalid {
				t.Fatal("discovery replaced a known sibling rejection")
			}
		})
	}
}

// Done exposes that a follower has actually entered the flight wait, avoiding
// scheduler timing as evidence of coalescing failed discoveries.
type discoveryWaitContext struct {
	context.Context
	entered chan struct{}
	once    sync.Once
}

func (c *discoveryWaitContext) Done() <-chan struct{} {
	c.once.Do(func() { close(c.entered) })
	return c.Context.Done()
}

func TestContractDiscoveryCoalescesFailureAndFollowerCancellation(t *testing.T) {
	for _, cancelFollower := range []bool{false, true} {
		t.Run(strconv.FormatBool(cancelFollower), func(t *testing.T) {
			state := newMCPListenerClientState("", "one")
			entered := make(chan struct{})
			release := make(chan struct{})
			var calls atomic.Int32
			var enteredOnce sync.Once
			failure := fmt.Errorf("discovery refused")
			discover := func() error {
				calls.Add(1)
				enteredOnce.Do(func() { close(entered) })
				<-release
				return failure
			}
			leader := make(chan error, 1)
			go func() { _, err := state.acquireToolContract(t.Context(), "echo", discover); leader <- err }()
			<-entered
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			observed := &discoveryWaitContext{Context: ctx, entered: make(chan struct{})}
			follower := make(chan error, 1)
			go func() { _, err := state.acquireToolContract(observed, "echo", discover); follower <- err }()
			<-observed.entered
			if cancelFollower {
				cancel()
				if err := <-follower; !errors.Is(err, context.Canceled) {
					t.Fatalf("follower cancellation=%v", err)
				}
			}
			close(release)
			if err := <-leader; !errors.Is(err, failure) {
				t.Fatalf("leader=%v", err)
			}
			if !cancelFollower {
				if err := <-follower; !errors.Is(err, failure) {
					t.Fatalf("follower=%v", err)
				}
			}
			if calls.Load() != 1 {
				t.Fatalf("discoveries=%d", calls.Load())
			}
		})
	}
}

// A follower must not inherit a failure that says nothing about its own tool:
// another tool's absence, or the initiating request ending. It retries and
// establishes its own contract instead of being refused.
func TestContractDiscoveryFollowerRetriesUnrelatedFailure(t *testing.T) {
	for _, tc := range []struct {
		name         string
		leaderTool   string
		cancelLeader bool
	}{
		{"different-tool-absent", "missing", false},
		{"same-tool-leader-canceled", "echo", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			state := newMCPListenerClientState("", "one")
			entered, release := make(chan struct{}), make(chan struct{})
			leaderCtx, cancelLeader := context.WithCancel(t.Context())
			defer cancelLeader()
			leaderDiscover := func() error {
				close(entered)
				select {
				case <-release:
				case <-leaderCtx.Done():
					return leaderCtx.Err()
				}
				return errors.New("tool absent from complete discovery inventory")
			}
			leader := make(chan error, 1)
			go func() { _, err := state.acquireToolContract(leaderCtx, tc.leaderTool, leaderDiscover); leader <- err }()
			<-entered
			observed := &discoveryWaitContext{Context: t.Context(), entered: make(chan struct{})}
			followerDiscovered := false
			follower := make(chan error, 1)
			go func() {
				release, err := state.acquireToolContract(observed, "echo", func() error {
					followerDiscovered = true
					return state.baseline.SetToolHeaderBindings([]tools.ToolDef{{Name: "echo"}})
				})
				if release != nil {
					release()
				}
				follower <- err
			}()
			<-observed.entered
			if tc.cancelLeader {
				cancelLeader()
			} else {
				close(release)
			}
			t.Logf("goroutine result: %v", <-leader)
			err := <-follower
			if err != nil || !followerDiscovered {
				t.Fatalf("follower inherited an unrelated failure: err=%v discovered=%v", err, followerDiscovered)
			}
		})
	}
}

func TestContractDiscoveryOrdersQueuedClientInventory(t *testing.T) {
	state := newMCPListenerClientState("", "one")
	entered := make(chan struct{})
	release := make(chan struct{})
	done := make(chan tools.HeaderContractState, 1)
	go func() {
		unlock, err := state.acquireToolContract(t.Context(), "echo", func() error {
			close(entered)
			<-release
			return state.baseline.SetToolHeaderBindings([]tools.ToolDef{{Name: "echo", InputSchema: json.RawMessage(`{"type":"object"}`)}})
		})
		if err != nil {
			t.Error(err)
			done <- tools.HeaderContractUnknown
			return
		}
		defer unlock()
		done <- state.baseline.HeaderContract("echo").State
	}()
	<-entered
	listDone := make(chan struct{})
	go func() {
		if err := state.contractMu.Lock(t.Context()); err != nil {
			t.Error(err)
			return
		}
		defer state.contractMu.Unlock()
		if err := state.baseline.SetToolHeaderBindings([]tools.ToolDef{{Name: "echo", InputSchema: json.RawMessage(headerStateSchema)}}); err != nil {
			t.Error(err)
		}
		close(listDone)
	}()
	testwait.For(t, time.Second, func() bool {
		state.contractMu.mu.Lock()
		defer state.contractMu.mu.Unlock()
		return state.contractMu.waitingWriters == 1
	}, "newer client list queued")
	close(release)
	<-listDone
	if got := <-done; got != tools.HeaderContractValidWithBindings {
		t.Fatalf("older discovery selected over queued client list: %v", got)
	}
}

func TestContractDiscoveryRechecksClientInventoryBeforeFetching(t *testing.T) {
	state := newMCPListenerClientState("", "one")
	if err := state.contractMu.Lock(t.Context()); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		unlock, err := state.acquireToolContract(t.Context(), "echo", func() error {
			t.Error("discovery fetched after client list established the contract")
			return errors.New("unexpected fetch")
		})
		if unlock != nil {
			unlock()
		}
		done <- err
	}()
	testwait.For(t, time.Second, func() bool {
		state.contractMu.mu.Lock()
		defer state.contractMu.mu.Unlock()
		return state.contractMu.waitingWriters == 1
	}, "discovery queued behind client list")
	if err := state.baseline.SetToolHeaderBindings([]tools.ToolDef{{Name: "echo", InputSchema: json.RawMessage(headerStateSchema)}}); err != nil {
		t.Fatal(err)
	}
	state.contractMu.Unlock()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestContractDiscoveryCanceledAcquisition(t *testing.T) {
	for _, known := range []bool{false, true} {
		t.Run(strconv.FormatBool(known), func(t *testing.T) {
			state := newMCPListenerClientState("", "one")
			if known {
				if err := state.baseline.SetToolHeaderBindings([]tools.ToolDef{{Name: "echo"}}); err != nil {
					t.Fatal(err)
				}
			}
			if err := state.contractMu.Lock(t.Context()); err != nil {
				t.Fatal(err)
			}
			defer state.contractMu.Unlock()
			ctx, cancel := context.WithCancel(t.Context())
			cancel()
			unlock, err := state.acquireToolContract(ctx, "echo", func() error { t.Error("canceled acquisition fetched"); return nil })
			if unlock != nil || !errors.Is(err, context.Canceled) {
				t.Fatalf("canceled acquisition returned hold=%v error=%v", unlock != nil, err)
			}
		})
	}
}

func TestContractDiscoveryDoesNotResolveHeldInventory(t *testing.T) {
	for _, blocked := range []bool{false, true} {
		t.Run(strconv.FormatBool(blocked), func(t *testing.T) {
			manager := deferred.NewManager(deferred.Config{Enabled: true, Timeout: time.Hour})
			defer manager.ResolveAll(config.ActionBlock, deferred.SourceContext)
			if err := manager.Hold(deferred.HeldAction{
				DeferID: "held", ActionID: "held", Target: "tool", SizeBytes: 1,
				Authority:  deferred.AuthoritySnapshot{SessionID: "mcp"},
				RulePolicy: config.DeferResolutionPolicy{AllowOn: config.DeferAllowOn{ToolInventoryBaseline: true}},
				Resolve:    func(deferred.Resolution) {},
			}); err != nil {
				t.Fatal(err)
			}
			opts := paramContractOpts(t)
			opts.DeferManagerFn = func() *deferred.Manager { return manager }
			opts.ToolCfg.DetectDrift = true
			state := newMCPListenerClientState("", "one")
			up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				description := "Echo input"
				if blocked {
					description = headerStateWarning
				}
				discoveryList(w, ParseMCPFrame([]byte(`{"id":1}`)), headerStateDefs(headerStateSchema, description), "")
			}))
			defer up.Close()
			req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "http://proxy.vendor.example/", nil)
			req.Header = currentWireHeaders(methodToolsCall, "echo")
			err := discoverMCPToolContract(mcpContractDiscoveryRequest{request: req, client: up.Client(), upstream: up.URL, opts: opts, state: state, log: io.Discard, tool: "echo"})
			if (err != nil) != blocked {
				t.Fatalf("blocked=%v discovery error=%v", blocked, err)
			}
			if _, ok := manager.Held("held"); !ok {
				t.Fatal("private discovery resolved inventory approval")
			}
		})
	}
}

func TestContractDiscoveryPageInspectionFailures(t *testing.T) {
	for _, mode := range []string{"invalid URL", "network", "byte budget", "identity changed", "notification then response", "broken compression", "bad cursor"} {
		t.Run(mode, func(t *testing.T) {
			opts := paramContractOpts(t)
			up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				if mode == "broken compression" {
					w.Header().Set("Content-Encoding", "gzip")
					_, _ = io.WriteString(w, "broken")
					return
				}
				if mode == "notification then response" {
					w.Header().Set("Content-Type", "text/event-stream")
					_, _ = io.WriteString(w, "data: {\"jsonrpc\":\"2.0\",\"method\":\"notifications/tools/list_changed\"}\n\ndata: ")
				}
				if mode == "bad cursor" {
					_, _ = io.WriteString(w, `{"jsonrpc":"2.0","id":1,"result":{"tools":[],"nextCursor":42}}`)
					return
				}
				discoveryList(w, ParseMCPFrame([]byte(`{"id":1}`)), headerStateDefs(headerStateSchema, "Echo input"), "")
				if mode == "notification then response" {
					_, _ = io.WriteString(w, "\n\n")
				}
			}))
			defer up.Close()
			state := newMCPListenerClientState("", "one")
			req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "http://proxy.vendor.example/", nil)
			req.Header = currentWireHeaders(methodToolsCall, "echo")
			d := mcpContractDiscoveryRequest{request: req, client: up.Client(), upstream: up.URL, opts: opts, state: state, log: io.Discard, tool: "echo"}
			remaining := transport.MaxLineSize
			switch mode {
			case "invalid URL":
				d.upstream = ":"
			case "network":
				up.Close()
			case "byte budget":
				remaining = 1
			case "identity changed":
				d.opts.ServerIdentityFn = func() ServerIdentity { return ServerIdentity{Refusal: "registration removed"} }
			}
			if mode == "bad cursor" {
				if err := discoverMCPToolContract(d); err == nil {
					t.Fatal("unreadable pagination treated as complete")
				}
				return
			}
			_, err := d.page(t.Context(), nil, &remaining)
			if mode == "notification then response" {
				if err != nil {
					t.Fatal(err)
				}
			} else if err == nil {
				t.Fatalf("%s was accepted", mode)
			}
		})
	}
}

func TestContractDiscoveryCanceledAtStructuralCommit(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	opts := paramContractOpts(t)
	checks := 0
	opts.ServerIdentityFn = func() ServerIdentity {
		checks++
		if checks == 2 {
			// The final output-identity check runs after response inspection.
			// Cancellation here must still prevent structural admission.
			cancel()
		}
		return ServerIdentity{}
	}
	state := newMCPListenerClientState("", "one")
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		discoveryList(w, ParseMCPFrame([]byte(`{"id":1}`)), headerStateDefs(headerStateSchema, "Echo input"), "")
	}))
	defer up.Close()
	req := httptest.NewRequestWithContext(ctx, http.MethodPost, "http://proxy.vendor.example/", nil)
	req.Header = currentWireHeaders(methodToolsCall, "echo")
	err := discoverMCPToolContract(mcpContractDiscoveryRequest{request: req, client: up.Client(), upstream: up.URL, opts: opts, state: state, log: io.Discard, tool: "echo"})
	if checks != 2 || !errors.Is(err, context.Canceled) || state.baseline.HeaderContract("echo").State != tools.HeaderContractUnknown {
		t.Fatalf("canceled completion: checks=%d error=%v contract=%v", checks, err, state.baseline.HeaderContract("echo").State)
	}
}

// MCP pagination requires treating even an empty cursor as an opaque token.
func TestHTTPListener_ContractDiscoveryEmptyCursor(t *testing.T) {
	for _, mismatch := range []bool{false, true} {
		t.Run(strconv.FormatBool(mismatch), func(t *testing.T) {
			f := newDiscoveryFixture(t, paramContractOpts(t), func(w http.ResponseWriter, _ *http.Request, frame MCPFrame, n int) {
				if n == 1 {
					_, _ = fmt.Fprintf(w, `{"jsonrpc":"2.0","id":%s,"result":{"tools":[{"name":"filler","inputSchema":{"type":"object"}}],"nextCursor":""}}`, frame.ID)
					return
				}
				var request struct {
					Params map[string]json.RawMessage `json:"params"`
				}
				if err := json.Unmarshal(frame.Raw, &request); err != nil {
					t.Error(err)
				}
				if string(request.Params["cursor"]) != `""` {
					t.Errorf("empty cursor lost: %s", frame.Raw)
				}
				discoveryList(w, frame, headerStateDefs(headerStateSchema, "Echo input"), "")
			})
			mirror, want := "body", http.StatusOK
			if mismatch {
				mirror, want = "different", http.StatusBadRequest
			}
			status, body := f.call(t, mirror, "first")
			if status != want || f.lists.Load() != 2 {
				t.Fatalf("status=%d lists=%d body=%s", status, f.lists.Load(), body)
			}
			if mismatch && f.calls.Load() != 0 {
				t.Fatal("mismatching call forwarded")
			}
		})
	}
}
