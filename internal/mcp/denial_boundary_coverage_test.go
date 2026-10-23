// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/audit"
	"github.com/luckyPipewrench/pipelock/internal/deferred"
	"github.com/luckyPipewrench/pipelock/internal/mcp/transport"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
	"github.com/luckyPipewrench/pipelock/internal/testwait"
)

func TestMCPDeniedReplyRevocationGates(t *testing.T) {
	for _, gate := range []string{"identity", "session"} {
		for _, revoked := range []bool{false, true} {
			name := gate + "/active"
			if revoked {
				name = gate + "/revoked"
			}
			t.Run(name, func(t *testing.T) {
				logger, events := newListenerEventLogger(t)
				opts := MCPProxyOpts{AuditLogger: logger}
				var out bytes.Buffer
				var writer transport.MessageWriter = transport.NewStdioWriter(&out)
				if gate == "identity" {
					admitted := ServerIdentity{Name: "local-tools", Revision: "revision"}
					opts.ServerIdentityFn = func() ServerIdentity {
						if revoked {
							return ServerIdentity{Refusal: "registration revoked"}
						}
						return admitted
					}
					opts = opts.withServerIdentity(admitted)
					writer = &serverIdentityMessageWriter{writer: writer, opts: opts}
				} else {
					state := &mcpListenerClientState{}
					if revoked {
						state.revoke()
					}
					writer = &listenerStateMessageWriter{writer: writer, state: state, opts: opts}
				}
				reply := []byte(`{"jsonrpc":"2.0","id":91,"error":{"code":-32002,"message":"media refused"}}`)
				err := writeMCPDenial(opts, mcpMediaPolicyDenialAudit(), writer, reply)
				if revoked {
					if err == nil || !mcpDenialWasFinalized(err) || out.Len() != 0 {
						t.Fatalf("revoked writer: err=%v reply=%s", err, out.String())
					}
					if gate == "session" && !errors.Is(err, context.Canceled) {
						t.Fatalf("revoked session: %v", err)
					}
				} else if err != nil || strings.TrimSpace(out.String()) != string(reply) {
					t.Fatalf("active writer: err=%v reply=%s", err, out.String())
				}
				// Failure to deliver an already-denied reply must not become a second block.
				assertDenialRoute(t, events.String(), scanner.AuditMediaPolicy, audit.BlockClassProtective, "[redacted]", "response")
			})
		}
	}
}

func TestMCPListenerDecisionClassificationWire(t *testing.T) {
	for _, tc := range []struct{ name, layer, label string }{
		{"contract", mcpContractReceiptLayer, scanner.AuditContract},
		{"a2a", mcpReceiptLayerA2A, scanner.AuditA2AScan},
		{"admission", "", scanner.AuditMCPProtocol},
	} {
		t.Run(tc.name, func(t *testing.T) {
			logger, events := newListenerEventLogger(t)
			descriptor := mcpListenerBlockAudit(mcpListenerBlockDecision{layer: tc.layer})
			recorder := httptest.NewRecorder()
			writer := &mcpListenerDenialWriter{ResponseWriter: recorder, opts: MCPProxyOpts{AuditLogger: logger}, descriptor: &descriptor}
			reply := `{"jsonrpc":"2.0","id":92,"error":{"code":-32002,"message":"admission refused"}}`
			writer.WriteHeader(http.StatusForbidden)
			if _, err := io.WriteString(writer, reply); err != nil {
				t.Fatal(err)
			}
			if recorder.Code != http.StatusForbidden || recorder.Body.String() != reply {
				t.Fatalf("status=%d reply=%s", recorder.Code, recorder.Body.String())
			}
			assertDenialRoute(t, events.String(), tc.label, audit.BlockClassProtective, mcpResourceListener, "input")
		})
	}
}

func TestMCPDeferredReceiptFailureClassificationWire(t *testing.T) {
	logger, events := newListenerEventLogger(t)
	opts := MCPProxyOpts{AuditLogger: logger}
	descriptor := mcpDeferredDenialAudit(deferred.Resolution{Reason: deferred.ReasonReceiptNotWritten})
	blocked := inputMCPDenial(opts, descriptor, &BlockedRequest{ID: []byte(`93`), ErrorCode: -32002, ErrorMessage: "receipt refused"})
	recorder := httptest.NewRecorder()
	writeMCPHTTPInputResult(opts, *blocked, recorder)
	if recorder.Code != http.StatusOK || !strings.Contains(recorder.Body.String(), `"id":93`) || !strings.Contains(recorder.Body.String(), `"code":-32002`) || strings.Contains(recorder.Body.String(), `"result"`) {
		t.Fatalf("status=%d reply=%s", recorder.Code, recorder.Body.String())
	}
	assertDenialRoute(t, events.String(), scanner.AuditReceiptEmission, audit.BlockClassInfrastructureError, mcpResourceInput, "input")
}

func TestMCPListenerIdentityRevokedBeforeFinalCommit(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), testwait.Deadline(5*time.Second))
	defer cancel()
	var changed atomic.Bool
	var calls atomic.Int32
	logger, events := newListenerEventLogger(t)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, identityUpstreamOK)
	}))
	defer upstream.Close()
	baseURL, _ := startListenerProxyWithOpts(t, upstream.URL, MCPProxyOpts{
		Scanner: testScannerForHTTP(t), AuditLogger: logger,
		ServerIdentityFn: func() ServerIdentity {
			if changed.Load() {
				return ServerIdentity{Refusal: identityRefusalText}
			}
			// Admission, pre-scan and per-message output precede the final check.
			if calls.Add(1) == 3 {
				// Return the admitted snapshot, then model revocation immediately
				// after that output check, before the final response commit.
				changed.Store(true)
			}
			return ServerIdentity{Name: "local-tools", Revision: "revision"}
		},
	})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, baseURL+"/", strings.NewReader(jsonToolsCallEcho))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusBadGateway || !strings.Contains(string(body), `"id":1`) || !strings.Contains(string(body), `"error"`) || strings.Contains(string(body), `"result"`) {
		t.Fatalf("status=%d reply=%s", resp.StatusCode, body)
	}
	assertDenialRoute(t, events.String(), scanner.AuditAgentIdentity, audit.BlockClassProtective, mcpResourceInput, "response")
}

func TestMCPInputClassificationCompatibilityWire(t *testing.T) {
	for _, tc := range []struct{ name, label, wantLabel, wantClass string }{
		{"default_threat_class", scanner.AuditMCPInputDLP, scanner.AuditMCPInputDLP, audit.BlockClassThreat},
		{"unregistered_finding", "unregistered_input_finding", scanner.AuditScannerUnavailable, audit.BlockClassInfrastructureError},
	} {
		t.Run(tc.name, func(t *testing.T) {
			logger, events := newListenerEventLogger(t)
			opts := MCPProxyOpts{AuditLogger: logger}
			// Exercise the classifier's compatibility contract: an omitted class uses
			// threat, while an unregistered finding retains a fail-closed delivery.
			descriptor := mcpInputGateBlockAudit(tc.label, "", "")
			blocked := inputMCPDenial(opts, descriptor, &BlockedRequest{ID: []byte(`94`), ErrorCode: -32002, ErrorMessage: "input refused"})
			recorder := httptest.NewRecorder()
			writeMCPHTTPInputResult(opts, *blocked, recorder)
			if recorder.Code != http.StatusOK || !strings.Contains(recorder.Body.String(), `"id":94`) || !strings.Contains(recorder.Body.String(), `"code":-32002`) || strings.Contains(recorder.Body.String(), `"result"`) {
				t.Fatalf("status=%d reply=%s", recorder.Code, recorder.Body.String())
			}
			assertDenialRoute(t, events.String(), tc.wantLabel, tc.wantClass, mcpResourceInput, "input")
			if tc.name == "default_threat_class" && !strings.Contains(events.String(), `"reason":"`+scanner.AuditMCPInputDLP+`"`) {
				t.Fatal(events.String())
			}
		})
	}
}
