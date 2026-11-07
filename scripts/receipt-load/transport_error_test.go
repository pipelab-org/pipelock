// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"reflect"
	"strings"
	"syscall"
	"testing"
	"time"
	"unicode/utf8"
)

func TestClassifyTransportError(t *testing.T) {
	for _, tt := range []struct {
		name string
		err  error
		want string
	}{
		{"deadline", context.DeadlineExceeded, "timeout"},
		{"wrapped deadline", fmt.Errorf("request: %w", context.DeadlineExceeded), "timeout"},
		{"network timeout", &net.DNSError{IsTimeout: true}, "timeout"},
		{"wrapped network timeout", &url.Error{Op: "Get", URL: "http://one.load.example", Err: &net.DNSError{IsTimeout: true}}, "timeout"},
		{"refused", &net.OpError{Op: "dial", Err: os.NewSyscallError("connect", syscall.ECONNREFUSED)}, "connection_refused"},
		{"reset", &url.Error{Op: "Get", URL: "http://two.load.example", Err: syscall.ECONNRESET}, "connection_reset"},
		{"eof", io.EOF, "eof"},
		{"unexpected eof", fmt.Errorf("read: %w", io.ErrUnexpectedEOF), "eof"},
		{"canceled", context.Canceled, "other"},
		{"other", errors.New("unrecognized failure"), "other"},
		{"text is not a class", errors.New("timeout: connection refused: EOF"), "other"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if got := classifyTransportError(tt.err); got != tt.want {
				t.Fatalf("class = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestIssueTransportErrors(t *testing.T) {
	plan := newWorkload(3, 0, 1)
	for _, tt := range []struct {
		name  string
		setup func(*testing.T) loadParams
		kind  string
		text  string
	}{
		{
			name: "client timeout",
			setup: func(t *testing.T) loadParams {
				p := directParams(t, plan, http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
					// Delay headers until the client times out. Cancellation releases
					// the handler without making server shutdown wait for the timer.
					select {
					case <-time.After(time.Second):
					case <-r.Context().Done():
					}
				}))
				p.client.Timeout = 50 * time.Millisecond
				return p
			},
			kind: "timeout", text: "Client.Timeout exceeded while awaiting headers",
		},
		{
			name: "connection refused",
			setup: func(t *testing.T) loadParams {
				listener, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", "127.0.0.1:0")
				if err != nil {
					t.Fatal(err)
				}
				addr := listener.Addr().String()
				if err := listener.Close(); err != nil {
					t.Fatal(err)
				}
				return loadParams{client: &http.Client{Transport: &http.Transport{Proxy: nil}, Timeout: time.Second}, plan: plan, sinkAddr: addr}
			},
			kind: "connection_refused", text: "connection refused",
		},
		{
			name: "eof",
			setup: func(t *testing.T) loadParams {
				return directParams(t, plan, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
					conn, _, err := w.(http.Hijacker).Hijack()
					if err != nil {
						t.Error(err)
						return
					}
					_ = conn.Close()
				}))
			},
			kind: "eof", text: "EOF",
		},
		{
			name: "invalid request",
			setup: func(_ *testing.T) loadParams {
				return loadParams{plan: plan, sinkAddr: "invalid\x7f.load.example"}
			},
			kind: "other", text: "invalid control character",
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			p := tt.setup(t)
			out, _ := p.issue(context.Background(), plan.slot(phaseMeasure, 0), time.Now())
			if !out.ran || !out.transportErr || out.transportErrKind != tt.kind || !strings.Contains(out.transportErrText, tt.text) {
				t.Fatalf("outcome = %+v, want %s containing %q", out, tt.kind, tt.text)
			}
			if out.status != 0 || out.bodyReadErr || len(out.transportErrText) > 300 {
				t.Fatalf("transport failure accounting = %+v", out)
			}
		})
	}
}

func TestTransportErrorTextLimit(t *testing.T) {
	for _, tt := range []struct{ name, text, want string }{
		{"short", "failure", "failure"},
		{"boundary", strings.Repeat("a", 300), strings.Repeat("a", 300)},
		{"long", strings.Repeat("a", 301), strings.Repeat("a", 300)},
		{"partial rune", strings.Repeat("a", 299) + "é", strings.Repeat("a", 299)},
		{"invalid utf8", "failure\xff", "failure\uFFFD"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			var out requestOutcome
			out.setTransportError(errors.New(tt.text))
			if out.transportErrText != tt.want || !utf8.ValidString(out.transportErrText) {
				t.Fatalf("text = %q, want %q", out.transportErrText, tt.want)
			}
		})
	}
}

func TestTransportErrorAggregation(t *testing.T) {
	for _, after := range []int{0, 4, 10} {
		t.Run(fmt.Sprintf("restart_after_%d", after), func(t *testing.T) {
			plan := newWorkload(3, 7, 18)
			phase, err := measuredPhases(options{requests: plan.measured, restartAfter: after}, func(offset, count int) phaseResult {
				p := phaseResult{outcomes: make([]requestOutcome, count), samples: map[int]string{0: "body"}, elapsed: time.Second}
				for i := range p.outcomes {
					index := offset + i
					out := requestOutcome{ran: true, status: http.StatusOK, doneAtNS: int64(count - i)}
					if index%3 != 0 {
						failure := context.DeadlineExceeded
						if index%3 == 2 {
							failure = syscall.ECONNRESET
						}
						out.status = 0
						out.setTransportError(fmt.Errorf("request %d: %w", index, failure))
					}
					p.outcomes[i] = out
				}
				return p
			}, func() error { return nil })
			if err != nil {
				t.Fatal(err)
			}
			got := summarizeMeasured(plan, phase, time.Second, phase.samples)
			wantKinds := map[string]int{"timeout": 6, "connection_reset": 6}
			if got.Errors != 12 || got.StatusCounts[0] != 12 || got.Verdict != perfInvalid || !reflect.DeepEqual(got.TransportErrorKinds, wantKinds) {
				t.Fatalf("performance = %+v", got)
			}
			wantIndexes := []int{1, 2, 4, 5, 7, 8, 10, 11}
			if len(got.TransportErrorSamples) != len(wantIndexes) {
				t.Fatalf("samples = %+v", got.TransportErrorSamples)
			}
			for i, index := range wantIndexes {
				sample := got.TransportErrorSamples[i]
				out := phase.outcomes[index]
				if sample.Index != index || sample.Kind != out.transportErrKind || sample.Error != out.transportErrText {
					t.Fatalf("sample %d = %+v, want measured index %d", i, sample, index)
				}
			}
			wantReason := "transport errors: throughput is not comparable (first: timeout: request 1: context deadline exceeded)"
			if len(got.Reasons) != 1 || got.Reasons[0] != wantReason {
				t.Fatalf("reasons = %q, want %q", got.Reasons, wantReason)
			}
			raw, err := json.Marshal(got)
			if err != nil {
				t.Fatal(err)
			}
			var decoded performanceReport
			if err := json.Unmarshal(raw, &decoded); err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(decoded.TransportErrorSamples, got.TransportErrorSamples) || !reflect.DeepEqual(decoded.TransportErrorKinds, wantKinds) {
				t.Fatalf("JSON lost diagnostics: %s", raw)
			}
		})
	}
}
