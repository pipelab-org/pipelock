// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"bytes"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

func TestGenericSSEFindingConfirmation(t *testing.T) {
	for _, shape := range []string{"injection", "dlp", "exempt injection"} {
		for _, failed := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/failure=%t", shape, failed), func(t *testing.T) {
				cfg := config.Defaults()
				cfg.Internal = nil
				cfg.ResponseScanning.Patterns = []config.ResponseScanPattern{{Name: "response marker", Regex: "POLICY_MARKER"}}
				sc := scanner.MustNew(cfg)
				defer sc.Close()
				streamCfg := enabledSSECfg()
				streamCfg.Action = config.ActionWarn
				payload := "POLICY_MARKER"
				if shape == "dlp" {
					payload = fakeAWSKey()
				}
				if shape == "exempt injection" {
					streamCfg.Action = config.ActionBlock
				}
				clean := "data: {\"text\":\"hello\"}\n\n"
				warned := fmt.Sprintf("data: {\"text\":%q}\n\n", payload)
				body := clean + warned + clean
				var out bytes.Buffer
				calls := 0
				failure := errors.New("confirmation unavailable")
				err := ScanGenericSSEStreamWithOptions(t.Context(), strings.NewReader(body), &out, nil, sc, streamCfg, GenericSSEScanOptions{
					ResponseScanExempt: shape == "exempt injection",
					ConfirmFinding: func(finding error) error {
						calls++
						if !errors.Is(finding, ErrSSEStreamFinding) {
							t.Fatalf("confirmation received a non-finding: %v", finding)
						}
						if strings.Contains(out.String(), payload) {
							t.Fatal("finding delivered before confirmation")
						}
						if failed {
							return failure
						}
						return nil
					},
				})
				if calls != 1 {
					t.Fatalf("confirmation calls=%d, want one warned event", calls)
				}
				if failed {
					if !errors.Is(err, failure) || errors.Is(err, ErrSSEStreamFinding) {
						t.Fatalf("confirmation failure classification: %v", err)
					}
					if out.String() != clean {
						t.Fatalf("failed event or later event delivered: %q", out.String())
					}
				} else if err != nil || out.String() != body {
					t.Fatalf("confirmed stream changed: err=%v body=%q", err, out.String())
				}
			})
		}
	}
}

type sseFindingFlushProbe struct {
	legacy   int
	observed int
	err      error
}

func (p *sseFindingFlushProbe) Flush() { p.legacy++ }

func (p *sseFindingFlushProbe) FlushError() error {
	p.observed++
	return p.err
}

func TestGenericSSEObservesFlushOnlyForWrappedFinding(t *testing.T) {
	cfg := config.Defaults()
	cfg.Internal = nil
	const marker = "POLICY_MARKER"
	cfg.ResponseScanning.Patterns = []config.ResponseScanPattern{{Name: "response marker", Regex: marker}}
	sc := scanner.MustNew(cfg)
	defer sc.Close()
	streamCfg := enabledSSECfg()
	streamCfg.Action = config.ActionWarn

	const clean = "data: hello\n\n"
	const warned = "data: " + marker + "\n\n"
	flushErr := errors.New("downstream flush failed")
	for _, tc := range []struct {
		name       string
		wrap       bool
		err        error
		wantLegacy int
		wantBody   string
	}{
		{name: "legacy ignores an error-capable flusher", wantLegacy: 3, wantBody: clean + warned + clean},
		{name: "v3 observes successful warning flush", wrap: true, wantLegacy: 2, wantBody: clean + warned + clean},
		{name: "v3 stops after failed warning flush", wrap: true, err: flushErr, wantLegacy: 1, wantBody: clean + warned},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var out bytes.Buffer
			probe := &sseFindingFlushProbe{err: flushErr}
			var opts GenericSSEScanOptions
			if tc.wrap {
				probe.err = tc.err
				opts.DeliverFinding = func(finding error, deliver func() (bool, error)) error {
					if !errors.Is(finding, ErrSSEStreamFinding) {
						t.Fatalf("delivery wrapper got %v, want a finding", finding)
					}
					if out.String() != clean {
						t.Fatalf("wrapper called after warning was written: %q", out.String())
					}
					observed, err := deliver()
					if observed != (tc.err == nil) || !errors.Is(err, tc.err) {
						t.Fatalf("delivery = (%t, %v), want (%t, %v)", observed, err, tc.err == nil, tc.err)
					}
					return err
				}
			}
			err := ScanGenericSSEStreamWithOptions(t.Context(), strings.NewReader(clean+warned+clean), &out, probe, sc, streamCfg, opts)
			if !errors.Is(err, tc.err) || out.String() != tc.wantBody {
				t.Fatalf("stream = (%q, %v), want (%q, %v)", out.String(), err, tc.wantBody, tc.err)
			}
			wantObserved := 0
			if tc.wrap {
				wantObserved = 1
			}
			if probe.legacy != tc.wantLegacy || probe.observed != wantObserved {
				t.Fatalf("flush calls: legacy=%d observed=%d", probe.legacy, probe.observed)
			}
		})
	}
}

type sseWriteFailure struct{ err error }

func (w sseWriteFailure) Write([]byte) (int, error) { return 0, w.err }

func TestSSEStopsOnDownstreamWriteFailure(t *testing.T) {
	cfg := config.Defaults()
	cfg.Internal = nil
	sc := scanner.MustNew(cfg)
	defer sc.Close()
	for _, transport := range []string{"generic", "A2A"} {
		t.Run(transport, func(t *testing.T) {
			body := strings.NewReader("data: {\"text\":\"hello\"}\n\n")
			writeErr := errors.New("downstream writer closed")
			writer := sseWriteFailure{err: writeErr}
			probe := &sseFindingFlushProbe{}
			var err error
			if transport == "A2A" {
				err = ScanA2AStream(t.Context(), body, writer, probe, sc, enabledA2ACfg())
			} else {
				err = ScanGenericSSEStreamWithOptions(t.Context(), body, writer, probe, sc, enabledSSECfg(), GenericSSEScanOptions{})
			}
			if !errors.Is(err, writeErr) {
				t.Fatalf("stream error = %v, want %v", err, writeErr)
			}
			if probe.legacy != 0 || probe.observed != 0 {
				t.Fatalf("flushed after a failed write: legacy=%d observed=%d", probe.legacy, probe.observed)
			}
		})
	}
}
