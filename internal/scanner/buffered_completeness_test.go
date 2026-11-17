// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/checker"
	"github.com/luckyPipewrench/pipelock/internal/checker/checkertest"
	"github.com/luckyPipewrench/pipelock/internal/config"
)

func TestBufferedInjectionPartialCoverage(t *testing.T) {
	for _, state := range []string{"benign", "finding", "failure"} {
		t.Run(state, func(t *testing.T) {
			srv := checkertest.New(t, state)
			cfg := testResponseConfig()
			srv.Configure(cfg, config.InjectionSurfaceHTTPResponse, config.InjectionModeBlock)
			sc := MustNew(cfg)
			t.Cleanup(sc.Close)
			got := sc.ScanBufferedInjection(t.Context(), BufferedInjectionScan{Surface: config.InjectionSurfaceHTTPResponse, Content: "extracted text", Completeness: &checker.Completeness{Status: checker.Partial, Reason: checker.ReasonUnsupported}})
			if got.Clean || got.Assessment.Status == AssessmentBenign || len(srv.Items()) != 1 || srv.Items()[0].Completeness.Status != checker.Partial {
				t.Fatalf("partial coverage lost: result=%+v items=%+v", got, srv.Items())
			}
			if state == "finding" && !got.CheckerBlocked() {
				t.Fatalf("partial finding lost: %+v", got)
			}
			if state != "finding" && !got.Failed() {
				t.Fatalf("partial refusal lost: %+v", got)
			}
		})
	}
}
