// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"encoding/hex"
	"fmt"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

func TestReassemblyConcurrentSharedViews(t *testing.T) {
	cfg := config.Defaults()
	cfg.Internal = nil
	cfg.DLP.ScanEnv = false
	sc := MustNew(cfg)
	defer sc.Close()
	body := strings.Repeat("a!", maxReassembledTokenLen+104) + reassemblyBang(hex.EncodeToString([]byte(inspectionLimitAWSKey())))
	control := MustNew(cfg)
	control.reassemblyPlan = nil
	absent := control.ScanTextForDLP(t.Context(), body)
	control.Close()
	if slices.Contains(matchNames(absent.Matches), "AWS Access ID") {
		t.Fatal("control does not isolate terminal coverage")
	}
	ctx, release := WithSharedDecodes(t.Context())
	defer release()
	const workers = 4
	failures := make(chan error, workers)
	var group sync.WaitGroup
	for range workers {
		group.Go(func() {
			for range 2 {
				result := sc.ScanTextForDLP(ctx, body)
				if result.Clean || HasInspectionLimit(result.Matches) || !slices.Contains(matchNames(result.Matches), "AWS Access ID") {
					failures <- fmt.Errorf("shared scan lost independent terminal state: %+v", result)
					return
				}
			}
		})
	}
	group.Wait()
	close(failures)
	for err := range failures {
		t.Error(err)
	}
}
