// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package blockreason

import (
	"encoding/json"
	"math"
	"strings"
	"testing"
)

func TestAdaptiveCloseMetadata(t *testing.T) {
	info, err := New(EscalationLevel, SeverityCritical, RetryNone)
	if err != nil {
		t.Fatal(err)
	}
	info = info.WithAdaptiveRecovery(20, 5, 300)
	payload := info.CloseFramePayload()
	if len(payload) > closeFrameMaxBytes || !json.Valid([]byte(payload)) {
		t.Fatalf("invalid close: %s", payload)
	}
	for _, want := range []string{`"block_reason":"escalation_level"`, `"score":20`, `"threshold":5`, `"wait_s":300`} {
		if !strings.Contains(payload, want) {
			t.Errorf("missing %s in %s", want, payload)
		}
	}
	for _, tc := range []struct {
		score, threshold float64
		wait             int
	}{
		{math.NaN(), 5, 300}, {math.Inf(1), 5, 300}, {0, math.NaN(), 300}, {0, math.Inf(-1), 300}, {-1, 5, 300}, {0, 0, 300}, {0, 5, 0},
	} {
		if got := info.WithAdaptiveRecovery(tc.score, tc.threshold, tc.wait).CloseFramePayload(); strings.Contains(got, `"adaptive"`) {
			t.Errorf("invalid metadata accepted: %s", got)
		}
	}
	// Extremely large valid numbers may exceed the wire budget. Drop optional
	// diagnostics only after the ordinary metadata; always preserve the reason.
	payload = info.WithAdaptiveRecovery(math.MaxFloat64, math.MaxFloat64, math.MaxInt).CloseFramePayload()
	if len(payload) > closeFrameMaxBytes || !strings.Contains(payload, `"block_reason":"escalation_level"`) {
		t.Fatalf("overflow lost reason: %s", payload)
	}
}
