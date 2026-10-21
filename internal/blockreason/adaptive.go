// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package blockreason

import "math"

// adaptiveCloseDetail is optional v1 close metadata. WaitSeconds is the
// configured wait per level, rather than an ETA based on a stale snapshot.
type adaptiveCloseDetail struct {
	Score       float64 `json:"score"`
	Threshold   float64 `json:"threshold"`
	WaitSeconds int     `json:"wait_s"`
}

// WithAdaptiveRecovery attaches content-free adaptive diagnostics. The normal
// close-frame byte budget and reason-preservation rules still apply.
func (i Info) WithAdaptiveRecovery(score, threshold float64, waitSeconds int) Info {
	i.adaptive = nil
	if math.IsNaN(score) || math.IsInf(score, 0) || math.IsNaN(threshold) || math.IsInf(threshold, 0) || score < 0 || threshold <= 0 || waitSeconds <= 0 {
		return i
	}
	i.adaptive = &adaptiveCloseDetail{Score: score, Threshold: threshold, WaitSeconds: waitSeconds}
	return i
}
