// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package checker

import "context"

// HealthError records which configured probe failed, without its private text.
type HealthError struct {
	Probe      Classification
	Assessment Assessment
}

func (e *HealthError) Error() string { return "checker known-answer self-test failed" }

// SelfTest checks both configured known answers. The caller supplies public or
// otherwise approved probes, never captured private traffic by default. It uses
// one deadline for both probes and never silently enables an off policy.
func SelfTest(ctx context.Context, c Checker, policy Policy, benign, suspicious Item) error {
	ctx, cancel := context.WithTimeout(ctx, policy.Timeout)
	defer cancel()
	for _, probe := range []struct {
		item           Item
		want           State
		classification Classification
	}{
		{benign, StateBenign, Benign},
		{suspicious, StateFinding, Suspicious},
	} {
		result := c.Check(ctx, probe.item, policy)
		if result.State != probe.want || result.Status != StatusAssessed || ctx.Err() != nil {
			return &HealthError{Probe: probe.classification, Assessment: result}
		}
	}
	return nil
}
