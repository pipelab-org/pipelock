// Copyright 2026 Pipelab
// SPDX-License-Identifier: Apache-2.0

package v3

// PolicySnapshot retains a decision's policy attribution. Its zero value
// means the decision had no captured attribution.
type PolicySnapshot struct {
	hash string
}

// CapturePolicy records the policy digest from the snapshot used at decision
// time. A malformed or absent digest is unavailable.
func CapturePolicy(snapshotDigest string) PolicySnapshot {
	if !isDigest(snapshotDigest) {
		return PolicySnapshot{}
	}
	return PolicySnapshot{hash: snapshotDigest}
}

// ActionPolicy is suitable for encoding on an action. No current
// configuration or writer state is consulted.
func (p PolicySnapshot) ActionPolicy() ActionPolicy {
	if p.hash == "" {
		return ActionPolicy{Source: "unavailable"}
	}
	return ActionPolicy{Source: "request_snapshot", Hash: p.hash}
}
