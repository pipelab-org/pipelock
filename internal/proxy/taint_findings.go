// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"github.com/luckyPipewrench/pipelock/internal/mcp"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
	"github.com/luckyPipewrench/pipelock/internal/session"
)

func responseScanFindingKinds(result scanner.ResponseScanResult) []session.HostileFindingKind {
	if result.Clean {
		return nil
	}
	// A failed scan blocks delivery on every response path, so the agent never
	// receives that body. Inspection failure is not exposure: recording it as
	// hostile would mark the whole agent identity hostile for a response it
	// never saw, which client cancellations and restarts trigger routinely.
	// Findings a completed scan made before the failure are still recorded.
	var kinds []session.HostileFindingKind
	if len(result.Matches) > 0 {
		kinds = append(kinds, session.FindingWording)
	}
	if len(kinds) == 0 {
		if result.Failed() {
			return nil
		}
		kinds = append(kinds, session.FindingUnattributed)
	}
	return session.MergeFindingKinds(kinds)
}

// Content findings expose aggregate markers. Preserve framing causes exposed
// by sentinels, without parsing attacker-influenced error text for content kinds.
func sseTaintFindingKinds(err error) []session.HostileFindingKind {
	if IsSSEStreamFinding(err) {
		return observedSSEFindingKinds(err)
	}
	return nil
}

// OnFinding itself establishes the old finding signal, even without a marker.
func observedSSEFindingKinds(err error) []session.HostileFindingKind {
	kinds := mcp.SSETaintFindingKinds(err)
	if len(kinds) == 0 {
		kinds = append(kinds, session.FindingUnattributed)
	}
	return session.MergeFindingKinds(kinds)
}

func upstreamResponseFindingKinds(result scanner.ResponseScanResult) []session.HostileFindingKind {
	if result.Failed() {
		return nil
	}
	return responseScanFindingKinds(result)
}
