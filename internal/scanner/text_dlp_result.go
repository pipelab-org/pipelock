// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package scanner

func partitionTextDLPMatches(matches, informational []TextDLPMatch) ([]TextDLPMatch, []TextDLPMatch) {
	all := append(matches[:len(matches):len(matches)], informational...)
	return finishTextDLPMatches(all, nil, nil)
}

// Findings returns enforcing and informational evidence for transport reporting.
// Enforcement is decided by Matches and Incomplete; informational evidence must
// never trigger adaptive escalation or terminate another decoding lane.
func (r TextDLPResult) Findings() []TextDLPMatch {
	return append(r.Matches[:len(r.Matches):len(r.Matches)], r.InformationalMatches...)
}
