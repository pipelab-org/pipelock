// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package discover

import "github.com/luckyPipewrench/pipelock/internal/mcpwrap"

// Evidence strings for proxy-shaped invocations that are not proven to run
// this executable. Each keeps the server unprotected; they differ only so an
// operator knows whether to repair a path, replace a binary, or check access.
const (
	evidenceProtectedPipelock = "command is this pipelock executable and args begin mcp proxy"
	evidenceProtectedOther    = "wrapped by recognized security proxy"
	evidenceUnknown           = "no command or url configured"
	evidenceWrapperRelative   = "mcp proxy wrapper found, but its executable is not an absolute path, so its identity is unconfirmed"
	evidenceWrapperMissing    = "mcp proxy wrapper found, but its executable path does not exist"
	evidenceWrapperDifferent  = "mcp proxy wrapper found, but its executable differs from this pipelock executable"
	evidenceWrapperUncheck    = "mcp proxy wrapper found, but its executable identity could not be checked"
)

// classifyServer determines whether a server is wrapped by this executable's
// proxy and why, from a single identity inspection, so the reported state and
// its evidence always describe the same observation.
func classifyServer(s MCPServer) (ProtectionStatus, string) {
	if s.Command == "" && s.URL == "" {
		return Unknown, evidenceUnknown
	}
	state, reason := mcpwrap.ExplainInvocation(s.Command, s.Args)
	if state == mcpwrap.WrapperSelf {
		return ProtectedPipelock, evidenceProtectedPipelock
	}
	// Future: check for other known proxy wrappers here.
	// Anything not pipelock-wrapped with a command or URL is unprotected.
	return Unprotected, foreignEvidence(reason)
}

// classifyProtection determines if a server is wrapped by a security proxy.
func classifyProtection(s MCPServer) ProtectionStatus {
	status, _ := classifyServer(s)
	return status
}

func foreignEvidence(reason mcpwrap.ForeignReason) string {
	switch reason {
	case mcpwrap.ForeignRelativePath:
		return evidenceWrapperRelative
	case mcpwrap.ForeignMissing:
		return evidenceWrapperMissing
	case mcpwrap.ForeignDifferentFile:
		return evidenceWrapperDifferent
	case mcpwrap.ForeignUncheckable:
		return evidenceWrapperUncheck
	default:
		return evidenceNoProxy
	}
}

// protectionEvidence returns a human-readable explanation for a protection
// classification already recorded on s. Discover uses classifyServer instead,
// which derives both from one inspection.
func protectionEvidence(s MCPServer) string {
	switch s.Protection {
	case ProtectedPipelock:
		return evidenceProtectedPipelock
	case ProtectedOther:
		return evidenceProtectedOther
	case Unknown:
		return evidenceUnknown
	default:
		_, reason := mcpwrap.ExplainInvocation(s.Command, s.Args)
		return foreignEvidence(reason)
	}
}
