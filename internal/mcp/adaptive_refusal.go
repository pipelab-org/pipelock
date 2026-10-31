// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package mcp

import "github.com/luckyPipewrench/pipelock/internal/decide"

func adaptiveRefusalMessage(opts MCPProxyOpts) (string, bool) {
	if opts.Rec == nil {
		return "", false
	}
	_, message, blocked := decide.AdaptiveRefusal(opts.Rec.EscalationLevel(), opts.adaptiveCfg())
	return "pipelock: " + message, blocked
}

// Project only the wire error. The terminal descriptor, receipt intent, logs,
// metrics and adaptive signals retain the finding that caused the denial.
func adaptiveDeniedReply(opts MCPProxyOpts, reply []byte) []byte {
	if len(reply) == 0 {
		return reply
	}
	if message, blocked := adaptiveRefusalMessage(opts); blocked {
		return blockSessionDenyResponse(ParseMCPFrame(reply).ID, message)
	}
	return reply
}

func adaptiveBlockedRequest(opts MCPProxyOpts, br *BlockedRequest) {
	if message, blocked := adaptiveRefusalMessage(opts); blocked {
		br.ErrorCode = -32001
		br.ErrorMessage = message
		br.ErrorData = nil
		if br.SyntheticResponse != nil {
			br.SyntheticResponse = adaptiveDeniedReply(opts, br.SyntheticResponse)
		}
	}
}
