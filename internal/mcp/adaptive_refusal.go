// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"github.com/luckyPipewrench/pipelock/internal/decide"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

func adaptiveRefusalMessage(opts MCPProxyOpts) (string, bool) {
	if opts.Rec == nil {
		return "", false
	}
	_, message, blocked := decide.AdaptiveRefusal(opts.Rec.EscalationLevel(), opts.adaptiveCfg())
	return "pipelock: " + message, blocked
}

// keepsOwnRefusal reports a denial that block_all must not project. The kill
// switch runs before every detector on each MCP path and answers with the
// operator's message, so its refusal carries no detector information.
func (d mcpDenialAudit) keepsOwnRefusal() bool {
	spec, ok := denialSpec(d.kind)
	return ok && spec.label == scanner.AuditKillSwitch
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

func adaptiveBlockedRequest(opts MCPProxyOpts, descriptor mcpDenialAudit, br *BlockedRequest) {
	if descriptor.keepsOwnRefusal() {
		return
	}
	if message, blocked := adaptiveRefusalMessage(opts); blocked {
		br.ErrorCode = -32001
		br.ErrorMessage = message
		br.ErrorData = nil
		if br.SyntheticResponse != nil {
			br.SyntheticResponse = adaptiveDeniedReply(opts, br.SyntheticResponse)
		}
	}
}
