// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"fmt"
	"io"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/decide"
	"github.com/luckyPipewrench/pipelock/internal/session"
)

// The same detail reaches the caller and the diagnostic stream. In stdio mode
// the command supplies stderr; stdout is reserved for JSON-RPC messages.
func mcpAdaptiveBlockMessage(rec session.Recorder, cfg *config.AdaptiveEnforcement, category string, logW io.Writer) string {
	var score float64
	var level int
	if rec != nil {
		score, level = rec.ThreatScore(), rec.EscalationLevel()
	}
	message := "pipelock: " + decide.AdaptiveBlockDetail(category, score, level, cfg)
	if logW != nil {
		_, _ = fmt.Fprintln(logW, message)
	}
	return message
}

func mcpAirlockDiagnostic(eval MCPInputEvaluation, opts MCPProxyOpts, rec session.Recorder, logW io.Writer) string {
	var score float64
	var level int
	if rec != nil {
		score, level = rec.ThreatScore(), rec.EscalationLevel()
	}
	message := mcpAirlockBlockMessage(eval) + "; " + decide.AdaptiveBlockDetail("airlock", score, level, opts.adaptiveCfg()) + "; " + decide.AirlockRecoveryDetail(eval.AirlockTier, opts.airlockCfg())
	if logW != nil {
		_, _ = fmt.Fprintln(logW, message)
	}
	return message
}
