// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"context"

	"github.com/luckyPipewrench/pipelock/internal/audit"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

func wirePromptInjectionAudit(sc *scanner.Scanner, logger *audit.Logger) {
	if sc == nil || logger == nil {
		return
	}
	sc.SetInjectionWarnHook(func(_ context.Context, names []string) {
		// Scanner-only observations may have no transport attribution. Do not
		// fabricate a URL or MCP identity, or retain the matched content.
		logger.LogResponseScan(audit.LogContext{}, config.ActionWarn, len(names), names, nil)
	})
}

func logPromptInjectionPolicy(cfg *config.Config, logger *audit.Logger) {
	if notice := cfg.PromptInjectionNotice(); notice != "" {
		logger.LogConfigReload("prompt_injection_policy", notice, cfg.Hash())
	}
}
