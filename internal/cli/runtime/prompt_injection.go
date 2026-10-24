// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"context"
	"fmt"
	"io"
	"strings"

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

// wirePromptInjectionStderr reports warn-only wording observations by pattern
// name for runtimes without a structured audit sink.
func wirePromptInjectionStderr(sc *scanner.Scanner, stderr io.Writer) {
	if sc == nil || stderr == nil {
		return
	}
	sc.SetInjectionWarnHook(func(_ context.Context, names []string) {
		_, _ = fmt.Fprintf(stderr, "pipelock: warn-only prompt-injection wording match: %s\n", strings.Join(names, ", "))
	})
}

func logPromptInjectionPolicy(cfg *config.Config, logger *audit.Logger) {
	if notice := cfg.PromptInjectionNotice(); notice != "" {
		logger.LogConfigReload("prompt_injection_policy", notice, cfg.Hash())
	}
}

// announcePromptInjectionPolicy discloses a reduced wording policy on stderr
// and in the audit log for runtimes whose startup does not print config
// validation warnings. Either sink may be nil.
func announcePromptInjectionPolicy(cfg *config.Config, logger *audit.Logger, stderr io.Writer) {
	notice := cfg.PromptInjectionNotice()
	if notice == "" {
		return
	}
	if logger != nil {
		logPromptInjectionPolicy(cfg, logger)
	}
	if stderr != nil {
		_, _ = fmt.Fprintln(stderr, "WARNING: "+notice)
	}
}
