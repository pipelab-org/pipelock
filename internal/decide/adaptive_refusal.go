// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package decide

import (
	"github.com/luckyPipewrench/pipelock/internal/blockreason"
	"github.com/luckyPipewrench/pipelock/internal/config"
)

// AdaptiveRefusal projects block_all onto the wire without changing the finding
// that produced a refusal. Callers retain scanner evidence and signals before
// applying this projection. Other adaptive upgrades retain their usual reasons.
func AdaptiveRefusal(level int, cfg *config.AdaptiveEnforcement) (blockreason.Info, string, bool) {
	if UpgradeAction("", level, cfg) != config.ActionBlock {
		return blockreason.Info{}, "", false
	}
	info := blockreason.MustNew(blockreason.EscalationLevel,
		blockreason.SeverityFor(blockreason.EscalationLevel), blockreason.RetryFor(blockreason.EscalationLevel))
	info, _ = info.WithLayer("session_deny") // fixed, valid layer
	return info, AdaptiveBlockMessage("session_deny"), true
}
