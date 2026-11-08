// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/eventcatalog"
)

// LogWatchOnly records observation separately from enforcement. Callers pass
// scanner names and diagnostic reasons, never inspected payload bytes.
func (l *Logger) LogWatchOnly(transport, scannerName, reason, action string, uninspectedBytes int64, enforced bool) {
	if l == nil {
		return
	}
	event, message := eventcatalog.EventWouldBlock, "policy observed in watch-only"
	if action == "" || action == config.ActionWarn || action == config.ActionAllow {
		event, message = eventcatalog.EventWatchOnlyObservation, "finding observed in watch-only"
	}
	if action == "escalate" {
		event, message = eventcatalog.EventWouldEscalate, "escalation observed in watch-only"
	}
	if action == "uninspected" {
		event, message = eventcatalog.EventUninspected, "traffic forwarded without complete inspection in watch-only"
	}
	if enforced {
		event, message = eventcatalog.EventWatchOnlyEnforced, "enforced in watch-only"
	}
	e := newLogEntryRaw(l.zl.Warn(), event).
		boolField("watch_only", true).
		boolField("enforced", enforced).
		str("transport", transport).
		str("scanner", scannerName).
		str("reason", reason).
		str("would_have_been_action", action).
		int64Field("uninspected_bytes", uninspectedBytes)
	e.msg(message)
	if l.emitter != nil {
		l.emitEvent(event, e.fields)
	}
}

// LogWatchOnlyMode announces startup and changes in either direction.
func (l *Logger) LogWatchOnlyMode(enabled bool) {
	if l == nil {
		return
	}
	e := newLogEntryRaw(l.zl.Warn(), eventcatalog.EventWatchOnlyMode).boolField("watch_only", enabled)
	e.msg("watch-only mode changed; core credential floor, kill switch, and access controls remain enforced")
	if l.emitter != nil {
		l.emitEvent(eventcatalog.EventWatchOnlyMode, e.fields)
	}
}
