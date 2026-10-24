// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"crypto/rand"
	"fmt"
	"reflect"
	"strings"
	"unicode"

	"github.com/luckyPipewrench/pipelock/internal/audit"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/proxy"
)

type reloadAttempt struct {
	before     *config.Config
	sourceHash string
	restart    []string
}

const reloadSentryScrubberField = "sentry.scrubber"

func (s *Server) sentryRestartFields(fields []string, cfg *config.Config) []string {
	if s.sentry.ScrubberNeedsRestart(cfg) {
		fields = append(fields, reloadSentryScrubberField)
	}
	return fields
}

// liveConfig tolerates a manually constructed Server that has no proxy yet;
// such a server can still reject a candidate before anything is published.
func (s *Server) liveConfig() *config.Config {
	if s.proxy == nil {
		return nil
	}
	return s.proxy.CurrentConfig()
}

func (s *Server) initReloadIdentity() {
	s.reloadOutcome = proxy.ReloadOutcome{
		InstanceID: rand.Text(), Generation: 1, Trigger: "startup",
		Verdict: proxy.ReloadAccepted, RestartRequiredFields: []string{},
		ReloadAvailable: s.opts.ConfigFile != "" && s.opts.ConfigFile != "-",
		WatcherState:    "not_started",
	}
	if cfg := s.liveConfig(); cfg != nil {
		s.reloadOutcome.AcceptedSourceHash = cfg.Hash()
		s.reloadOutcome.CanonicalPolicyHash = cfg.CanonicalPolicyHash()
	}
}

// ReloadStatus waits for any in-flight transaction, including Conductor's
// durable activation or compensation, before returning a detached snapshot.
func (s *Server) ReloadStatus() proxy.ReloadOutcome {
	s.reloadMu.Lock()
	defer s.reloadMu.Unlock()
	return s.reloadSnapshotLocked()
}

func (s *Server) reloadSnapshotLocked() proxy.ReloadOutcome {
	out := s.reloadOutcome
	out.RestartRequiredFields = append([]string{}, out.RestartRequiredFields...)
	return out
}

func (s *Server) setReloadWatcherState(state string) {
	s.reloadMu.Lock()
	defer s.reloadMu.Unlock()
	if state == "watching" && s.reloadOutcome.WatcherState != "not_started" {
		return
	}
	s.reloadOutcome.WatcherState = state
}

// ReloadFile loads only the daemon's configured file, under its environment.
// The returned value belongs to this call's transaction, never a later poll.
func (s *Server) ReloadFile() proxy.ReloadOutcome {
	s.reloadMu.Lock()
	defer s.unlockReloadAndReport()
	if !s.reloadOutcome.ReloadAvailable {
		s.reloadOutcome.Trigger = "api"
		s.reloadOutcome.Verdict = proxy.ReloadUnavailable
		s.reloadOutcome.Reason = "daemon has no reloadable configuration file; restart with --config"
		s.reloadOutcome.CandidateSourceHash = ""
		return s.reloadSnapshotLocked()
	}
	cfg, sourceHash, err := config.LoadReload(s.opts.ConfigFile)
	out := s.reloadEventLocked(config.ReloadEvent{Config: cfg, SourceHash: sourceHash, Err: err}, "api")
	s.notifyReloadStatusLocked()
	return out
}

func (s *Server) reloadEventLocked(event config.ReloadEvent, trigger string) proxy.ReloadOutcome {
	if event.Err != nil {
		s.logger.LogError(audit.NewResourceLogContext(configReloadAuditMethod, s.opts.ConfigFile), event.Err)
		s.finishReloadLocked(&reloadAttempt{before: s.liveConfig(), sourceHash: event.SourceHash}, event.Err)
		if s.reloadOutcome.Verdict == proxy.ReloadRejected {
			s.reloadOutcome.Reason = "configuration loading or validation failed; inspect daemon logs for details"
		}
		s.revokeUnavailableAckKey()
	} else if err := s.reloadLocked(event.Config); err != nil {
		s.revokeUnavailableAckKey()
	}
	s.reloadOutcome.Trigger = trigger
	return s.reloadSnapshotLocked()
}

func (s *Server) finishReloadLocked(attempt *reloadAttempt, err error) {
	if s.reloadOutcome.InstanceID == "" {
		s.initReloadIdentity()
	}
	out := &s.reloadOutcome
	out.Trigger = "runtime"
	out.CandidateSourceHash = attempt.sourceHash
	live := s.liveConfig()
	changed := live != attempt.before
	runtimeChanged := false
	if changed {
		// Compare the exported runtime fields, including settings intentionally
		// excluded from policy JSON. Raw source bytes and hash caches are
		// unexported; comment-only input does not invent an activation.
		if !sameRuntimeConfig(attempt.before, live) {
			runtimeChanged = true
			out.Generation++
		}
		out.CanonicalPolicyHash = live.CanonicalPolicyHash()
	}
	out.Reason = ""
	if err != nil {
		out.Verdict = proxy.ReloadRejected
		out.Reason = safeReloadReason(err)
		if changed {
			out.Verdict = proxy.ReloadUncertain
			out.Reason = "reload failed after runtime publication; configuration may be partially active; inspect daemon logs"
			out.AcceptedSourceHash = ""
			// Keep the existing uncertainty deny source. Do not claim the
			// proxy and all dependent runtime state were swapped atomically.
			if s.killswitch != nil {
				s.killswitch.SetConductorApplyFailure(true, out.Reason)
			}
		} else if s.killswitch != nil && s.killswitch.ConductorApplyFailure() {
			out.Verdict = proxy.ReloadUncertain
			out.Reason = "candidate rejected; runtime consistency remains uncertain; traffic is denied"
			out.AcceptedSourceHash = ""
		}
		return
	}
	if !s.reloadDurablePending && s.killswitch != nil && s.killswitch.ConductorApplyFailure() {
		out.Verdict = proxy.ReloadUncertain
		out.Reason = "runtime consistency remains uncertain; traffic is denied; restart or complete Conductor recovery"
		out.AcceptedSourceHash = ""
		return
	}
	if s.reloadDurablePending {
		// Enforcement-only bundles omit follower-local plumbing. Preserving
		// those omitted fields is ownership resolution, not restart drift.
		attempt.restart = nil
	}
	attempt.restart = s.sentryRestartFields(attempt.restart, live)
	out.RestartRequiredFields = append([]string{}, attempt.restart...)
	out.PendingRestart = len(attempt.restart) != 0
	if out.PendingRestart {
		out.Verdict = proxy.ReloadRestartRequired
		out.Reason = "reloadable settings applied; remaining fields require restart or their documented reconciliation"
		return
	}
	previousSource := out.AcceptedSourceHash
	out.AcceptedSourceHash = attempt.sourceHash
	out.Verdict = proxy.ReloadAccepted
	if !changed || (!runtimeChanged && previousSource == attempt.sourceHash) {
		out.Verdict = proxy.ReloadUnchanged
	}
}

func sameRuntimeConfig(before, after *config.Config) bool {
	if before == nil || after == nil {
		return before == after
	}
	left, right := reflect.ValueOf(before).Elem(), reflect.ValueOf(after).Elem()
	for i := range left.NumField() {
		if left.Type().Field(i).IsExported() && !reflect.DeepEqual(left.Field(i).Interface(), right.Field(i).Interface()) {
			return false
		}
	}
	return true
}

// Only field-based downgrade diagnostics are safe to return verbatim. Other
// errors can contain YAML values, paths or credentials; detailed logs stay local.
func safeReloadReason(err error) string {
	if strings.HasPrefix(err.Error(), "rejected: security downgrade from ") {
		return strings.Map(func(r rune) rune {
			if unicode.IsPrint(r) {
				return r
			}
			return ' '
		}, err.Error())
	}
	return "configuration activation rejected; inspect daemon logs for details"
}

func (s *Server) reloadSystemdStatusLocked() string {
	out := s.reloadOutcome
	status := fmt.Sprintf("config %s instance=%s generation=%d policy=%s pending_restart=%t", out.Verdict, out.InstanceID, out.Generation, out.CanonicalPolicyHash, out.PendingRestart)
	if out.Reason != "" {
		status += ": " + out.Reason
	}
	return sdNotifySafeStatus(status)
}

func (s *Server) notifyReloadStatusLocked() {
	if s.startupNotifiedAlready() {
		sdNotifyOrLog(s.opts.Stderr, "STATUS="+s.reloadSystemdStatusLocked())
	}
}
