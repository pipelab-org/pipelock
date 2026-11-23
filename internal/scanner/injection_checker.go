// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"context"

	"github.com/luckyPipewrench/pipelock/internal/checker"
	"github.com/luckyPipewrench/pipelock/internal/checker/selection"
	"github.com/luckyPipewrench/pipelock/internal/config"
)

// InjectionCheckerEvent records one external checker outcome without content
// or provider text. Watch events never changed delivery.
type InjectionCheckerEvent struct {
	Checker string
	Surface string
	Mode    string
	State   string
	Reason  string
	Watch   bool
	// Dropped marks a watch call skipped because every watch slot was busy.
	Dropped bool
}

// InjectionCheckerHook observes external checker outcomes. It never changes
// a verdict.
type InjectionCheckerHook func(context.Context, InjectionCheckerEvent)

// SetInjectionCheckerHook installs the observer for external checker outcomes.
func (s *Scanner) SetInjectionCheckerHook(hook InjectionCheckerHook) {
	if hook == nil {
		s.injectionCheckerHook.Store(nil)
		return
	}
	s.injectionCheckerHook.Store(&hook)
}

// ReportInjectionChecker sends an outcome to the installed hook, if any.
func (s *Scanner) ReportInjectionChecker(ctx context.Context, ev InjectionCheckerEvent) {
	if s == nil {
		return
	}
	if hook := s.injectionCheckerHook.Load(); hook != nil {
		(*hook)(ctx, ev)
	}
}

// InjectionCheckers returns this snapshot's external checker set.
func (s *Scanner) InjectionCheckers() *selection.Set {
	if s == nil {
		return nil
	}
	return s.injectionCheckers
}

// ExternalAssessment is the deciding external checker's result for one item.
type ExternalAssessment struct {
	Checker    string
	Mode       string // config.InjectionModeWarn or config.InjectionModeBlock
	Assessment checker.Assessment
}

// Block reports whether delivery must be withheld: a finding, or any result
// that is not a complete benign assessment, in block mode.
func (e ExternalAssessment) Block() bool {
	return e.Mode == config.InjectionModeBlock && e.Assessment.State != checker.StateBenign
}

// Finding reports whether the checker classified the item suspicious.
func (e ExternalAssessment) Finding() bool { return e.Assessment.State == checker.StateFinding }

// Recovery is the assessment this result contributes to adaptive clean
// credit: benign only when the checker assessed the complete item benign.
func (e ExternalAssessment) Recovery() InjectionAssessment {
	status := AssessmentNotAssessed
	switch e.Assessment.State {
	case checker.StateBenign:
		status = AssessmentBenign
	case checker.StateFinding:
		status = AssessmentFinding
	case checker.StateIncomplete:
		status = AssessmentIncomplete
	case checker.StateOff:
		status = AssessmentOff
	}
	return InjectionAssessment{Checker: e.Checker, Status: status}
}

// FindingReason is the reason every external finding reports. A checker's
// own reason IDs never reach events or logs: an identifier-shaped value can
// still be assessed content echoed back, and events carry no content.
const FindingReason = "suspicious"

// Reason is the stable, proxy-owned reason for a non-benign result, for
// operator logs: FindingReason for a finding, otherwise the assessment's
// failure reason or state.
func (e ExternalAssessment) Reason() string {
	if e.Finding() {
		return FindingReason
	}
	if e.Assessment.Reason != "" {
		return string(e.Assessment.Reason)
	}
	return string(e.Assessment.State)
}

// DiagnosticReason describes the outcome for operator-facing errors.
func (e ExternalAssessment) DiagnosticReason() string {
	if e.Assessment.Reason == checker.ReasonOverBudget {
		return e.Reason() + ": request exceeds max_request_bytes"
	}
	return e.Reason()
}

// AssessInjection runs the external checker deciding surface on item. ok is
// false when the built-in checker decides surface or its mode is off; the
// built-in then applies as usual. Every non-benign result is reported to the
// checker hook. The surface's watch checker, if any, also runs, off the
// delivery path.
func (s *Scanner) AssessInjection(ctx context.Context, surface string, item checker.Item) (ExternalAssessment, bool) {
	set := s.InjectionCheckers()
	s.watchInjection(ctx, set, surface, item)
	b, ok := set.Decider(surface)
	if !ok {
		return ExternalAssessment{}, false
	}
	mode := config.InjectionModeWarn
	if b.Policy.Mode == checker.ModeBlock {
		mode = config.InjectionModeBlock
	}
	out := ExternalAssessment{Checker: b.Name, Mode: mode, Assessment: b.Checker.Check(ctx, item, b.Policy)}
	if out.Assessment.State != checker.StateBenign {
		s.ReportInjectionChecker(ctx, InjectionCheckerEvent{
			Checker: b.Name, Surface: surface, Mode: mode,
			State: string(out.Assessment.State), Reason: out.Reason(),
		})
	}
	return out, true
}

// ExternalInjectionSurface reports whether an external checker owns surface.
// The built-in wording rules never run there, whatever the checker's mode.
func (s *Scanner) ExternalInjectionSurface(surface string) bool {
	return s.InjectionCheckers().External(surface)
}

func (s *Scanner) watchInjection(ctx context.Context, set *selection.Set, surface string, item checker.Item) {
	b, ok := set.Watcher(surface)
	if !ok {
		return
	}
	admitted := set.Watch(ctx, b, item, func(a checker.Assessment) {
		reason := ExternalAssessment{Assessment: a}.Reason()
		s.ReportInjectionChecker(context.WithoutCancel(ctx), InjectionCheckerEvent{
			Checker: b.Name, Surface: surface, Mode: config.InjectionModeWarn,
			State: string(a.State), Reason: reason, Watch: true,
		})
	})
	if !admitted {
		s.ReportInjectionChecker(ctx, InjectionCheckerEvent{Checker: b.Name, Surface: surface, Watch: true, Dropped: true})
	}
}
