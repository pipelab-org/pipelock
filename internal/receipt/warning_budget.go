// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package receipt

import (
	"context"
	"encoding/json"
	"sync"
)

// This bounds the per-unit lease; the summary preserves overflow counts.
const maxIndividualDLPWarnings = 16

// DLPWarningSlots reserves individual warnings plus one overflow summary.
const DLPWarningSlots = maxIndividualDLPWarnings + 1

type warningBudgetKey struct{}

type warningBudget struct {
	mu        sync.Mutex
	emitter   *Emitter
	admission EmitOpts
	written   int
	counts    map[string]int
	summary   EmitOpts
	report    func(error)
}

// WithDLPWarningBudget routes warnings to the admitted writer. Finish writes
// the summary, if any, before the caller releases the admission.
func WithDLPWarningBudget(ctx context.Context, emitter *Emitter, admission EmitOpts) (context.Context, func()) {
	if admission.NativeLease == nil {
		return ctx, func() {}
	}
	if admission.nativeEmitter != nil {
		emitter = admission.nativeEmitter
	}
	b := &warningBudget{emitter: emitter, admission: admission}
	return context.WithValue(ctx, warningBudgetKey{}, b), b.finish
}

// EmitDLPWarning records a warning with its unit's evidence budget when
// present. The caller separately audits every warning, including overflow.
func EmitDLPWarning(ctx context.Context, fallback *Emitter, opts EmitOpts, report func(error)) {
	var b *warningBudget
	if ctx != nil {
		b, _ = ctx.Value(warningBudgetKey{}).(*warningBudget)
	}
	if b == nil {
		if err := fallback.Emit(opts); err != nil {
			report(err)
		}
		return
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.written < maxIndividualDLPWarnings {
		b.written++
		if err := b.emitter.Emit(opts.InheritAdmission(b.admission)); err != nil {
			report(err)
		}
		return
	}
	if b.counts == nil {
		b.counts = make(map[string]int)
		b.summary = opts.InheritAdmission(b.admission)
		b.report = report
	}
	b.counts[opts.Pattern]++
}

func (b *warningBudget) finish() {
	b.mu.Lock()
	defer b.mu.Unlock()
	if len(b.counts) == 0 {
		return
	}
	// A map with string keys and integer values always marshals.
	counts, _ := json.Marshal(b.counts)
	b.summary.Pattern = "additional warnings by pattern: " + string(counts)
	if err := b.emitter.Emit(b.summary); err != nil {
		b.report(err)
	}
	b.counts = nil
}
