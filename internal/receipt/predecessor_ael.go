// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package receipt

import (
	"errors"
	"fmt"

	"github.com/luckyPipewrench/pipelock/internal/ael"
	"github.com/luckyPipewrench/pipelock/internal/recorder"
	"github.com/luckyPipewrench/pipelock/internal/verification"
)

// VerifyPredecessorAEL authenticates the native run of each stopped session
// that standalone chain linking could select. Existing links and live
// writers belong to their own branches of history.
func VerifyPredecessorAEL(dir, base string, options verification.Options) error {
	candidates, err := priorChainCandidates(dir, base, "")
	if err != nil {
		return err
	}
	for _, candidate := range candidates {
		if err := options.Check(); err != nil {
			return err
		}
		if !candidate.available(dir) {
			continue
		}
		tail, tailErr := sessionReceiptTail(candidate.files)
		if !errors.Is(tailErr, recorder.ErrTornTail) &&
			(tailErr != nil || tail == nil || VerifyInternalConsistencyOnly(*tail) != nil) {
			// The existing linker skips these candidates. A legacy receipt
			// failure alone must not become a native startup refusal.
			continue
		}
		if err := verifySessionAEL(dir, candidate.session, options); err != nil {
			return fmt.Errorf("verify predecessor session %q native AEL: %w", candidate.session, err)
		}
	}
	return nil
}

func verifySessionAEL(dir, session string, options verification.Options) error {
	type claim struct {
		run, signer string
		complete    bool
	}
	var claims []claim
	whole := new(WholeRecorderWalker)
	chain := newChainKeysWalker()
	err := recorder.WalkSessionHistoryWithOptions(dir, session, options, func(entry recorder.Entry) error {
		if whole.EntryCount() == 0 && entry.Type == recorder.GroupGateEntryType {
			return errGroupedPredecessor
		}
		r, ok := whole.Add(entry)
		if err := whole.Err(); err != nil {
			return err
		}
		if !ok {
			if entry.Type == transcriptRootEntryType && len(claims) != 0 {
				claims[len(claims)-1].complete = true
			}
			return nil
		}
		chain.Add(r)
		control := r.ActionRecord.SessionControl
		if control == nil {
			return nil
		}
		switch control.Kind {
		case SessionControlOpen:
			// A signer rotation in a single recorder session closes the
			// old native run before persisting the new signed opening.
			if len(claims) != 0 {
				claims[len(claims)-1].complete = true
			}
			if control.Open != nil && control.Open.RunNonce != "" {
				claims = append(claims, claim{run: control.Open.RunNonce, signer: r.SignerKey})
			}
		case SessionControlClose:
			if len(claims) != 0 {
				claims[len(claims)-1].complete = true
			}
		}
		return nil
	})
	if errors.Is(err, errGroupedPredecessor) {
		return nil // The receipt group owns verification of its shards.
	}
	if err != nil && !errors.Is(err, recorder.ErrTornTail) {
		return err
	}
	if len(claims) != 0 {
		// Standalone continuity already accepts an internally verified
		// predecessor signed by an older key. The v1 walk authenticates
		// the claims and their transitions before trusting any AEL signer.
		if result := chain.Result(); !result.Valid {
			return fmt.Errorf("invalid predecessor receipt chain: %s", result.Error)
		}
	}
	for _, claim := range claims {
		if _, err := ael.VerifyRunWithOptions(dir, claim.run, claim.signer, claim.complete, options); err != nil {
			return fmt.Errorf("run %s: %w", claim.run, err)
		}
	}
	return nil
}

var errGroupedPredecessor = errors.New("receipt group owns predecessor")
