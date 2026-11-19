// Copyright 2026 Pipelab
// SPDX-License-Identifier: Apache-2.0

package v3

import (
	"errors"
	"fmt"
	"maps"
	"slices"
)

var errMissingRecoveryHold = errors.New("allow resolution without a stored hold")

type heldActionState struct {
	hold    Action
	allowed bool
}

// recoverHolds runs over the verified effective prefix of each stream, in
// history order. The order and shape of its decisions have already been
// appraised. A settled decision can be dropped immediately.
func (v *verification) recoverHolds(lineage string) ([]Action, error) {
	streams := v.histories[lineage]
	root := slices.IndexFunc(streams, func(stream *verifiedStream) bool { return stream.body.Previous == nil })
	if root < 0 {
		return nil, errors.New("hold recovery requires a verified history root")
	}
	holds := map[string]heldActionState{}
	for stream := streams[root]; ; stream = stream.successors[0] {
		err := walkRecords(v.ctx, v.store, stream.open.Stream, stream.limit, func(record stagedRecord) error {
			if record.Kind != kindAction {
				return nil
			}
			action, err := unmarshalBody[Action](record)
			if err != nil {
				return err
			}
			switch action.Phase {
			case phaseHold:
				holds[action.ActionID] = heldActionState{hold: action}
			case phaseResolution:
				if action.Verdict == verdictAllow {
					hold, ok := holds[action.ActionID]
					if !ok {
						return fmt.Errorf("%w (record %s)", errMissingRecoveryHold, record.id)
					}
					hold.allowed = true
					holds[action.ActionID] = hold
				} else {
					delete(holds, action.ActionID)
				}
			case phaseIntent, phaseOutcome:
				delete(holds, action.ActionID)
			}
			return nil
		})
		if err != nil {
			return nil, err
		}
		if len(stream.successors) == 0 {
			break
		}
	}
	actions := make([]Action, 0, len(holds))
	for _, id := range slices.Sorted(maps.Keys(holds)) {
		state := holds[id]
		relation := "unknown"
		if state.allowed {
			relation = relationAfter
		}
		actions = append(actions, blockingHoldResolution(state.hold, "restart_recovery", relation, state.allowed))
	}
	return actions, nil
}
