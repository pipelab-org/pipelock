// Copyright 2026 Pipelab
// SPDX-License-Identifier: Apache-2.0

package deferred

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

const maxJournalLineBytes = 1 << 20

type journalReplay struct {
	pending  map[string]journalEntry
	terminal map[string]struct{}
}

func newJournalReplay() journalReplay {
	return journalReplay{pending: map[string]journalEntry{}, terminal: map[string]struct{}{}}
}

func (r journalReplay) apply(entry journalEntry) error {
	if entry.ReleasePending && entry.State != StateHeld {
		return fmt.Errorf("defer journal integrity: release_pending on state %q for defer_id %q", entry.State, entry.DeferID)
	}
	switch entry.State {
	case StateHeld:
		if _, seen := r.terminal[entry.DeferID]; seen {
			return fmt.Errorf("defer journal integrity: held entry after terminal state for defer_id %q", entry.DeferID)
		}
		if _, seen := r.pending[entry.DeferID]; entry.ReleasePending && !seen {
			return fmt.Errorf("defer journal integrity: release_pending without a prior hold for defer_id %q", entry.DeferID)
		}
		// A release-pending entry stays pending: its allow never reached
		// the journal as final, so the call was not sent and recovery
		// closes it to block.
		r.pending[entry.DeferID] = entry
	case StateResolvedAllow, StateResolvedBlock, StateResolvedStepUp:
		delete(r.pending, entry.DeferID)
		r.terminal[entry.DeferID] = struct{}{}
	case StateAdmissionRejected:
		// Audit-only marker for an action that was never held. It must not
		// touch hold lifecycle: for a duplicate defer_id it shares a live
		// hold's id, so resolving/terminalizing it here would drop that
		// live hold from recovery.
	default:
		return fmt.Errorf("defer journal integrity: unknown state %q for defer_id %q", entry.State, entry.DeferID)
	}
	return nil
}

// JournalCutover describes the exact legacy journal bytes retained by a
// receipt cutover. A torn suffix can be replaced with the retained prefix.
type JournalCutover struct {
	Digest    string
	KeepBytes int64
	Torn      bool
	Pending   int
}

// InspectJournalCutover validates all complete entries and distinguishes a
// malformed newline-terminated entry from a torn final line.
func InspectJournalCutover(source io.Reader) (JournalCutover, error) {
	in := bufio.NewReaderSize(source, maxJournalLineBytes)
	replay := newJournalReplay()
	hash := sha256.New()
	var result JournalCutover
	for {
		line, err := in.ReadSlice('\n')
		last := errors.Is(err, io.EOF)
		if err != nil && !last {
			return JournalCutover{}, fmt.Errorf("read defer journal for cutover: %w", err)
		}
		if len(line) != 0 {
			var entry journalEntry
			if decodeErr := json.Unmarshal(line, &entry); decodeErr != nil {
				if !last || !errors.Is(json.NewDecoder(bytes.NewReader(line)).Decode(new(json.RawMessage)), io.ErrUnexpectedEOF) {
					return JournalCutover{}, fmt.Errorf("parse defer journal for cutover: %w", decodeErr)
				}
				result.Torn = true
			} else {
				if applyErr := replay.apply(entry); applyErr != nil {
					return JournalCutover{}, applyErr
				}
				_, _ = hash.Write(line)
				result.KeepBytes += int64(len(line))
			}
		}
		if last {
			break
		}
	}
	result.Pending = len(replay.pending)
	result.Digest = "sha256:" + hex.EncodeToString(hash.Sum(nil))
	return result, nil
}
