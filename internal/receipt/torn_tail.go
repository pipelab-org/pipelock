// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package receipt

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"slices"
	"strings"
	"sync"

	contractreceipt "github.com/luckyPipewrench/pipelock/internal/contract/receipt"
	"github.com/luckyPipewrench/pipelock/internal/recorder"
)

// SessionID identifies the immutable recorder session owned by this emitter.
func (e *Emitter) SessionID() string {
	if e == nil {
		return ""
	}
	return e.session
}

func (e *Emitter) observeTornTail(err error) {
	var torn *recorder.TornTailError
	if e == nil || !errors.As(err, &torn) {
		return
	}
	if sink, ok := e.metrics.(interface{ RecordEvidenceTornTail(string, int64) }); ok {
		sink.RecordEvidenceTornTail(torn.Path, torn.Offset)
	}
}

// CheckSessionTail refuses to adopt a damaged current session. Before reporting
// a torn write, it validates the complete prefix and any valid final JSON record:
// a bad signature or broken link must not be hidden by an incomplete write.
func CheckSessionTail(rec *recorder.Recorder, session string, signerKeys []string) error {
	return CheckSessionTailCached(rec, session, signerKeys, nil)
}

// CheckSessionTailCached is CheckSessionTail for a caller that checks the same
// run repeatedly, such as every configuration reload of one process.
//
// The check runs with recorder writes excluded, and a run grows for as long as
// the process lives. Re-parsing and re-verifying every signed record on every
// reload therefore made each reload slower than the last and held every
// receipt-gated request for its whole duration. The cache keeps, per shard of
// the verified prefix, the exact bytes' digest and the chain state at its end.
// A shard whose bytes still hash to the recorded digest, checked for the same
// session and signer keys and reached through an unchanged prefix, carries the
// recorded state forward instead of being parsed again. Any changed byte, a
// reordered or missing shard, a different session or a different key set
// misses, and the shard and everything after it are validated in full, so the
// result is the one a full validation returns. Only shards that validated
// without error are remembered. A nil cache validates everything.
func CheckSessionTailCached(rec *recorder.Recorder, session string, signerKeys []string, cache *TailCheckCache) error {
	if rec == nil || rec.IsNop() {
		return nil
	}
	return rec.InspectSession(session, func() error { return checkSessionTailLocked(rec, session, signerKeys, cache) })
}

// TailCheckCache remembers the evidence shards a tail check validated in full.
// The zero value is empty and ready to use.
type TailCheckCache struct {
	mu      sync.Mutex
	session string
	keys    string
	shards  []verifiedShard
}

type verifiedShard struct {
	path   string
	digest recorder.EvidenceFileDigest
	// end is the chain state after the shard's last record.
	end tailChainState
}

// tailChainState is what validation of the next shard depends on.
type tailChainState struct {
	previous     *recorder.Entry
	priorReceipt *Receipt
	priorV2      *contractreceipt.EvidenceReceipt
}

// Package seams so tests can count full validations.
var (
	validateShardFile = recorder.ValidateEvidenceFileDigest
	digestShardFile   = recorder.DigestEvidenceFile
)

func signerKeySet(keys []string) string {
	sorted := slices.Clone(keys)
	slices.Sort(sorted)
	return strings.Join(slices.Compact(sorted), "\n")
}

func checkSessionTailLocked(rec *recorder.Recorder, session string, signerKeys []string, cache *TailCheckCache) error {
	files, err := recorderFiles(rec.Dir(), session)
	if err != nil {
		return err
	}
	keySet := signerKeySet(signerKeys)
	var reusable []verifiedShard
	if cache != nil {
		cache.mu.Lock()
		defer cache.mu.Unlock()
		if cache.session == session && cache.keys == keySet {
			reusable = cache.shards
		}
	}
	verified := make([]verifiedShard, 0, len(files))
	if cache != nil {
		// Whatever happens below, the cache holds exactly the prefix this
		// call verified: a failure must not leave older entries that a later
		// call could reach through a changed prefix.
		defer func() { cache.session, cache.keys, cache.shards = session, keySet, verified }()
	}
	var state tailChainState
	for i, file := range files {
		if len(verified) == i && i < len(reusable) && reusable[i].path == file {
			if digest, err := digestShardFile(file); err == nil && digest == reusable[i].digest {
				verified = append(verified, reusable[i])
				state = reusable[i].end
				continue
			}
		}
		digest, err := validateShardFile(file, func(next recorder.Entry) error {
			return state.advance(next, session, signerKeys)
		})
		if err != nil {
			if i+1 < len(files) && errors.Is(err, recorder.ErrTornTail) {
				return fmt.Errorf("receipt group session has a torn segment: %s", filepath.Base(file))
			}
			return fmt.Errorf("validating evidence file %s: %w", file, err)
		}
		verified = append(verified, verifiedShard{path: file, digest: digest, end: state})
	}
	return nil
}

// advance validates next against the chain state and moves the state past it.
func (s *tailChainState) advance(next recorder.Entry, session string, signerKeys []string) error {
	if err := validateTailEntry(next, session, signerKeys); err != nil {
		return err
	}
	if s.previous != nil && (next.Sequence != s.previous.Sequence+1 || next.PrevHash != s.previous.Hash) {
		return fmt.Errorf("recorder hash link mismatch at seq %d", next.Sequence)
	}
	s.previous = &next
	if next.Type == recorderEntryType {
		r, err := receiptFromEntry(next)
		if err != nil {
			return err
		}
		if s.priorReceipt != nil {
			hash, err := ReceiptHash(*s.priorReceipt)
			if err != nil {
				return err
			}
			if r.ActionRecord.ChainPrevHash != hash {
				return errors.New("receipt hash link mismatch before torn tail")
			}
			if r.ActionRecord.KeyTransition == nil && r.ActionRecord.ChainSeq != s.priorReceipt.ActionRecord.ChainSeq+1 {
				return errors.New("receipt sequence mismatch before torn tail")
			}
		}
		s.priorReceipt = r
	}
	if next.Type == "evidence_receipt" {
		raw, err := receiptBytesFromEntry(next)
		if err != nil {
			return err
		}
		var r contractreceipt.EvidenceReceipt
		if err := json.Unmarshal(raw, &r); err != nil {
			return err
		}
		if s.priorV2 != nil {
			hash, err := contractreceipt.ReceiptHash(*s.priorV2)
			if err != nil {
				return err
			}
			if r.ChainPrevHash != hash || r.ChainSeq != s.priorV2.ChainSeq+1 {
				return errors.New("v2 receipt chain mismatch before torn tail")
			}
		}
		s.priorV2 = &r
	}
	return nil
}

func validateTailEntry(entry recorder.Entry, session string, signerKeys []string) error {
	if entry.SessionID != session || entry.Hash == "" || recorder.ComputeHash(entry) != entry.Hash {
		return fmt.Errorf("invalid recorder tail in session %q at seq %d", session, entry.Sequence)
	}
	return ValidateEvidenceEntry(entry, signerKeys)
}

// ValidateEvidenceEntry checks embedded receipt signatures before classifying
// an incomplete write. Nil signerKeys permits structural-only inspection;
// live recovery supplies the keys held by the process.
func ValidateEvidenceEntry(entry recorder.Entry, signerKeys []string) error {
	if entry.Type == "evidence_receipt" {
		raw, err := receiptBytesFromEntry(entry)
		if err != nil {
			return err
		}
		var r contractreceipt.EvidenceReceipt
		if err := json.Unmarshal(raw, &r); err != nil {
			return err
		}
		keyID := r.Signature.SignerKeyID
		if signerKeys != nil && !slices.Contains(signerKeys, keyID) {
			return errors.New("tail receipt signer was not held by this process")
		}
		key, err := hex.DecodeString(keyID)
		if err != nil {
			return err
		}
		return contractreceipt.VerifyWithKey(r, ed25519.PublicKey(key), keyID)
	}
	if entry.Type != recorderEntryType {
		return nil
	}
	r, err := receiptFromEntry(entry)
	if err != nil {
		return err
	}
	if err := VerifyInternalConsistencyOnly(*r); err != nil {
		return fmt.Errorf("tail receipt signature invalid: %w", err)
	}
	if signerKeys != nil && !slices.Contains(signerKeys, r.SignerKey) {
		return errors.New("tail receipt signer was not held by this process")
	}
	return nil
}
