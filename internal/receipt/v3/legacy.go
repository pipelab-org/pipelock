// Copyright 2026 Pipelab
// SPDX-License-Identifier: Apache-2.0

package v3

import (
	"bufio"
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"slices"
	"strings"

	contract "github.com/luckyPipewrench/pipelock/internal/contract/receipt"
	legacy "github.com/luckyPipewrench/pipelock/internal/receipt"
	"github.com/luckyPipewrench/pipelock/internal/recorder"
)

const (
	legacyAction   = "action_v1"
	legacyEvidence = "evidence_v2"
	legacyGroup    = "receipt_group"
)

type legacyBatch struct {
	action   []legacy.Receipt
	evidence []contract.EvidenceReceipt
}

func legacyCandidate(name string) bool {
	_, _, isRecorder := recorder.ParseEvidenceFilename(name)
	return isRecorder || isGroupArtifact(name) || name == "activation-receipts.jsonl" ||
		name == "redaction-receipts.jsonl" || name == "ratification-receipts.jsonl"
}

func isGroupArtifact(name string) bool {
	return strings.HasPrefix(name, "receipt-group-") && strings.HasSuffix(name, ".json")
}

func (v *verification) verifyLegacy(paths []string) (map[legacyIdentity]legacyPresentation, error) {
	presented := map[legacyIdentity]legacyPresentation{}
	if len(paths) == 0 {
		return presented, nil
	}
	keys := make([]string, 0, len(v.opts.Keys))
	for _, key := range v.opts.Keys {
		keys = append(keys, hex.EncodeToString(key))
	}
	sessions := map[string][]string{}
	groupDirs := map[string]bool{}
	batches := []legacyBatch{}
	for _, path := range paths {
		name := filepath.Base(path)
		if v.opts.Directory && isGroupArtifact(name) {
			groupDirs[filepath.Dir(path)] = true
			continue
		}
		if v.opts.Directory {
			if session, _, ok := recorder.ParseEvidenceFilename(name); ok {
				sessions[session] = append(sessions[session], path)
				continue
			}
		}
		batch, operational, err := readLegacy(path)
		switch {
		case err != nil:
			v.addCode(codeLegacyInvalid, "")
		case len(batch.action) != 0 || len(batch.evidence) != 0:
			batches = append(batches, batch)
		case operational && v.opts.Directory:
			v.result.IgnoredFiles++
		default:
			v.addCode(codeUnrecognizedFile, "")
		}
	}
	for _, session := range sortedKeys(sessions) {
		paths := sessions[session]
		slices.SortFunc(paths, func(a, b string) int {
			_, startA, _ := recorder.ParseEvidenceFilename(filepath.Base(a))
			_, startB, _ := recorder.ParseEvidenceFilename(filepath.Base(b))
			if startA != startB {
				if startA < startB {
					return -1
				}
				return 1
			}
			return strings.Compare(a, b)
		})
		var all legacyBatch
		for _, path := range paths {
			batch, operational, err := readLegacy(path)
			switch {
			case err != nil:
				v.addCode(codeLegacyInvalid, "")
			case len(batch.action) != 0 || len(batch.evidence) != 0:
				all.action = append(all.action, batch.action...)
				all.evidence = append(all.evidence, batch.evidence...)
			case operational:
				v.result.IgnoredFiles++
			default:
				v.addCode(codeUnrecognizedFile, "")
			}
		}
		batches = append(batches, all)
	}
	positions := map[legacyIdentity]map[int64]string{}
	for _, batch := range batches {
		v.legacyActions(batch.action, keys, presented, positions)
		v.legacyEvidence(batch.evidence, keys, presented, positions)
	}
	for _, dir := range sortedKeys(groupDirs) {
		_, err := legacy.VerifyReceiptGroups(dir, keys, func(group legacy.ReceiptGroupResult) error {
			switch group.Verdict {
			case legacy.GroupIncomplete:
				v.addCode(codeLegacyGroupIncomplete, "")
			case legacy.GroupInvalid:
				v.addCode(codeLegacyInvalid, "")
			}
			head := group.CloseManifestSHA
			if head == "" {
				head = group.OpenManifestSHA
			}
			if head != "" && !strings.HasPrefix(head, "sha256:") {
				head = "sha256:" + head
			}
			key := legacyIdentity{legacyGroup, group.GroupID}
			presented[key] = legacyPresentation{InventoryChain: InventoryChain{
				Format: key.format, Chain: key.chain, Seq: int64(group.ShardCount), Record: head,
			}, verdict: string(group.Verdict)}
			return nil
		})
		if err != nil {
			return nil, fmt.Errorf("verify legacy receipt groups: %w", err)
		}
	}
	for _, item := range presented {
		v.result.Legacy = append(v.result.Legacy, LegacyResult{item.Chain, item.Format, item.verdict})
	}
	sortLegacy(v.result.Legacy)
	return presented, nil
}

func readLegacy(path string) (legacyBatch, bool, error) {
	f, err := openEvidence(path)
	if err != nil {
		return legacyBatch{}, false, err
	}
	defer func() { _ = f.Close() }()
	reader := bufio.NewReader(f)
	var batch legacyBatch
	var last *recorder.Entry
	var entryMode string
	for {
		line, err := reader.ReadBytes('\n')
		if err != nil && !errors.Is(err, io.EOF) {
			return batch, false, err
		}
		line = bytes.TrimSpace(line)
		if len(line) == 0 {
			if errors.Is(err, io.EOF) {
				break
			}
			continue
		}
		kind, parseErr := batch.add(line, &last, filepath.Base(path))
		if parseErr != nil || entryMode != "" && entryMode != kind {
			return batch, false, errors.New("malformed or mixed legacy record")
		}
		if kind == "" {
			return batch, false, nil
		}
		entryMode = kind
		if errors.Is(err, io.EOF) {
			break
		}
	}
	return batch, entryMode == "recorder", nil
}

func (b *legacyBatch) add(line []byte, last **recorder.Entry, name string) (string, error) {
	var probe struct {
		RecordType string `json:"record_type"`
		Type       string `json:"type"`
		Version    int    `json:"version"`
		SessionID  string `json:"session_id"`
	}
	if err := json.Unmarshal(line, &probe); err != nil {
		return "", fmt.Errorf("read legacy discriminator: %w", err)
	}
	switch {
	case probe.RecordType == string(contract.RecordTypeEvidenceV2):
		return "evidence", b.addEvidence(line)
	case probe.RecordType == "" && probe.Version == 1 && probe.Type == "":
		return "action", b.addAction(line)
	case probe.Type != "" && probe.SessionID != "":
		entry, err := recorder.ParseEntryLine(line)
		if err != nil {
			return "", fmt.Errorf("parse legacy recorder entry: %w", err)
		}
		if session, start, ok := recorder.ParseEvidenceFilename(name); ok &&
			(session != entry.SessionID || *last == nil && start != entry.Sequence) {
			return "", errors.New("recorder entry disagrees with evidence file name")
		}
		if recorder.ComputeHash(entry) != entry.Hash || *last != nil &&
			((*last).SessionID != entry.SessionID || entry.Sequence != (*last).Sequence+1 || entry.PrevHash != (*last).Hash) {
			return "", errors.New("recorder entry has invalid sequence or hash")
		}
		if *last == nil && entry.Sequence == 0 && entry.PrevHash != recorder.GenesisHash {
			return "", errors.New("recorder entry has invalid genesis hash")
		}
		*last = &entry
		switch entry.Type {
		case "action_receipt":
			return "recorder", b.addAction(entry.RawDetail)
		case "evidence_receipt":
			return "recorder", b.addEvidence(entry.RawDetail)
		}
		return "recorder", nil
	default:
		return "", nil
	}
}

func (b *legacyBatch) addAction(line []byte) error {
	receipt, err := legacy.Unmarshal(line)
	if err != nil {
		return fmt.Errorf("read legacy action receipt: %w", err)
	}
	b.action = append(b.action, receipt)
	return nil
}

func (b *legacyBatch) addEvidence(line []byte) error {
	receipt, err := contract.ParseEvidenceReceipt(line)
	if err != nil {
		return fmt.Errorf("read legacy evidence receipt: %w", err)
	}
	b.evidence = append(b.evidence, receipt)
	return nil
}

func (v *verification) legacyActions(records []legacy.Receipt, keys []string, presented map[legacyIdentity]legacyPresentation, positions map[legacyIdentity]map[int64]string) {
	for len(records) != 0 {
		first := records[0].ActionRecord
		n := 1
		for n < len(records) && records[n].ActionRecord.ChainSeq != 0 {
			n++
		}
		chain := records[:n]
		walker := legacy.NewChainWalker(keys)
		id := first.RunNonce
		if id == "" {
			id, _ = first.Hash()
			id = legacyHash(id)
		}
		key := legacyIdentity{legacyAction, id}
		for _, item := range chain {
			walker.Add(item)
			hash, _ := item.ActionRecord.Hash()
			saveLegacyPosition(positions, key, item.ActionRecord.ChainSeq, hash)
			v.rememberLegacyKey(item.SignerKey)
		}
		result := walker.Result()
		verdict := prefixVerdict
		if legacy.IsGracefulSessionCloseSeal(chain[len(chain)-1]) && first.RunNonce != "" {
			verdict = "VALID"
		}
		last := chain[len(chain)-1].ActionRecord
		hash, _ := last.Hash()
		v.saveLegacy(presented, positions, key, last.ChainSeq, hash, result.Valid, verdict)
		records = records[n:]
	}
}

func (v *verification) legacyEvidence(records []contract.EvidenceReceipt, keys []string, presented map[legacyIdentity]legacyPresentation, positions map[legacyIdentity]map[int64]string) {
	for len(records) != 0 {
		n := 1
		for n < len(records) && records[n].ChainSeq != 0 {
			n++
		}
		chain := records[:n]
		first, _ := contract.ReceiptHash(chain[0])
		key := legacyIdentity{legacyEvidence, legacyHash(first)}
		walker := legacy.NewEvidenceChainWalker(keys, contract.ChainVerifyOptions{})
		for _, item := range chain {
			walker.Add(item)
			hash, _ := contract.ReceiptHash(item)
			saveLegacyPosition(positions, key, item.ChainSeq, hash)
			v.rememberLegacyKey(item.Signature.SignerKeyID)
		}
		last := chain[len(chain)-1]
		hash, _ := contract.ReceiptHash(last)
		v.saveLegacy(presented, positions, key, last.ChainSeq, hash, walker.Result().Valid, prefixVerdict)
		records = records[n:]
	}
}

func legacyHash(text string) string {
	return "sha256:" + strings.TrimPrefix(text, "sha256:")
}

func saveLegacyPosition(positions map[legacyIdentity]map[int64]string, key legacyIdentity, seq uint64, hash string) {
	if positions[key] == nil {
		positions[key] = map[int64]string{}
	}
	if seq > maxInteger {
		positions[key][-1] = "out_of_range"
		return
	}
	pos := int64(seq)
	if previous, found := positions[key][pos]; found && previous != hash {
		positions[key][-1] = "fork"
	}
	positions[key][pos] = hash
}

func (v *verification) saveLegacy(presented map[legacyIdentity]legacyPresentation, positions map[legacyIdentity]map[int64]string, key legacyIdentity, seq uint64, hash string, valid bool, verdict string) {
	if seq > maxInteger {
		v.addCode(codeLegacyInvalid, "")
		return
	}
	position := int64(seq)
	previous, exists := presented[key]
	if !valid {
		v.addCode(codeLegacyInvalid, "")
		verdict = "INVALID"
	}
	forked := positions[key][-1] != ""
	if !exists || position > previous.Seq {
		previous = legacyPresentation{
			InventoryChain: InventoryChain{Chain: key.chain, Format: key.format, Seq: position, Record: legacyHash(hash)},
			verdict:        verdict,
		}
	}
	previous.forked = forked
	presented[key] = previous
}

func (v *verification) rememberLegacyKey(text string) {
	raw, err := hex.DecodeString(text)
	if err == nil && len(raw) == layoutPublicKeyBytes {
		v.used[Digest(raw)] = true
	}
}
