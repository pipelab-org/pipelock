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
	"maps"
	"path/filepath"
	"slices"
	"strconv"
	"strings"

	contract "github.com/luckyPipewrench/pipelock/internal/contract/receipt"
	"github.com/luckyPipewrench/pipelock/internal/evidence/endproof"
	legacy "github.com/luckyPipewrench/pipelock/internal/receipt"
	"github.com/luckyPipewrench/pipelock/internal/recorder"
)

const (
	legacyAction   = "action_v1"
	legacyEvidence = "evidence_v2"
	legacyGroup    = "receipt_group"
	legacyPass     = "pass"
	legacyFailure  = "failure"
	legacyInvalid  = "INVALID"
)

type legacyBatch struct {
	action   []legacy.Receipt
	evidence []contract.EvidenceReceipt
	recorder bool
	session  string
}

func legacyCandidate(name string) bool {
	_, _, isRecorder := recorder.ParseEvidenceFilename(name)
	return isRecorder || isGroupArtifact(name) || name == "activation-receipts.jsonl" ||
		name == "redaction-receipts.jsonl" || name == "ratification-receipts.jsonl"
}

func isGroupArtifact(name string) bool {
	return strings.HasPrefix(name, "receipt-group-") && strings.HasSuffix(name, ".json")
}

func (v *verification) verifyLegacy(paths []string, excluded map[string]bool) (map[legacyIdentity]legacyPresentation, error) {
	presented := map[legacyIdentity]legacyPresentation{}
	if len(paths) == 0 {
		v.checkLegacySelection(presented)
		return presented, v.verifyLegacyEndpoint(presented)
	}
	keys := make([]string, 0, len(v.opts.Keys))
	for _, key := range v.opts.Keys {
		keys = append(keys, hex.EncodeToString(key))
	}
	sessions := map[string]string{}
	groupDirs := map[string]bool{}
	positions := map[legacyIdentity]map[int64]string{}
	bases := map[string]string{}
	verifyBatch := func(batch legacyBatch) {
		v.legacyActions(batch, keys, presented, positions)
		v.legacyEvidence(batch, keys, presented, positions)
	}
	for _, path := range paths {
		name := filepath.Base(path)
		if v.opts.Directory {
			groupDirs[filepath.Dir(path)] = true
			if isGroupArtifact(name) {
				continue
			}
			if session, _, ok := recorder.ParseEvidenceFilename(name); ok {
				sessions[session] = filepath.Dir(path)
				continue
			}
		}
		batch, operational, err := readLegacy(path)
		switch {
		case err != nil:
			v.failedLegacy("", err)
		case len(batch.action) != 0 || len(batch.evidence) != 0:
			verifyBatch(batch)
		case operational && v.opts.Directory || v.skip == codeUnrecognizedFile:
			v.result.IgnoredFiles++
		default:
			v.addCode(codeUnrecognizedFile, "")
		}
	}
	for _, dir := range sortedKeys(groupDirs) {
		groupDirs[dir] = v.verifyLegacyGroups(presented, func(visit func(legacy.ReceiptGroupResult) error) (legacy.ReceiptGroupInventoryResult, error) {
			return legacy.VerifyLegacyReceiptGroups(dir, keys, excluded, visit)
		})
	}
	ordinarySessions := map[string][]string{}
	bareSessions := map[string]bool{}
	for _, session := range sortedKeys(sessions) {
		dir := sessions[session]
		if groupDirs[dir] {
			base, run := legacy.RunSessionBase(session)
			if !run {
				base = session
			}
			ordinary, cached := ordinarySessions[base]
			if !cached {
				var err error
				ordinary, err = legacy.ResolveLegacyBaseSessions(dir, base, excluded)
				if err != nil {
					return nil, fmt.Errorf("list legacy receipt sessions: %w", err)
				}
				ordinarySessions[base] = ordinary
			}
			if !slices.Contains(ordinary, session) {
				continue
			}
		}
		if base, run := legacy.RunSessionBase(session); run {
			bases[base] = dir
		}
		// The session came from top-level input discovery. Its recorder
		// history lives there even if another recorder has a subdirectory.
		root, absErr := filepath.Abs(dir)
		if absErr != nil {
			return nil, fmt.Errorf("resolve legacy receipt directory: %w", absErr)
		}
		location := recorder.EvidenceLocation{Root: root, Dir: root, ExcludedNames: excluded}
		batch := legacyBatch{recorder: true, session: session}
		err := recorder.WithSessionHistorySnapshot(location, session, func() error {
			var readErr error
			batch.action, batch.evidence, readErr = legacy.ReadSessionChains(location, session)
			if readErr == nil && len(batch.evidence) != 0 && len(batch.action) == 0 {
				var bare bool
				bare, readErr = legacy.IsBareEvidenceSession(location, session)
				if bare {
					bareSessions[session] = true
				}
			}
			return readErr
		})
		switch {
		case err != nil:
			v.failedLegacy(session, err)
		case len(batch.action) != 0 || len(batch.evidence) != 0:
			verifyBatch(batch)
		default:
			v.result.IgnoredFiles++
		}
	}
	restartExcluded := maps.Clone(excluded)
	if len(bareSessions) > 0 {
		if restartExcluded == nil {
			restartExcluded = make(map[string]bool)
		}
		for _, path := range paths {
			name := filepath.Base(path)
			if session, _, ok := recorder.ParseEvidenceFilename(name); ok && bareSessions[session] {
				restartExcluded[name] = true
			}
		}
	}
	for _, base := range sortedKeys(bases) {
		dir := bases[base]
		v.verifyLegacyContinuity(dir, base, keys, groupDirs[dir], restartExcluded)
	}
	v.checkLegacySelection(presented)
	if err := v.verifyLegacyEndpoint(presented); err != nil {
		return nil, err
	}
	for _, item := range presented {
		v.result.Legacy = append(v.result.Legacy, v.legacyResult(item))
	}
	sortLegacy(v.result.Legacy)
	return presented, nil
}

type legacyGroupReader func(func(legacy.ReceiptGroupResult) error) (legacy.ReceiptGroupInventoryResult, error)

func (v *verification) verifyLegacyGroups(presented map[legacyIdentity]legacyPresentation, read legacyGroupReader) bool {
	var groups []legacy.ReceiptGroupResult
	summary, err := read(func(group legacy.ReceiptGroupResult) error {
		groups = append(groups, group)
		return nil
	})
	if err != nil {
		verdict := legacy.GroupInvalid
		code := codeLegacyInvalid
		if recorder.IsEvidenceUnavailable(err) {
			verdict, code = legacy.GroupIncomplete, codeLegacyGroupIncomplete
		}
		v.addCode(code, "")
		v.result.Legacy = append(v.result.Legacy, LegacyResult{
			Class: legacyFailure, Format: legacyGroup, Verdict: string(verdict),
		})
		return true
	}
	for _, group := range groups {
		if v.skip == codeLegacyGroupIncomplete && group.Verdict == legacy.GroupIncomplete {
			group.Verdict = legacy.GroupValid
		}
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
	}
	return summary.Groups != 0
}

func (v *verification) verifyLegacyContinuity(dir, base string, keys []string, grouped bool, excluded map[string]bool) {
	report, err := legacy.VerifyBase(dir, base, legacy.BaseVerifyOptions{
		TrustedKeys: keys, ExcludeReceiptGroupSessions: grouped, ExcludedNames: excluded,
	})
	if err == nil && report.Healthy() {
		return
	}
	label := "RESTART CONTINUITY FAILED"
	switch {
	case v.opts.GenericLegacyLabels:
		label = legacyInvalid
	case err != nil:
		label = "RESTART CONTINUITY INCOMPLETE"
	}
	v.addCode(codeLegacyInvalid, "")
	v.result.Legacy = append(v.result.Legacy, LegacyResult{
		Chain: base, Format: legacyAction, Class: legacyFailure, Verdict: label,
	})
}

func (v *verification) checkLegacySelection(presented map[legacyIdentity]legacyPresentation) {
	selection := v.opts.LegacySelection
	if selection.Group != "" {
		_, found := presented[legacyIdentity{legacyGroup, selection.Group}]
		v.accept("expect-legacy-group", selection.Group, found)
	}
	if selection.Session != "" {
		found := false
		for _, row := range presented {
			found = found || row.session == selection.Session
		}
		v.accept("expect-legacy-session", selection.Session, found)
	}
	if selection.Bindings != nil {
		found := false
		for _, row := range presented {
			found = found || row.Format == legacyEvidence && (selection.Session == "" || row.session == selection.Session)
		}
		if !found {
			v.accept("expect-legacy-v2", "evidence_v2", false)
		}
	}
}

func (v *verification) verifyLegacyEndpoint(presented map[legacyIdentity]legacyPresentation) error {
	end := v.opts.LegacyEnd
	if end == nil {
		return nil
	}
	selection := v.opts.LegacySelection
	// A selected session can hold an action chain and an evidence chain written
	// side by side. As for a legacy directory, the endpoint pins the evidence
	// chain; the action chain is still verified, without an endpoint.
	evidenceOnly := selection.Bindings != nil
	if selection.Session != "" {
		for key, item := range presented {
			evidenceOnly = evidenceOnly || key.format == legacyEvidence && item.session == selection.Session
		}
	}
	var target legacyIdentity
	for key, item := range presented {
		if key.format == legacyGroup || selection.Session != "" && item.session != selection.Session ||
			evidenceOnly && key.format != legacyEvidence {
			continue
		}
		if target.format != "" {
			return errors.New("legacy endpoint expectations require exactly one legacy chain")
		}
		target = key
	}
	if target.format == "" {
		// A chain that could not be read already has a failure diagnostic.
		if len(v.result.Legacy) != 0 {
			return nil
		}
		return errors.New("legacy endpoint expectations require exactly one legacy chain")
	}
	item := presented[target]
	if item.verdict == legacyInvalid || item.forked || item.Seq < 0 {
		return nil
	}
	if _, err := endproof.Pin(item.cliHead, item.cliSeq, end.Head, end.Sequence); err != nil {
		v.accept("expect-legacy-end", target.chain, false)
		item.verdict = legacyInvalid
	} else {
		if end.Head != "" {
			v.accept("expect-legacy-head", end.Head, true)
		}
		if end.Sequence != nil {
			v.accept("expect-legacy-seq", strconv.FormatUint(*end.Sequence, 10), true)
		}
		item.verdict = endproof.Valid
	}
	presented[target] = item
	return nil
}

func (v *verification) failedLegacy(chain string, err error) {
	label := "CHAIN BROKEN"
	if recorder.IsEvidenceUnavailable(err) {
		label = "CHAIN UNAVAILABLE"
	}
	v.addCode(codeLegacyInvalid, "")
	v.result.Legacy = append(v.result.Legacy, LegacyResult{
		Chain: chain, Format: legacyAction, Class: legacyFailure, Verdict: label,
	})
}

func (v *verification) legacyResult(item legacyPresentation) LegacyResult {
	row := LegacyResult{Chain: item.Chain, Format: item.Format, Class: legacyPass, Verdict: item.verdict}
	if item.Format == legacyGroup {
		if item.verdict != string(legacy.GroupValid) {
			row.Class = legacyFailure
		}
		return row
	}
	label := "CHAIN"
	if item.Format == legacyEvidence && !v.opts.GenericLegacyLabels {
		label = "EVIDENCE CHAIN"
	}
	switch {
	case item.verdict == legacyInvalid || item.forked:
		row.Class, row.Verdict = legacyFailure, label+" BROKEN"
	case item.verdict == prefixVerdict:
		if !v.opts.AllowPrefix || len(v.opts.Keys) == 0 && !v.opts.AllowUnpinned {
			row.Class = legacyFailure
		}
	case len(v.opts.Keys) == 0:
		row.Verdict = label + " UNPINNED"
		if !v.opts.AllowUnpinned {
			row.Class = legacyFailure
		}
	default:
		row.Verdict = label + " VALID"
	}
	return row
}

func readLegacy(path string) (legacyBatch, bool, error) {
	f, err := openEvidence(path)
	if err != nil {
		return legacyBatch{}, false, err
	}
	defer func() { _ = f.Close() }()
	reader := bufio.NewReader(f)
	var line []byte
	var batch legacyBatch
	var last *recorder.Entry
	var entryMode string
	for {
		fragment, err := reader.ReadSlice('\n')
		if len(line)+len(fragment) > recorder.MaxEntryLineBytes+2 {
			return batch, false, errors.New("line exceeds recorder entry limit")
		}
		line = append(line, fragment...)
		if errors.Is(err, bufio.ErrBufferFull) {
			continue
		}
		if err != nil && !errors.Is(err, io.EOF) {
			return batch, false, err
		}
		payload := bytes.TrimSuffix(line, []byte{'\n'})
		if len(payload) < len(line) {
			payload = bytes.TrimSuffix(payload, []byte{'\r'})
		}
		if len(payload) > recorder.MaxEntryLineBytes {
			return batch, false, errors.New("line exceeds recorder entry limit")
		}
		text := bytes.TrimSpace(payload)
		line = line[:0]
		if len(text) == 0 {
			if errors.Is(err, io.EOF) {
				break
			}
			continue
		}
		kind, parseErr := batch.add(text, &last, filepath.Base(path))
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
	batch.recorder = entryMode == "recorder"
	return batch, batch.recorder, nil
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

func (v *verification) legacyActions(batch legacyBatch, keys []string, presented map[legacyIdentity]legacyPresentation, positions map[legacyIdentity]map[int64]string) {
	records := batch.action
	for len(records) != 0 {
		first := records[0].ActionRecord
		n := 1
		for n < len(records) {
			record := records[n].ActionRecord
			if !batch.recorder && record.ChainSeq == 0 && record.KeyTransition == nil {
				break
			}
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
		for pos, item := range chain {
			if v.skip != codeLegacyInvalid {
				walker.Add(item)
			}
			hash, _ := item.ActionRecord.Hash()
			// A verified key transition restarts chain_seq at zero.
			// Detect competing records by position in the whole chain.
			saveLegacyPosition(positions, key, uint64(pos), hash)
			v.rememberLegacyKey(item.SignerKey)
		}
		result := walker.Result()
		verdict := prefixVerdict
		if len(endproof.ActionEvidence(chain)) > 0 {
			verdict = endproof.Valid
		}
		last := chain[len(chain)-1].ActionRecord
		hash, _ := last.Hash()
		item := legacyPresentation{
			InventoryChain: InventoryChain{Chain: key.chain, Format: key.format, Record: legacyHash(hash)},
			verdict:        verdict, cliHead: result.RootHash, cliSeq: last.ChainSeq, session: batch.session,
		}
		v.saveLegacy(presented, positions, item, uint64(len(chain))-1, v.skip == codeLegacyInvalid || result.Valid)
		records = records[n:]
	}
}

func (v *verification) legacyEvidence(batch legacyBatch, keys []string, presented map[legacyIdentity]legacyPresentation, positions map[legacyIdentity]map[int64]string) {
	records := batch.evidence
	for len(records) != 0 {
		n := 1
		for n < len(records) && (batch.recorder || records[n].ChainSeq != 0) {
			n++
		}
		chain := records[:n]
		first, _ := contract.ReceiptHash(chain[0])
		key := legacyIdentity{legacyEvidence, legacyHash(first)}
		var verifyOptions contract.ChainVerifyOptions
		selection := v.opts.LegacySelection
		if selection.Bindings != nil && (selection.Session == "" || selection.Session == batch.session) {
			verifyOptions = *selection.Bindings
		}
		walker := legacy.NewEvidenceChainWalker(keys, verifyOptions)
		for _, item := range chain {
			walker.Add(item)
			hash, _ := contract.ReceiptHash(item)
			saveLegacyPosition(positions, key, item.ChainSeq, hash)
			v.rememberLegacyKey(item.Signature.SignerKeyID)
		}
		last := chain[len(chain)-1]
		hash, _ := contract.ReceiptHash(last)
		result := walker.Result()
		item := legacyPresentation{
			InventoryChain: InventoryChain{Chain: key.chain, Format: key.format, Record: legacyHash(hash)},
			verdict:        prefixVerdict, cliHead: result.RootHash, cliSeq: last.ChainSeq, session: batch.session,
		}
		v.saveLegacy(presented, positions, item, last.ChainSeq, result.Valid)
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

func (v *verification) saveLegacy(presented map[legacyIdentity]legacyPresentation, positions map[legacyIdentity]map[int64]string, item legacyPresentation, seq uint64, valid bool) {
	if seq > maxInteger || item.cliSeq > maxInteger {
		v.addCode(codeLegacyInvalid, "")
		return
	}
	// Use chain order to select the longest presentation and the signed sequence
	// for the cutover row. A rotation can reset the signed sequence.
	item.position = int64(seq)
	item.Seq = int64(item.cliSeq)
	key := legacyIdentity{item.Format, item.Chain}
	item.positions = positions[key]
	previous, exists := presented[key]
	wasInvalid := previous.verdict == legacyInvalid
	if !exists || item.position > previous.position {
		previous = item
	}
	if !valid {
		v.addCode(codeLegacyInvalid, "")
	}
	if !valid || wasInvalid {
		previous.verdict = legacyInvalid
	}
	previous.forked = positions[key][-1] != ""
	presented[key] = previous
}

func (v *verification) rememberLegacyKey(text string) {
	raw, err := hex.DecodeString(text)
	if err == nil && len(raw) == layoutPublicKeyBytes {
		v.used[Digest(raw)] = true
	}
}
