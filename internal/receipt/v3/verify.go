// Copyright 2026 Pipelab
// SPDX-License-Identifier: Apache-2.0

package v3

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/luckyPipewrench/pipelock/internal/recorder"
)

type verification struct {
	ctx       context.Context
	opts      Options
	result    Result
	store     *recordStore
	keys      map[string]validatedKey
	trusted   map[string]bool
	used      map[string]bool
	streams   map[string]*verifiedStream
	contested map[string][]stagedRecord
	histories map[string][]*verifiedStream
	skip      string

	actionVersionNeeded int64
}

type verifiedStream struct {
	open       stagedRecord
	body       StreamOpen
	last       stagedRecord
	limit      int64
	contenders []stagedRecord
	successors []*verifiedStream
	missing    bool
	segment    int
	broken     bool
	summary    StreamResult
}

type tornFile struct {
	start int64
	last  stagedRecord
}

type fileState struct {
	stream      string
	start       int64
	last        stagedRecord
	broken      bool
	afterDamage bool
	torn        bool
	complete    bool
}

func (v *verification) add(f Finding) {
	v.result.Findings = append(v.result.Findings, f)
}

func (v *verification) addCode(code, stream string) {
	v.add(Finding{Class: findingClasses[code], Code: code, Stream: stream})
}

func (v *verification) addStream(stream string) *verifiedStream {
	if existing := v.streams[stream]; existing != nil {
		return existing
	}
	s := &verifiedStream{limit: maxInteger, segment: -1}
	v.streams[stream] = s
	return s
}

// VerifyPaths verifies v3 evidence in directory scope or an explicit file set.
// Callers with a legacy-only invocation keep their existing verification path.
func VerifyPaths(ctx context.Context, paths []string, opts Options) (Result, error) {
	return verifyPaths(ctx, paths, opts, "")
}

func verifyPaths(ctx context.Context, paths []string, opts Options, skip string) (Result, error) {
	return verifyPathsInspect(ctx, paths, opts, skip, nil)
}

func verifyPathsInspect(ctx context.Context, paths []string, opts Options, skip string, inspect func(*verification) error) (Result, error) {
	if err := opts.validate(); err != nil {
		return Result{}, err
	}
	if opts.ExplicitV3 && len(paths) != 1 {
		return Result{}, errors.New("explicit v3 format requires exactly one file")
	}
	files, legacy, inventories, ignored, err := discover(paths, opts, skip)
	if err != nil {
		return Result{}, err
	}
	store, err := newStore(ctx)
	if err != nil {
		return Result{}, err
	}
	defer store.close()
	v := verification{
		ctx: ctx, opts: opts, result: newResult(opts), store: store, skip: skip,
		keys: map[string]validatedKey{}, trusted: map[string]bool{}, used: map[string]bool{},
		streams: map[string]*verifiedStream{}, contested: map[string][]stagedRecord{},
		histories: map[string][]*verifiedStream{},
	}
	v.result.IgnoredFiles = ignored
	for _, key := range opts.Keys {
		id := Digest(key)
		v.keys[id], v.trusted[id] = validateKey(key), true
	}
	for _, file := range files {
		if err := v.discoverKey(file); err != nil {
			return Result{}, err
		}
	}
	if err := v.stageFiles(files); err != nil {
		return Result{}, err
	}
	if err := v.verifyStreams(); err != nil {
		return Result{}, err
	}
	if err := v.verifySuccession(); err != nil {
		return Result{}, err
	}
	cutoverEnds, err := v.verifyCutover(legacy, inventories, files)
	if err != nil {
		return Result{}, err
	}
	if err := v.appraiseDecisions(); err != nil {
		return Result{}, err
	}
	v.checkExpectations(cutoverEnds)
	v.result.Trust.Keys = sortedKeys(v.used)
	if len(files) == 0 && len(v.result.Legacy) != 0 {
		return Result{}, errors.New("legacy-only evidence requires the legacy verification path")
	}
	if v.skip != codeNoEvidence && len(files) == 0 && len(v.result.Findings) == 0 {
		v.addCode(codeNoEvidence, "")
	}
	v.result.finish(opts)
	if inspect != nil {
		if err := inspect(&v); err != nil {
			return Result{}, err
		}
	}
	return v.result, nil
}

func openEvidence(path string) (*os.File, error) {
	realPath, err := filepath.EvalSymlinks(path)
	if err != nil {
		return nil, fmt.Errorf("resolve evidence path: %w", err)
	}
	file, _, err := recorder.OpenEvidenceFile(realPath)
	if err != nil {
		return nil, fmt.Errorf("open evidence: %w", err)
	}
	return file, nil
}

func (v *verification) discoverKey(input inputFile) error {
	if input.code != "" || input.start > 0 {
		return nil
	}
	file, err := openEvidence(input.path)
	if err != nil {
		return err
	}
	defer func() { _ = file.Close() }()
	line, complete, err := readBounded(v.ctx, bufio.NewReaderSize(file, maxLineBytes+1))
	if err != nil {
		return fmt.Errorf("read opening record: %w", err)
	}
	if !complete {
		return nil
	}
	record, code := parseLine(line, v.skip)
	if code != "" || record.Seq != 0 || record.Kind != kindStreamOpen {
		return nil
	}
	key, _ := record.values["signer_key"].(map[string]any)
	public, _ := key["public"].(string)
	raw, valid := decodeBase64(public, layoutPublicKeyBytes)
	if !valid || Digest(raw) != record.Signer {
		return nil
	}
	if _, exists := v.keys[record.Signer]; !exists {
		v.keys[record.Signer] = validateKey(raw)
	}
	return nil
}

func (v *verification) stageFiles(files []inputFile) error {
	return v.store.stage(v.ctx, func(write recordWriter) error {
		return v.stageInputFiles(files, write)
	})
}

func (v *verification) stageInputFiles(files []inputFile, write recordWriter) error {
	maxStarts := map[string]int64{}
	var tails []tornFile
	for _, file := range files {
		state, err := v.stageFile(file, write)
		if err != nil {
			return err
		}
		if !state.complete {
			continue
		}
		if previous, ok := maxStarts[state.stream]; !ok || previous < state.start {
			maxStarts[state.stream] = state.start
		}
		if state.torn {
			tails = append(tails, tornFile{state.start, state.last})
		}
	}
	for _, tail := range tails {
		switch {
		case tail.last.Kind == kindStreamClose:
			if v.skip == codeDataAfterClose {
				continue
			}
			v.add(tail.last.finding(codeDataAfterClose))
		case tail.start < maxStarts[tail.last.Stream]:
			v.addCode(codeFileLayout, tail.last.Stream)
		default:
			v.add(tail.last.finding(codeTornTail))
		}
	}
	return nil
}

func (v *verification) stageFile(input inputFile, write recordWriter) (fileState, error) {
	state := fileState{stream: input.stream, start: input.start}
	if v.skip == codeFileLayout && input.code == "" {
		state = fileState{start: -1}
	}
	if input.code != "" {
		v.addCode(input.code, state.stream)
		return state, nil
	}
	file, err := openEvidence(input.path)
	if err != nil {
		return state, err
	}
	defer func() { _ = file.Close() }()
	limit := maxLineBytes + 1
	if v.skip == codeLineSize {
		limit++
	}
	reader := bufio.NewReaderSize(file, limit)
	for offset := int64(0); ; offset++ {
		if err := v.ctx.Err(); err != nil {
			return state, err
		}
		line, complete, err := readBounded(v.ctx, reader)
		if err != nil {
			return state, fmt.Errorf("read receipt file: %w", err)
		}
		if !complete {
			if !state.complete && !state.broken {
				v.addCode(codeFileLayout, state.stream)
			} else if state.complete && len(line) != 0 {
				state.torn = v.skip != codeTornTail
			}
			return state, nil
		}
		if !v.stageLine(line, &state, offset, write, &err) {
			state.broken = true
			state.afterDamage = true
			if err != nil {
				return state, err
			}
		}
	}
}

func (v *verification) stageLine(line []byte, state *fileState, offset int64, write recordWriter, outErr *error) bool {
	record, code := parseLine(line, v.skip)
	if code != "" {
		v.addCode(code, state.stream)
		return false
	}
	if code = checkSignature(record, v.keys[record.Signer], v.skip); code != "" {
		v.addCode(code, state.stream)
		return false
	}
	item := stagedRecord{Common: record.Common, id: record.ID}
	v.used[record.Signer] = true
	if !state.complete {
		if offset == 0 && state.start >= 0 && (state.stream != record.Stream || state.start != record.Seq) {
			v.add(item.finding(codeFileLayout))
			return false
		}
		if state.start < 0 {
			state.stream, state.start = record.Stream, record.Seq-offset
		}
	}
	if v.skip != codeStreamOrder && (record.Stream != state.stream || !state.broken && record.Seq != state.start+offset) {
		v.add(item.finding(codeStreamOrder))
		return false
	}
	if v.skip != codeDataAfterClose && offset > 0 && state.last.Kind == kindStreamClose {
		v.add(item.finding(codeDataAfterClose))
		return false
	}
	if localOrderFailure(record, state) && v.skip != codeStreamOrder {
		v.add(item.finding(codeStreamOrder))
		return false
	}
	unknown, code := checkBody(record, v.skip)
	state.complete = true
	state.last = item
	v.addStream(state.stream)
	item.unknown, item.bodyCode, item.afterDamage = unknown, code, state.afterDamage
	if err := write(v.ctx, item, record.Payload); err != nil {
		*outErr = fmt.Errorf("stage verified record: %w", err)
		return false
	}
	state.afterDamage = false
	return true
}

func localOrderFailure(record Record, state *fileState) bool {
	if state.broken {
		return false
	}
	if record.Seq == 0 {
		// Compare claims at position zero before deciding whether any one
		// of them can open the stream.
		return false
	}
	if record.Kind == kindStreamOpen {
		return true
	}
	return state.last.id != "" && (record.Prev != state.last.id || record.Signer != state.last.Signer)
}

func checkBody(r Record, skip string) (bool, string) {
	if skip != codeUnknownCrit && len(r.Crit) != 0 {
		return true, codeUnknownCrit
	}
	kind, known := wireKinds[r.Kind]
	if !known || r.BodyV != kind.version && (skip != codeUnknownControl || !kind.control) {
		if known && kind.control {
			return true, codeUnknownControl
		}
		return true, ""
	}
	if r.Kind == kindAction {
		unknown, valid := matchObject(r.values, kind.body)
		if skip != codeBodySchema && !valid {
			return false, codeBodySchema
		}
		// The structural check also protects the typed field reads below.
		if valid && !actionFields(r.values) {
			return false, codeBodySchema
		}
		return unknown, ""
	}
	unknown, valid := matchObject(r.values, kind.body)
	if !valid {
		return false, codeBodySchema
	}
	if skip != codeUnknownControl && unknown && kind.control {
		return true, codeUnknownControl
	}
	switch r.Kind {
	case kindStreamOpen:
		previous, cutover := r.values["previous"], r.values["legacy_cutover"]
		if (previous == nil) == (cutover == nil) {
			return false, codeBodySchema
		}
		coverage := r.values["coverage"].(map[string]any)
		if !sortedStrings(coverage["surfaces"], false) {
			return false, codeBodySchema
		}
		signer := r.values["signer_key"].(map[string]any)
		raw, _ := decodeBase64(signer["public"].(string), layoutPublicKeyBytes)
		if Digest(raw) != r.Signer {
			return false, codeBodySchema
		}
	case kindStreamClose:
		if r.values["records"] != r.Seq+1 {
			return false, codeBodySchema
		}
	}
	return unknown, ""
}

func actionFields(fields map[string]any) bool {
	policy := fields["policy"].(map[string]any)
	if policy["source"] == "writer_config" {
		return false
	}
	if hold, ok := fields["hold"].(map[string]any); ok {
		switch fields["phase"] {
		case "hold":
			if hold["policy"] == nil || hold["correction"] != nil ||
				hold["resolution_policy"] != nil || hold["resolution_source"] != nil {
				return false
			}
		case "resolution":
			if hold["policy"] != nil || hold["parent"] != nil ||
				hold["resolution_policy"] == nil || hold["resolution_source"] == nil {
				return false
			}
		}
	}
	if redaction, ok := fields["redaction"].(map[string]any); ok {
		classes, _ := redaction["classes"].([]any)
		last := ""
		for _, entry := range classes {
			class := entry.(map[string]any)["class"].(string)
			if class <= last {
				return false
			}
			last = class
		}
	}
	return true
}

func unmarshalBody[T any](r stagedRecord) (T, error) {
	var body T
	if err := json.Unmarshal(r.Body, &body); err != nil {
		return body, fmt.Errorf("decode verified body: %w", err)
	}
	return body, nil
}

// Check the body and trust only after establishing the record's position.
func (v *verification) checkStagedBody(current stagedRecord) bool {
	if current.bodyCode != "" {
		v.add(current.finding(current.bodyCode))
		return findingClasses[current.bodyCode] != invalid
	}
	if v.skip != codeTrust && len(v.trusted) != 0 && !v.trusted[current.Signer] {
		v.add(current.finding(codeTrust))
	}
	return true
}

func (v *verification) verifyStreams() error {
	for _, id := range sortedKeys(v.streams) {
		s := v.streams[id]
		if err := v.verifyStream(id, s); err != nil {
			return err
		}
		if s.broken {
			s.open, s.last, s.body = stagedRecord{}, stagedRecord{}, StreamOpen{}
			continue
		}
		if s.open.Kind == kindStreamOpen && !s.open.unknown {
			v.histories[s.body.Lineage] = append(v.histories[s.body.Lineage], s)
		}
	}
	return nil
}

func (v *verification) verifyStream(id string, s *verifiedStream) error {
	var previous stagedRecord
	var beat int64
	publish := func(current stagedRecord) error {
		prior := s.last
		s.last = current
		var orderCode string
		switch {
		case prior.id == "":
			if current.Seq != 0 || current.Kind != kindStreamOpen || current.Prev != Genesis(id) {
				orderCode = codeStreamOrder
			}
		case prior.Kind == kindStreamClose:
			orderCode = codeDataAfterClose
		case current.Seq != prior.Seq+1 || current.Prev != prior.id ||
			current.Signer != prior.Signer || current.Kind == kindStreamOpen:
			orderCode = codeStreamOrder
		}
		// A damaged physical predecessor can explain a missing position, but
		// a second, intact copy of this record still has to pass the check.
		if orderCode == codeStreamOrder && current.afterDamage &&
			(current.Seq > prior.Seq+1 || prior.id == "" && current.Seq > 0) {
			s.broken = true
			v.checkStagedBody(current)
			return nil
		}
		if orderCode != "" && orderCode != v.skip {
			v.add(current.finding(orderCode))
			return nil
		}
		if !v.checkStagedBody(current) {
			s.broken = true
			return nil
		}
		if current.Seq == 0 && current.Kind == kindStreamOpen {
			s.open = current
			if !current.unknown {
				body, err := unmarshalBody[StreamOpen](current)
				if err != nil {
					return err
				}
				s.body = body
			}
		}
		if v.skip != codeClockRegression && prior.id != "" && current.TS < prior.TS {
			v.add(current.finding(codeClockRegression))
		}
		if current.Kind == kindHeartbeat && !current.unknown {
			h, err := unmarshalBody[Heartbeat](current)
			if err != nil {
				return err
			}
			beat++
			if v.skip != codeHeartbeatGap && h.Beat != beat {
				v.add(current.finding(codeHeartbeatGap))
			}
		}
		s.summary.Records++
		return nil
	}
	err := v.store.walk(v.ctx, id, maxInteger, func(current stagedRecord) error {
		if len(s.contenders) != 0 {
			if current.Seq == s.contenders[0].Seq {
				s.contenders = append(s.contenders, current)
			}
			return nil
		}
		if previous.id != "" {
			if previous.Seq == current.Seq && v.skip != codeFork {
				s.contenders = []stagedRecord{previous, current}
				return nil
			}
			if err := publish(previous); err != nil {
				return err
			}
		}
		previous = current
		return nil
	})
	if err != nil {
		return err
	}
	if len(s.contenders) > 0 {
		s.limit = s.contenders[0].Seq - 1
		for _, record := range s.contenders {
			v.add(record.finding(codeFork))
		}
		if s.limit < 0 {
			v.contested[id] = s.contenders
			ids := make([]string, 0, len(s.contenders))
			for _, candidate := range s.contenders {
				ids = append(ids, candidate.id)
			}
			v.result.ContestedStreams = append(v.result.ContestedStreams, ContestedStream{Records: ids, Stream: id})
		}
		return nil
	}
	if previous.id != "" {
		return publish(previous)
	}
	return nil
}
