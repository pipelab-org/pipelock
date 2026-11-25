// Copyright 2026 Pipelab
// SPDX-License-Identifier: Apache-2.0

package v3

import (
	"cmp"
	"database/sql"
	"errors"
	"fmt"
	"slices"
	"strconv"
)

func (v *verification) verifySuccession() error {
	for _, id := range sortedKeys(v.streams) {
		stream := v.streams[id]
		if p := stream.body.Previous; p != nil {
			parent := v.streams[p.Stream]
			switch {
			case parent == nil || parent.open.id == "" && len(parent.contenders) == 0:
				if v.skip != codePredecessorNotPresented {
					stream.missing = true
					v.add(stream.open.finding(codePredecessorNotPresented))
				}
			default:
				parent.successors = append(parent.successors, stream)
			}
		}
	}
	for _, id := range sortedKeys(v.streams) {
		parent := v.streams[id]
		for _, child := range parent.successors {
			if v.skip != codeSuccessionFork && len(parent.successors) > 1 {
				v.add(child.open.finding(codeSuccessionFork))
			}
			if parent.open.id != "" {
				if err := v.checkPin(parent, child); err != nil {
					return err
				}
			}
		}
		parent.setSummary()
	}
	return nil
}

func (v *verification) checkPin(parent, child *verifiedStream) error {
	pin := child.body.Previous
	sameLineage := parent.body.Lineage == child.body.Lineage
	if v.skip != codeLineageMismatch && !sameLineage && parent.body.Lineage != "" {
		v.add(child.open.finding(codeLineageMismatch))
	}
	id, kind, err := v.store.pin(v.ctx, pin.Stream, pin.Seq, parent.limit)
	if err != nil {
		// The pin was physically absent or beyond the verified shared prefix.
		if errors.Is(err, sql.ErrNoRows) {
			if v.skip != codePredecessorTruncated {
				v.add(child.open.finding(codePredecessorTruncated))
				return nil
			}
			id = pin.Record
			if pin.Ended == "closed" {
				kind = kindStreamClose
			}
		} else {
			return fmt.Errorf("look up predecessor pin: %w", err)
		}
	}
	if v.skip != codePinMismatch && (id != pin.Record || pin.Ended == "closed" && kind != kindStreamClose ||
		pin.Ended == "unsealed" && kind == kindStreamClose) {
		v.add(child.open.finding(codePinMismatch))
		return nil
	}
	if pin.Ended != "write_error" {
		if v.skip != codeTailAfterSuccession && parent.last.Seq > pin.Seq {
			v.add(child.open.finding(codeTailAfterSuccession))
		}
		return nil
	}
	if v.skip == codeUnconfirmed || len(parent.successors) != 1 || !sameLineage || len(parent.contenders) > 0 {
		return nil
	}
	parent.limit = pin.Seq
	parent.confirmedWriteError = true
	if parent.last.Seq > pin.Seq {
		if err := v.store.walk(v.ctx, pin.Stream, parent.last.Seq, func(record stagedRecord) error {
			if record.Seq > pin.Seq {
				v.add(record.finding(codeUnconfirmed))
			}
			return nil
		}); err != nil {
			return err
		}
	}
	return nil
}

func (s *verifiedStream) setSummary() {
	s.summary.Stream, s.summary.Signer = s.open.Stream, s.open.Signer
	if s.body.Previous != nil {
		s.summary.Previous = s.body.Previous.Stream
	}
	if s.last.id != "" {
		s.summary.Last, s.summary.Tip = s.last.position(), s.last.position()
	}
	s.summary.End = "open"
	switch {
	case len(s.contenders) > 0:
		s.summary.End = "forked"
	case s.last.Kind == kindStreamClose:
		s.summary.End = "closed"
	}
	switch {
	case len(s.successors) > 1:
		s.summary.Tip = nil
	case len(s.successors) == 1 && len(s.contenders) == 0:
		child := s.successors[0]
		pin := child.body.Previous
		switch {
		case pin.Ended == "unsealed" && s.last.id == pin.Record && s.last.Seq == pin.Seq &&
			s.last.Kind != kindStreamClose && s.body.Lineage == child.body.Lineage:
			s.summary.End = "superseded_unsealed"
		case pin.Ended == "write_error" && s.confirmedWriteError:
			s.summary.End = "superseded_write_error"
			s.summary.Tip = &Position{pin.Record, pin.Seq}
			s.summary.Records = pin.Seq + 1
			from := pin.Seq + 1
			s.summary.UnconfirmedFrom = &from
		}
	}
}

type segment struct {
	streams []*verifiedStream
	rooted  bool
}

func (v *verification) segments(members []*verifiedStream) []segment {
	next := map[*verifiedStream]*verifiedStream{}
	hasParent := map[*verifiedStream]bool{}
	rootCount := 0
	for _, member := range members {
		if member.body.Previous == nil {
			rootCount++
		}
		if len(member.contenders) == 0 && len(member.successors) == 1 {
			child := member.successors[0]
			if child.body.Lineage == member.body.Lineage {
				next[member] = child
				hasParent[child] = true
			}
		}
	}
	if v.skip != codeRootFork && rootCount > 1 {
		for _, member := range members {
			if member.body.Previous == nil {
				v.add(member.open.finding(codeRootFork))
			}
		}
	}
	var pieces []segment
	appendFrom := func(start *verifiedStream) {
		open := segment{rooted: start.body.Previous == nil}
		for current := start; current != nil && current.segment < 0; current = next[current] {
			current.segment = len(pieces)
			open.streams = append(open.streams, current)
		}
		pieces = append(pieces, open)
	}
	forked := false
	for _, member := range members {
		forked = forked || len(member.contenders) != 0 || len(member.successors) > 1
		if !hasParent[member] {
			appendFrom(member)
		}
	}
	for _, member := range members {
		if member.segment < 0 {
			appendFrom(member)
			forked = true
		}
	}
	if v.skip != codeHistoryDisconnected && (len(pieces) != 1 || forked) {
		v.addCode(codeHistoryDisconnected, members[0].open.Stream)
	}
	return pieces
}

func (v *verification) checkExpectations(cutoverEnds map[string]stagedRecord) {
	for _, wanted := range v.opts.AcceptDiscontinuities {
		if _, ok := cutoverEnds[wanted]; ok {
			v.accept("accept-discontinuity", wanted, true)
			continue
		}
		var found bool
		for _, stream := range v.streams {
			pin := stream.body.Previous
			if stream.open.id == wanted && pin != nil && (pin.Ended == "write_error" || pin.Ended == "unsealed") {
				found = true
				break
			}
		}
		v.accept("accept-discontinuity", wanted, found)
	}
	for _, id := range v.opts.AllowPartialHistories {
		s := v.streams[id]
		v.accept("allow-partial-history", id, s != nil && s.missing)
	}
	proved := map[string]bool{}
	for _, expected := range v.opts.ExpectHeads {
		tip := v.tip(expected.Stream)
		found := tip != nil && *tip == expected.Position
		v.accept("expect-head", expected.Stream+":"+strconv.FormatInt(expected.Seq, 10)+":"+expected.Record, found)
		if found {
			proved[expected.Stream] = true
		}
	}
	for _, expected := range v.opts.ExpectSequences {
		tip := v.tip(expected.Stream)
		found := tip != nil && tip.Seq == expected.Seq
		v.accept("expect-seq", expected.Stream+":"+strconv.FormatInt(expected.Seq, 10), found)
		if found {
			proved[expected.Stream] = true
		}
	}
	if v.opts.ExpectLineage != "" {
		v.accept("expect-lineage", v.opts.ExpectLineage, len(v.histories[v.opts.ExpectLineage]) != 0)
	}
	if v.opts.AllowPrefix {
		v.accept("allow-prefix", "true", true)
	}
	if v.opts.AllowUnpinned {
		v.accept("allow-unpinned", "true", true)
	}
	for _, id := range sortedKeys(cutoverEnds) {
		v.add(cutoverEnds[id].finding(codeLegacyEndUnproven))
	}
	for _, id := range sortedKeys(v.streams) {
		stream := v.streams[id]
		if v.skip == codeEndUnproven || stream.open.id == "" || proved[id] {
			continue
		}
		switch stream.summary.End {
		case "open":
			v.add(stream.last.finding(codeEndUnproven))
		case "superseded_unsealed", "superseded_write_error":
			// Acceptance names the successor's first record.
			successor := stream.successors[0].open
			if !slices.Contains(v.opts.AcceptDiscontinuities, successor.id) {
				v.add(successor.finding(codeEndUnproven))
			}
		}
	}
	for _, lineage := range sortedKeys(v.histories) {
		members := v.histories[lineage]
		streams := make([]StreamResult, 0, len(members))
		for _, member := range members {
			streams = append(streams, member.summary)
		}
		slices.SortFunc(streams, func(a, b StreamResult) int { return cmp.Compare(a.Stream, b.Stream) })
		v.result.Histories = append(v.result.Histories, HistoryResult{Lineage: lineage, Streams: streams})
	}
}

func (v *verification) accept(kind, value string, satisfied bool) {
	if v.skip != codeExpectationNotMet && !satisfied {
		v.addCode(codeExpectationNotMet, "")
		return
	}
	v.result.Accepted = append(v.result.Accepted, Acceptance{Kind: kind, Value: value})
}

func (v *verification) tip(stream string) *Position {
	if s := v.streams[stream]; s != nil {
		return s.summary.Tip
	}
	return nil
}
