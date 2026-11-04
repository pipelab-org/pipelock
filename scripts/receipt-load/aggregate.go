// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"errors"
	"fmt"
	"net/http"

	"github.com/luckyPipewrench/pipelock/internal/receipt"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

// Destination-only receipts cannot identify a planned request. Keep their
// counts separate from slots instead of guessing an identity from ordering.
// The forward producer contract is expectedFor, proxy/forward.go (empty layer
// for phase-less allows and intents, proxy.go's outcome layer for outcomes,
// scanner.ScannerCoreDLP for synthetic credential blocks) and v2receipt.go
// (scanner provenance; v2 does not contain the v1 layer or ActionID).
type aggregateBucket struct{ session, verdict string }

type aggregateActionInput struct {
	session, id, method, transport, action, phase, verdict, layer string
}

type aggregateAction struct {
	session string
	blocked bool
	counts  [kindCount]int
}

type aggregateObservation struct {
	counts  [kindCount]int
	actions map[string]*aggregateAction
	v1      map[aggregateBucket]int
	v2      map[aggregateBucket]int
}

func (s *recorderScanner) aggregateObservation() *aggregateObservation {
	if s.obs.aggregate == nil {
		s.obs.aggregate = &aggregateObservation{
			actions: make(map[string]*aggregateAction),
			v1:      make(map[aggregateBucket]int),
			v2:      make(map[aggregateBucket]int),
		}
	}
	return s.obs.aggregate
}

func (s *recorderScanner) observeAggregateV1(in aggregateActionInput) error {
	kind := v1Kind(in.phase, in.verdict)
	wantLayer := ""
	if kind == kindV1Outcome {
		wantLayer = "outcome"
	}
	blocked := in.verdict == verdictBlock
	if in.id == "" || in.method != http.MethodGet || in.transport != workloadTransport || in.action != string(receipt.ActionRead) ||
		kind == kindV1Other || ((kind == kindV1Intent || kind == kindV1Outcome) && in.verdict != verdictAllow) ||
		(blocked && in.layer != scanner.ScannerCoreDLP) || (!blocked && in.layer != wantLayer) {
		return errors.New("aggregate v1 receipt differs from the planned request or layer")
	}
	if _, control := s.controlIDs[in.id]; control {
		return errors.New("aggregate ActionID also owns a control receipt")
	}
	a := s.aggregateObservation()
	action := a.actions[in.id]
	if action == nil {
		action = &aggregateAction{session: in.session, blocked: blocked}
		a.actions[in.id] = action
	}
	if action.session != in.session || action.blocked != blocked {
		return errors.New("aggregate ActionID maps to conflicting decisions or shards")
	}
	action.counts[kind]++
	a.counts[kind]++
	a.v1[aggregateBucket{session: in.session, verdict: in.verdict}]++
	return nil
}

func evaluateAggregateIntegrity(in integrityInput) integrityReport {
	obs, a := in.obs, in.obs.aggregate
	rep := integrityReport{
		Verdict: verdictPass, ReceiptAttribution: "aggregate", Reasons: []string{},
		Kinds: make(map[string]kindReport, kindCount), ControlReceipts: obs.controlReceipts,
		RecorderFiles: obs.recorderFiles, AELFiles: obs.aelFiles, OrphanSamples: obs.orphanSamples,
	}
	if in.mode == modeOff && obs.totalFiles > 0 {
		rep.fail("off mode contains recorder evidence")
	}
	var expected [kindCount]int
	usedHeaders := make(map[string]bool)
	for slot := range in.plan.total() {
		blocked, key := in.plan.blocked(slot), in.plan.key(slot)
		for kind, count := range expectedFor(in.mode, blocked) {
			expected[kind] += int(count)
		}
		if len(obs.slots[slot].actionIDs) != 0 || obs.slots[slot].counts != [kindCount]int32{} {
			rep.fail("mixed destination-only and request-keyed receipts cannot prove completeness")
		}
		accountSink(&rep.Sink, blocked, in.sinkHits[slot], key)
		out := in.outcomes[slot]
		if !out.ran || out.transportErr || !expectsReceiptHeader(in.mode, blocked) {
			continue
		}
		h := &rep.ReceiptHeader
		h.Expected++
		action := a.actions[out.receiptHeader]
		switch {
		case out.receiptHeader == "":
			h.Missing++
			h.noteProblem(key + ": response carried no receipt header")
		case action == nil || action.blocked != blocked || usedHeaders[out.receiptHeader]:
			h.Mismatch++
			h.noteProblem(key + ": response ActionID is missing, reused or has the wrong verdict")
		}
		usedHeaders[out.receiptHeader] = true
	}
	rep.Sink.Orphan += int(in.sinkUnknown)
	rep.Sink.finish(false)
	if rep.Sink.Status != statusOK {
		rep.fail(describeKind("sink", rep.Sink))
	}
	for kind := range kindCount {
		var k kindReport
		accountSlot(&k, expected[kind], a.counts[kind], "planned aggregate")
		k.Orphan, k.Uncorrelatable = obs.orphans[kind], obs.uncorrelatable[kind]
		k.finish(false)
		rep.Kinds[kind.String()] = k
		rep.ReceiptMissing += k.Missing
		if k.Status != statusOK {
			rep.fail(describeKind(kind.String(), k))
		}
	}
	// Totals cannot conceal a missing outcome plus a duplicate on another
	// ActionID. AEL remains bound to each authenticated v1 action as well.
	for id, action := range a.actions {
		want := expectedFor(in.mode, action.blocked)
		for kind, count := range want {
			if receiptKind(kind) != kindV2 && action.counts[kind] != int(count) {
				rep.fail(fmt.Sprintf("aggregate action %s: %s want %d, found %d", id, receiptKind(kind), count, action.counts[kind]))
			}
		}
	}
	// v2 carries scanner provenance rather than a layer, and no per-request
	// identity. Compare each shard's verdict counts with its v1 decisions.
	for bucket, count := range a.v1 {
		if a.v2[bucket] != count {
			rep.fail(fmt.Sprintf("shard %s verdict %s: v1=%d v2=%d", bucket.session, bucket.verdict, count, a.v2[bucket]))
		}
	}
	for bucket, count := range a.v2 {
		if a.v1[bucket] == 0 && count != 0 {
			rep.fail("v2 shard/verdict has no matching v1 decisions")
		}
	}
	if rep.ReceiptHeader.Missing > 0 || rep.ReceiptHeader.Mismatch > 0 {
		rep.fail(fmt.Sprintf("receipt header: %d missing, %d mismatched", rep.ReceiptHeader.Missing, rep.ReceiptHeader.Mismatch))
	}
	return rep
}
