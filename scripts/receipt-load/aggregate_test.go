// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func aggregateFixture(t *testing.T, mode string, receipts []synthReceipt) integrityInput {
	t.Helper()
	plan := newWorkload(1, 2, 40)
	dir := t.TempDir()
	writeSynthRecorder(t, dir, plan, synthSink, receipts)
	path := filepath.Join(dir, "evidence-proxy.run.x-0.jsonl")
	raw, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(string(raw), "\n")
	for i, line := range lines {
		if !strings.Contains(line, "http://") {
			continue
		}
		var env map[string]any
		if err := json.Unmarshal([]byte(line), &env); err != nil {
			t.Fatal(err)
		}
		detail := env["detail"].(map[string]any)
		var fields map[string]any
		if env["type"] == recordTypeAction {
			fields = detail["action_record"].(map[string]any)
			fields["layer"] = ""
			if fields["decision_phase"] == "outcome" {
				fields["layer"] = "outcome"
			}
			if fields["verdict"] == verdictBlock {
				fields["layer"] = "core_dlp"
			}
		} else {
			fields = detail["payload"].(map[string]any)
			fields["winning_source"] = "scanner"
		}
		fields["target"] = "http://" + synthSink
		data, err := json.Marshal(env)
		if err != nil {
			t.Fatal(err)
		}
		lines[i] = string(data)
	}
	writeReviewFile(t, path, strings.Join(lines, "\n"))
	obs, err := scanRecorder(dir, plan, synthSink)
	if err != nil {
		t.Fatal(err)
	}
	in := integrityInput{mode: mode, plan: plan, obs: obs, outcomes: make([]requestOutcome, plan.total()), sinkHits: make([]int, plan.total())}
	for slot := range plan.total() {
		in.outcomes[slot] = requestOutcome{ran: true, receiptHeader: actionIDFor(slot)}
		if !plan.blocked(slot) {
			in.sinkHits[slot] = 1
		}
	}
	return in
}

func TestAggregateAccountingAndNegativeCases(t *testing.T) {
	plan := newWorkload(1, 2, 40)
	for _, mode := range []string{modeBest, modeRequired} {
		t.Run(mode, func(t *testing.T) {
			in := aggregateFixture(t, mode, perfectReceipts(plan, mode))
			if got := evaluateIntegrity(in); got.Verdict != verdictPass || got.ReceiptAttribution != "aggregate" {
				t.Fatalf("positive control: %+v", got)
			}
		})
	}
	for _, name := range []string{"missing-outcome", "compensating-duplicate", "v2-wrong-shard", "v2-wrong-verdict", "reused-header", "missing-ael", "mixed-shapes", "mixed-v2", "off-mode", "missing-header", "sink-missing", "uncorrelatable"} {
		t.Run(name, func(t *testing.T) {
			in := aggregateFixture(t, modeRequired, perfectReceipts(plan, modeRequired))
			a := in.obs.aggregate
			switch name {
			case "off-mode":
				in.mode = modeOff
			case "missing-header":
				in.outcomes[0].receiptHeader = ""
			case "sink-missing":
				in.sinkHits[0] = 0
			case "uncorrelatable":
				in.obs.uncorrelatable[kindV2] = 1
			case "missing-outcome":
				a.actions[actionIDFor(0)].counts[kindV1Outcome]--
				a.counts[kindV1Outcome]--
			case "compensating-duplicate":
				a.actions[actionIDFor(0)].counts[kindV1Outcome]--
				a.actions[actionIDFor(1)].counts[kindV1Outcome]++
			case "v2-wrong-shard":
				for bucket, count := range a.v2 {
					delete(a.v2, bucket)
					a.v2[aggregateBucket{session: "other", verdict: bucket.verdict}] = count
					break
				}
			case "v2-wrong-verdict":
				a.v2[aggregateBucket{session: "proxy.run.x", verdict: verdictAllow}]--
				a.v2[aggregateBucket{session: "proxy.run.x", verdict: verdictBlock}]++
			case "reused-header":
				in.outcomes[1].receiptHeader = in.outcomes[0].receiptHeader
			case "missing-ael":
				a.actions[actionIDFor(0)].counts[kindAEL]--
				a.counts[kindAEL]--
			case "mixed-v2":
				in.obs.slots[0].counts[kindV2] = 1
			case "mixed-shapes":
				in.obs.slots[0].actionIDs = []string{"legacy"}
			}
			if got := evaluateIntegrity(in); got.Verdict != verdictFail {
				t.Fatalf("%s accepted: %+v", name, got)
			}
		})
	}
}

func TestAggregateRejectsUnexpectedLayer(t *testing.T) {
	scanner := &recorderScanner{obs: newRecorderObservation(1), controlIDs: map[string]struct{}{}}
	in := aggregateActionInput{session: "shard", id: "block", method: "GET", transport: workloadTransport, action: "read", verdict: verdictBlock, layer: "core_dlp"}
	if err := scanner.observeAggregateV1(in); err != nil {
		t.Fatalf("producer control: %v", err)
	}
	in.id, in.layer = "wrong-layer", ""
	if err := scanner.observeAggregateV1(in); err == nil {
		t.Fatal("block with an unplanned layer accepted")
	}
}

func TestAggregateRejectsConflictingActionIdentity(t *testing.T) {
	s := &recorderScanner{obs: newRecorderObservation(1), controlIDs: map[string]struct{}{"control": {}}}
	in := aggregateActionInput{session: "one", id: "action", method: "GET", transport: workloadTransport, action: "read", verdict: verdictAllow}
	if err := s.observeAggregateV1(in); err != nil {
		t.Fatal(err)
	}
	in.id = "control"
	if err := s.observeAggregateV1(in); err == nil {
		t.Fatal("control and workload shared ActionID")
	}
	in.id, in.session = "action", "two"
	if err := s.observeAggregateV1(in); err == nil {
		t.Fatal("one ActionID assigned to two shards")
	}
}
