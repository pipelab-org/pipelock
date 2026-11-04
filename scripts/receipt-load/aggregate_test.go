// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// aggregateRecorder writes a synthetic recorder whose workload receipts carry
// only the sink destination, exactly as the production sanitizer now signs them.
func aggregateRecorder(t *testing.T, plan workload, receipts []synthReceipt) string {
	t.Helper()
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
	return dir
}

func aggregateFixture(t *testing.T, mode string, receipts []synthReceipt) integrityInput {
	t.Helper()
	plan := newWorkload(1, 2, 40)
	dir := aggregateRecorder(t, plan, receipts)
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

// A request whose every receipt vanished has no response header to expose it
// in best mode. Only the planned totals can see that.
func TestAggregateRejectsWholeMissingAllowedRequest(t *testing.T) {
	plan := newWorkload(1, 2, 40)
	victim := -1
	for slot := range plan.total() {
		if !plan.blocked(slot) {
			victim = slot
			break
		}
	}
	var kept []synthReceipt
	for _, r := range perfectReceipts(plan, modeBest) {
		if r.slot != victim {
			kept = append(kept, r)
		}
	}
	got := evaluateIntegrity(aggregateFixture(t, modeBest, kept))
	if got.Verdict != verdictFail || !hasReason(got.Reasons, "planned aggregate") {
		t.Fatalf("a request with no receipts passed: %+v", got)
	}
}

// Each response header must name a distinct recorded action with the verdict
// the plan gave that request, and the sink must not see unplanned requests.
func TestAggregateRejectsUnlinkedHeadersAndSinkStrangers(t *testing.T) {
	plan := newWorkload(1, 2, 40)
	blocked, allowed := -1, -1
	for slot := range plan.total() {
		if plan.blocked(slot) && blocked < 0 {
			blocked = slot
		}
		if !plan.blocked(slot) && allowed < 0 {
			allowed = slot
		}
	}
	for name, edit := range map[string]func(in *integrityInput){
		"unknown-action": func(in *integrityInput) { in.outcomes[blocked].receiptHeader = "no-such-action" },
		"wrong-verdict": func(in *integrityInput) {
			in.outcomes[blocked].receiptHeader, in.outcomes[allowed].receiptHeader = actionIDFor(allowed), actionIDFor(blocked)
		},
		"sink-stranger": func(in *integrityInput) { in.sinkUnknown = 1 },
	} {
		t.Run(name, func(t *testing.T) {
			in := aggregateFixture(t, modeRequired, perfectReceipts(plan, modeRequired))
			if got := evaluateIntegrity(in); got.Verdict != verdictPass {
				t.Fatalf("positive control: %+v", got)
			}
			edit(&in)
			if got := evaluateIntegrity(in); got.Verdict != verdictFail {
				t.Fatalf("%s accepted: %+v", name, got)
			}
		})
	}
}

// The scanner must refuse a destination-only receipt whose shape is not the one
// the forward producer writes, even when its target is the planned destination.
func TestAggregateScanRejectsOffContractReceipts(t *testing.T) {
	plan := newWorkload(1, 2, 40)
	cases := []struct{ name, typ, from, to string }{
		{"v2-transport", recordTypeEvidence, `"transport":"forward"`, `"transport":"connect"`},
		{"v2-action-type", recordTypeEvidence, `"action_type":"http_request"`, `"action_type":"mcp_tool"`},
		{"v2-winning-source", recordTypeEvidence, `"winning_source":"scanner"`, `"winning_source":"policy"`},
		{"v1-method", recordTypeAction, `"method":"GET"`, `"method":"POST"`},
		{"v1-transport", recordTypeAction, `"transport":"forward"`, `"transport":"connect"`},
		{"v1-action-type", recordTypeAction, `"action_type":"read"`, `"action_type":"write"`},
		{"native-activity-class", "ael", `"class":"read"`, `"class":"write"`},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			dir := aggregateRecorder(t, plan, perfectReceipts(plan, modeBest))
			if _, err := scanRecorder(dir, plan, synthSink); err != nil {
				t.Fatalf("positive control: %v", err)
			}
			path := filepath.Join(dir, "evidence-proxy.run.x-0.jsonl")
			if c.typ == "ael" {
				path = filepath.Join(dir, "ael", "run0", "recorders", "pipelock.jsonl")
			}
			raw, err := os.ReadFile(filepath.Clean(path))
			if err != nil {
				t.Fatal(err)
			}
			lines := strings.Split(string(raw), "\n")
			changed := false
			for i, line := range lines {
				if c.typ == "ael" {
					parts := strings.Split(line, ".")
					payload, err := base64.RawURLEncoding.DecodeString(parts[0])
					if err != nil || !strings.Contains(string(payload), `"id":"action-`) {
						continue
					}
					lines[i] = base64.RawURLEncoding.EncodeToString([]byte(strings.Replace(string(payload), c.from, c.to, 1))) + "." + parts[1]
					changed = true
					break
				}
				if strings.Contains(line, `"type":"`+c.typ+`"`) && strings.Contains(line, "http://"+synthSink) && strings.Contains(line, c.from) {
					lines[i], changed = strings.Replace(line, c.from, c.to, 1), true
					break
				}
			}
			if !changed {
				t.Fatal("mutation matched no receipt")
			}
			writeReviewFile(t, path, strings.Join(lines, "\n"))
			if _, err := scanRecorder(dir, plan, synthSink); err == nil {
				t.Fatalf("%s accepted", c.name)
			}
		})
	}
}

// A session-control receipt may not reuse the ActionID of a workload action the
// scanner has already read; the reverse order is covered by the conflict test.
func TestAggregateRejectsControlReusingAnEarlierWorkloadActionID(t *testing.T) {
	plan := newWorkload(1, 2, 40)
	dir := aggregateRecorder(t, plan, perfectReceipts(plan, modeBest))
	path := filepath.Join(dir, "evidence-proxy.run.x-0.jsonl")
	raw, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		t.Fatal(err)
	}
	writeReviewFile(t, path, string(raw)+v1Line(kindV1Allow, actionIDFor(0), "pipelock://session/heartbeat")+"\n")
	if _, err := scanRecorder(dir, plan, synthSink); err == nil {
		t.Fatal("control receipt reused a workload ActionID")
	}
}
