// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
)

func TestDestinationReceiptAssociations(t *testing.T) {
	plan := newWorkload(1, 0, 4)
	plan.destinations = newDestinationPlan(plan.total(), []string{"10001", "10002"})
	for _, mutation := range []string{"complete", "missing", "duplicate", "unknown", "redacted", "path", "conflicting_action", "bad_header", "aggregate"} {
		t.Run(mutation, func(t *testing.T) {
			receipts := perfectReceipts(plan, modeRequired)
			for i := range receipts {
				receipts[i].target = "http://" + plan.destinations.authority(receipts[i].slot)
			}
			switch mutation {
			case "missing":
				receipts = receipts[1:]
			case "duplicate":
				receipts = append(receipts, receipts[0])
			case "unknown":
				receipts[0].target = "http://unknown.load.example:10001"
			case "redacted":
				receipts[0].target = "[redacted-target]"
			case "path":
				receipts[0].target += "/ok?wk=" + plan.key(0)
			case "conflicting_action":
				for i := range receipts {
					if receipts[i].slot == 1 && receipts[i].kind == kindV1Intent {
						receipts[i].actionID = actionIDFor(0)
					}
				}
			}
			dir := t.TempDir()
			writeSynthRecorder(t, dir, plan, synthSink, receipts)
			path := filepath.Join(dir, "evidence-proxy.run.x-0.jsonl")
			data, err := os.ReadFile(filepath.Clean(path))
			if err != nil {
				t.Fatal(err)
			}
			// The synthetic helper predates scanner provenance on destination receipts.
			writeReviewFile(t, path, strings.ReplaceAll(string(data), `"transport":"forward"`, `"transport":"forward","winning_source":"scanner"`))
			obs, err := scanRecorder(dir, plan, "")
			if mutation == "conflicting_action" {
				if err == nil || !strings.Contains(err.Error(), "ActionID maps to multiple") {
					t.Fatalf("conflicting association: %v", err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			in := integrityInput{mode: modeRequired, plan: plan, obs: obs, outcomes: make([]requestOutcome, plan.total()), sinkHits: make([]int, plan.total())}
			for slot := range plan.total() {
				in.sinkHits[slot] = 1
				in.outcomes[slot] = requestOutcome{ran: true, receiptHeader: actionIDFor(slot)}
			}
			if mutation == "bad_header" {
				in.outcomes[0].receiptHeader = actionIDFor(1)
			}
			if mutation == "aggregate" {
				obs.aggregate = &aggregateObservation{}
			}
			got := evaluateIntegrity(in)
			want := verdictFail
			if mutation == "complete" {
				want = verdictPass
			}
			if got.Verdict != want || got.ReceiptAttribution != attributionPerRequestDestination {
				t.Fatalf("association %s: %+v", mutation, got)
			}
		})
	}
}

func TestDestinationSinkChecksKeyAndAuthority(t *testing.T) {
	plan := newWorkload(1, 0, 4)
	plan.destinations = newDestinationPlan(plan.total(), []string{"10001", "10002"})
	s := &sink{plan: plan, seen: make([]atomic.Int32, plan.total())}
	for _, tc := range []struct{ method, authority, path string }{
		{http.MethodGet, plan.destinations.authority(0), plan.pathAndQuery(0)},
		{http.MethodGet, plan.destinations.authority(1), plan.pathAndQuery(0)},
		{http.MethodPost, plan.destinations.authority(0), plan.pathAndQuery(0)},
		{http.MethodGet, plan.destinations.authority(0), "/ok?wk=unknown"},
	} {
		s.handle(httptest.NewRecorder(), httptest.NewRequestWithContext(context.Background(), tc.method, "http://"+tc.authority+tc.path, nil))
	}
	if s.hits()[0] != 1 || s.unknown.Load() != 3 {
		t.Fatalf("sink accepted mismatched key or destination: hits=%v unknown=%d", s.hits(), s.unknown.Load())
	}
}

func TestDestinationConfigAndLegacyKey(t *testing.T) {
	d := newDestinationPlan(4, []string{"10001", "10002"})
	data, err := applyConfig([]byte(fakeConfig), configParams{mode: modeRequired, chains: 1, dirs: newRunDirs(t.TempDir()), destinations: d})
	if err != nil || !strings.Contains(string(data), "host_overrides:") {
		t.Fatalf("config without DNS section: %s %v", data, err)
	}
	scanner := &recorderScanner{plan: newWorkload(1, 0, 4)}
	if _, ok := scanner.targetSlot("http://" + synthSink + "/ok"); ok {
		t.Fatal("legacy receipt without a key acquired identity")
	}
}
