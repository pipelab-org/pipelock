// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"context"
	"encoding/hex"
	"regexp"
	"slices"
	"strings"
	"testing"
)

const stopCoverageMarker = "Nested record"

func stopCoveragePlan(t *testing.T) *reassemblyPlan {
	t.Helper()
	plan, err := newReassemblyPlan([]*compiledPattern{{name: stopCoverageMarker, re: regexp.MustCompile(`MARK[0-9]{4}`)}})
	if err != nil {
		t.Fatal(err)
	}
	return plan
}

func stopCoverageMarkerHex() string {
	return hex.EncodeToString([]byte("&#77;&#65;&#82;&#75;1234"))
}

// doneCounter closes its context on the stopAt-th Done call. Callers observe
// cancellation through Done, the same channel terminalCanceled selects on.
type doneCounter struct {
	context.Context
	cancel context.CancelFunc
	hits   int
	stopAt int
}

func (c *doneCounter) Done() <-chan struct{} {
	c.hits++
	if c.stopAt > 0 && c.hits == c.stopAt {
		c.cancel()
	}
	return c.Context.Done()
}

func newDoneCounter(t *testing.T, stopAt int) *doneCounter {
	t.Helper()
	ctx, cancel := context.WithCancel(t.Context())
	t.Cleanup(cancel)
	return &doneCounter{Context: ctx, cancel: cancel, stopAt: stopAt}
}

func TestReassemblyLiteralStopsWhenBudgetStopped(t *testing.T) {
	budget := &assembledBudget{stopped: true}
	scan := assembledScan{budget: budget}
	scan.literal(0, 0, 0, 0, reassemblyNeedle{})
	if !scan.result.stopped || scan.result.incomplete || len(scan.result.findings) != 0 || scan.lanes[0][0] != nil {
		t.Fatalf("stopped literal continued: %+v lane=%v", scan.result, scan.lanes[0][0])
	}
	if budget.incomplete {
		t.Fatal("literal stop became an inspection limit")
	}
}

func TestReassemblyStrideCanceled(t *testing.T) {
	t.Run("nil budget", func(t *testing.T) {
		var budget *assembledBudget
		if budget.strideCanceled() {
			t.Fatal("nil budget stopped the walk")
		}
	})
	t.Run("nil memo", func(t *testing.T) {
		budget := &assembledBudget{stopped: true}
		if budget.strideCanceled() || !budget.stopped {
			t.Fatal("missing memo reported or cleared a stop")
		}
	})
	t.Run("already stopped", func(t *testing.T) {
		budget := &assembledBudget{stopped: true, memo: &decodingMemo{}}
		if !budget.strideCanceled() || !budget.stopped || budget.incomplete {
			t.Fatal("stopped budget resumed or became an inspection limit")
		}
	})
	t.Run("live context", func(t *testing.T) {
		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()
		budget := &assembledBudget{memo: &decodingMemo{scanCtx: ctx}}
		if budget.strideCanceled() || budget.stopped || budget.incomplete {
			t.Fatal("live context stopped the walk")
		}
	})
	t.Run("canceled context", func(t *testing.T) {
		ctx, cancel := context.WithCancel(t.Context())
		cancel()
		budget := &assembledBudget{memo: &decodingMemo{scanCtx: ctx}}
		if !budget.strideCanceled() || !budget.stopped {
			t.Fatal("canceled context continued")
		}
		if budget.incomplete || budget.memo.incomplete || budget.memo.reassemblyIncomplete {
			t.Fatal("cancellation became an inspection limit")
		}
	})
}

func TestReassemblySearchLaneStopsAtStride(t *testing.T) {
	plan := stopCoveragePlan(t)
	text := strings.Repeat("ab", responseBodyContextCheckBytes)
	t.Run("canceled replay", func(t *testing.T) {
		ctx, cancel := context.WithCancel(t.Context())
		cancel()
		budget := &assembledBudget{memo: &decodingMemo{scanCtx: ctx}}
		scan := assembledScan{p: plan, text: text, budget: budget}
		scan.searchLane(0, 0, 0)
		if scan.lanes[0][0] != nil || !scan.result.stopped || scan.result.incomplete || len(scan.result.findings) != 0 {
			t.Fatalf("partial lane was stored: lane=%v result=%+v", scan.lanes[0][0], scan.result)
		}
		if budget.incomplete || budget.memo.incomplete || budget.memo.reassemblyIncomplete {
			t.Fatal("stride stop became an inspection limit")
		}
		later := assembledScan{p: plan, text: text, budget: budget}
		later.searchLane(0, 0, 0)
		if later.lanes[0][0] != nil || !later.result.stopped || later.result.incomplete || len(later.result.findings) != 0 {
			t.Fatalf("later scan treated the partial replay as screened: lane=%v result=%+v", later.lanes[0][0], later.result)
		}
	})
	t.Run("already stopped", func(t *testing.T) {
		budget := &assembledBudget{stopped: true, memo: &decodingMemo{}}
		scan := assembledScan{p: plan, text: text, budget: budget}
		scan.searchLane(0, 0, 0)
		if scan.lanes[0][0] != nil || !scan.result.stopped || scan.result.incomplete || len(scan.result.findings) != 0 || budget.incomplete {
			t.Fatalf("stopped lane was screened: lane=%v result=%+v", scan.lanes[0][0], scan.result)
		}
	})
	t.Run("live context", func(t *testing.T) {
		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()
		budget := &assembledBudget{memo: &decodingMemo{scanCtx: ctx}}
		scan := assembledScan{p: plan, text: text, budget: budget}
		scan.searchLane(0, 0, 0)
		if scan.lanes[0][0] == nil || scan.result.stopped || scan.result.incomplete || budget.stopped || budget.incomplete {
			t.Fatalf("live replay did not keep a screened lane: lane=%v result=%+v stopped=%v", scan.lanes[0][0], scan.result, budget.stopped)
		}
	})
}

func TestReassemblyLayerStopsAtCodecBoundary(t *testing.T) {
	plan := stopCoveragePlan(t)
	body := reassemblyBang(hex.EncodeToString([]byte("MARK1234")))
	open := assembledLayer(plan, body, &assembledBudget{}, 0)
	if open.stopped || open.incomplete || !slices.Contains(matchNames(open.findings), stopCoverageMarker) {
		t.Fatalf("complete layer missed the marker: %+v", open)
	}
	budget := &assembledBudget{stopped: true}
	stopped := assembledLayer(plan, body, budget, 0)
	if !stopped.stopped || stopped.incomplete || len(stopped.findings) != 0 || budget.incomplete {
		t.Fatalf("stopped layer screened a codec: %+v budget=%+v", stopped, budget)
	}
}

func TestReassemblyHexViewsStopAtStride(t *testing.T) {
	text := strings.Repeat("ab", responseBodyContextCheckBytes)
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	budget := &assembledBudget{memo: &decodingMemo{scanCtx: ctx}}
	views := assembledHexViews(text, budget)
	if views != [2]string{} || !budget.stopped || budget.incomplete || budget.memo.incomplete {
		t.Fatalf("canceled hex walk published a view: %q stopped=%v incomplete=%v", views, budget.stopped, budget.incomplete)
	}
	liveCtx, liveCancel := context.WithCancel(t.Context())
	defer liveCancel()
	live := &assembledBudget{memo: &decodingMemo{scanCtx: liveCtx}}
	kept := assembledHexViews(text, live)
	if kept == [2]string{} || live.stopped || live.incomplete {
		t.Fatalf("live hex walk dropped the view: %q stopped=%v", kept, live.stopped)
	}
}

func TestReassemblyNestedHexAdmittedStop(t *testing.T) {
	plan := stopCoveragePlan(t)
	marker := stopCoverageMarkerHex()
	t.Run("stopped before views", func(t *testing.T) {
		open := assembledNestedHexAdmitted(plan, marker, &assembledBudget{memo: &decodingMemo{}})
		if open.stopped || open.incomplete || !slices.Contains(matchNames(open.findings), stopCoverageMarker) {
			t.Fatalf("complete nested walk missed the marker: %+v", open)
		}
		budget := &assembledBudget{stopped: true, memo: &decodingMemo{}}
		stopped := assembledNestedHexAdmitted(plan, marker, budget)
		if !stopped.stopped || stopped.incomplete != budget.incomplete || len(stopped.findings) != 0 || budget.memo.incomplete {
			t.Fatalf("stop before views changed the inspection limit: %+v", stopped)
		}
	})
	t.Run("stopped after a layer", func(t *testing.T) {
		// Both decoded phases are longer than one context stride, and the
		// outer hex walk takes two Done checks. The third check is the first
		// inner layer; cancelling there must not screen the other phase.
		text := strings.Repeat("a", responseBodyContextCheckBytes*2+3)
		counter := newDoneCounter(t, 3)
		budget := &assembledBudget{memo: &decodingMemo{scanCtx: counter}}
		stopped := assembledNestedHexAdmitted(plan, text, budget)
		if counter.hits != 3 || !stopped.stopped || stopped.incomplete || budget.incomplete || len(stopped.findings) != 0 {
			t.Fatalf("inner layer continued after cancel: hits=%d result=%+v budgetIncomplete=%v", counter.hits, stopped, budget.incomplete)
		}
		live := newDoneCounter(t, 0)
		openBudget := &assembledBudget{memo: &decodingMemo{scanCtx: live}}
		open := assembledNestedHexAdmitted(plan, text, openBudget)
		if live.hits < 4 || open.stopped || open.incomplete || openBudget.stopped {
			t.Fatalf("live nested walk stopped early: hits=%d result=%+v", live.hits, open)
		}
	})
}

func nestedStopMemo(plan *reassemblyPlan, ctx context.Context, inspected int, views ...string) *decodingMemo {
	pending := make([]int, len(views))
	for i := range views {
		pending[i] = i
	}
	return &decodingMemo{
		reassemblyPlan:          plan,
		reassemblyPending:       append([]string(nil), views...),
		reassemblyNestedPending: pending,
		reassemblyInspected:     inspected,
		scanCtx:                 ctx,
	}
}

func TestReassemblyFinishNestedStop(t *testing.T) {
	plan := stopCoveragePlan(t)
	long := strings.Repeat("a", responseBodyContextCheckBytes*2+3)
	marker := stopCoverageMarkerHex()
	assertNoLimit := func(t *testing.T, memo *decodingMemo, result TextDLPResult) {
		t.Helper()
		if memo.reassemblyIncomplete || memo.incomplete || HasInspectionLimit(result.Matches) {
			t.Fatalf("nested stop became an inspection limit: memoIncomplete=%v reassemblyIncomplete=%v result=%+v", memo.incomplete, memo.reassemblyIncomplete, result)
		}
	}
	t.Run("before next view", func(t *testing.T) {
		ctx, cancel := context.WithCancel(t.Context())
		cancel()
		memo := nestedStopMemo(plan, ctx, len([]string{long, marker}), long, marker)
		result := finishAssembled(TextDLPResult{Clean: true}, memo)
		assertNoLimit(t, memo, result)
		if slices.Contains(matchNames(result.Matches), stopCoverageMarker) {
			t.Fatal("canceled finalization screened a nested view")
		}
	})
	t.Run("nested result stopped", func(t *testing.T) {
		// Drain already finished. The first nested view's hex stride is the
		// second Done check and must break before the marker view is screened.
		counter := newDoneCounter(t, 2)
		memo := nestedStopMemo(plan, counter, 2, long, marker)
		result := finishAssembled(TextDLPResult{Clean: true}, memo)
		assertNoLimit(t, memo, result)
		if counter.hits != 2 || slices.Contains(matchNames(result.Matches), stopCoverageMarker) {
			t.Fatalf("later nested view was screened: hits=%d result=%+v", counter.hits, result)
		}
	})
	t.Run("live screens later view", func(t *testing.T) {
		counter := newDoneCounter(t, 0)
		memo := nestedStopMemo(plan, counter, 2, long, marker)
		result := finishAssembled(TextDLPResult{Clean: true}, memo)
		if result.Incomplete || memo.incomplete || memo.reassemblyIncomplete || !slices.Contains(matchNames(result.Matches), stopCoverageMarker) {
			t.Fatalf("live finalization missed the later view: hits=%d result=%+v", counter.hits, result)
		}
	})
}

func segmentRefusal(matched bool, graph *keywordDecodeSources) bool {
	return !matched && (graph.incomplete || graph.budget.incomplete)
}

func TestKeywordSegmentSearchRefusal(t *testing.T) {
	t.Run("invalid bounds", func(t *testing.T) {
		parent := "head" + repeatedSegmentText + "mid" + repeatedSegmentText
		for _, tc := range []struct {
			name       string
			start, end int
			dropParent bool
		}{
			{name: "negative", start: -1, end: 1},
			{name: "empty", start: 1, end: 1},
			{name: "past end", start: 0, end: len(repeatedSegmentText) + 1},
			{name: "no parent", start: 0, end: len(repeatedSegmentText), dropParent: true},
		} {
			t.Run(tc.name, func(t *testing.T) {
				graph, node := repeatedSegmentFixture(parent)
				if node == nil {
					t.Fatal("segment node was not admitted")
				}
				if tc.dropParent {
					node.parent = nil
				}
				handled, matched := node.visitLiteralSegment(tc.start, tc.end, rejectSegment)
				if !handled || matched || !segmentRefusal(matched, graph) || !graph.incomplete || graph.budget.incomplete {
					t.Fatalf("invalid segment looked searchable: handled=%v matched=%v owner=%v budget=%v", handled, matched, graph.incomplete, graph.budget.incomplete)
				}
			})
		}
	})
	t.Run("cache charge", func(t *testing.T) {
		graph, node := repeatedSegmentFixture("head" + repeatedSegmentText + "mid" + repeatedSegmentText)
		if node == nil {
			t.Fatal("segment node was not admitted")
		}
		graph.budget.used = maxDecodeTotalBytes
		handled, matched := node.visitLiteralSegment(0, len(node.text), rejectSegment)
		if !handled || matched || node.segmentSearch != nil || !segmentRefusal(matched, graph) || !graph.incomplete || !graph.budget.incomplete {
			t.Fatalf("cache refusal looked complete: handled=%v matched=%v search=%v owner=%v budget=%v", handled, matched, node.segmentSearch != nil, graph.incomplete, graph.budget.incomplete)
		}
	})
	t.Run("visit charge", func(t *testing.T) {
		graph, node := repeatedSegmentFixture("head" + repeatedSegmentText + "mid" + repeatedSegmentText)
		if node == nil {
			t.Fatal("segment node was not admitted")
		}
		node.segmentSearch = &keywordSegmentSearch{repeat: segmentRepeatMany, at: []int{len("head")}, done: true}
		graph.budget.used = maxDecodeTotalBytes
		calls := 0
		handled, matched := node.visitLiteralSegment(0, len(node.text), func(string, int, int) bool {
			calls++
			return true
		})
		if calls != 0 || !handled || matched || !segmentRefusal(matched, graph) || !graph.incomplete || !graph.budget.incomplete {
			t.Fatalf("visit refusal reported a match: calls=%d handled=%v matched=%v owner=%v budget=%v", calls, handled, matched, graph.incomplete, graph.budget.incomplete)
		}
	})
	t.Run("index refusal", func(t *testing.T) {
		segment := repeatedSegmentText
		parent := strings.Repeat("q", responseBodyContextCheckBytes) + segment
		graph, node := repeatedSegmentFixture(parent)
		if node == nil {
			t.Fatal("segment node was not admitted")
		}
		node.segmentSearch = &keywordSegmentSearch{repeat: segmentRepeatMany, at: []int{len(parent) - len(segment)}, from: 0}
		graph.budget.used = maxDecodeTotalBytes - (len(segment) + 2*keywordSpanBytes)
		calls := 0
		handled, matched := node.visitLiteralSegment(0, len(segment), func(string, int, int) bool {
			calls++
			return false
		})
		if calls != 1 || !handled || matched || !segmentRefusal(matched, graph) || !graph.incomplete || !graph.budget.incomplete {
			t.Fatalf("mid-walk refusal looked complete: calls=%d handled=%v matched=%v owner=%v budget=%v", calls, handled, matched, graph.incomplete, graph.budget.incomplete)
		}
	})
	t.Run("visit charge after index", func(t *testing.T) {
		segment := strings.Repeat("z", 48)
		parent := "HEAD" + segment
		graph := newKeywordDecodeSources(parent)
		node := graph.add(parent, segment, keywordSegment)
		if node == nil {
			t.Fatal("segment node was not admitted")
		}
		node.segmentSearch = &keywordSegmentSearch{repeat: segmentRepeatMany, from: len("HEAD")}
		graph.budget.used = maxDecodeTotalBytes - (len(segment) + keywordSpanBytes)
		calls := 0
		handled, matched := node.visitLiteralSegment(0, len(segment), func(string, int, int) bool {
			calls++
			return true
		})
		if calls != 0 || !handled || matched || !segmentRefusal(matched, graph) || !graph.incomplete || !graph.budget.incomplete {
			t.Fatalf("post-index visit refusal looked complete: calls=%d handled=%v matched=%v owner=%v budget=%v", calls, handled, matched, graph.incomplete, graph.budget.incomplete)
		}
	})
	t.Run("in budget", func(t *testing.T) {
		segment := repeatedSegmentText
		parent := segment + "q" + segment + "q" + segment
		rejected, rejectedNode := repeatedSegmentFixture(parent)
		if rejectedNode == nil {
			t.Fatal("segment node was not admitted")
		}
		calls := 0
		handled, matched := rejectedNode.visitLiteralSegment(0, len(segment), func(string, int, int) bool {
			calls++
			return false
		})
		if !handled || matched || calls != 3 || rejected.incomplete || rejected.budget.incomplete {
			t.Fatalf("in-budget repeated segment was refused: calls=%d handled=%v matched=%v owner=%v budget=%v", calls, handled, matched, rejected.incomplete, rejected.budget.incomplete)
		}
		graph, node := repeatedSegmentFixture(parent)
		calls = 0
		handled, matched = node.visitLiteralSegment(0, len(segment), func(string, int, int) bool {
			calls++
			return calls == 3
		})
		if !handled || !matched || calls != 3 || graph.incomplete || graph.budget.incomplete {
			t.Fatalf("later in-budget copy was refused: calls=%d handled=%v matched=%v owner=%v budget=%v", calls, handled, matched, graph.incomplete, graph.budget.incomplete)
		}
	})
}
