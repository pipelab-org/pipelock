// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

const repeatedSegmentText = "xyz"

func repeatedSegmentFixture(parent string) (*keywordDecodeSources, *keywordDecodeSource) {
	graph := newKeywordDecodeSources(parent)
	node := graph.add(parent, repeatedSegmentText, keywordSegment)
	return graph, node
}

func rejectSegment(string, int, int) bool { return false }

// A repeated segment used to run strings.Index over the parent suffix for every
// rejected candidate and charge only the segment length. One walk fits in the
// keyword allowance; repeating it for every candidate does not.
func TestRepeatedSegmentSearchChargedOnce(t *testing.T) {
	const candidates = 32
	segment := repeatedSegmentText
	gap := strings.Repeat("q", 200_000)
	parent := gap + segment + gap + segment
	graph, node := repeatedSegmentFixture(parent)
	if node == nil {
		t.Fatal("segment node was not admitted")
	}
	for range candidates {
		if node.visitSources(0, len(segment), rejectSegment) {
			t.Fatal("rejected candidates qualified")
		}
	}
	if graph.incomplete || graph.budget.incomplete {
		t.Fatalf("one bounded walk was refused: used=%d incomplete=%v", graph.budget.used, graph.budget.incomplete)
	}
	if graph.budget.searchBytes < len(parent) {
		t.Fatalf("search of %d parent bytes charged %d", len(parent), graph.budget.searchBytes)
	}
	if graph.budget.searchBytes >= candidates*len(parent)/2 {
		t.Fatalf("search repeated across candidates: searched %d", graph.budget.searchBytes)
	}
	searched := graph.budget.searchBytes
	used := graph.budget.used
	if node.visitSources(0, len(segment), rejectSegment) {
		t.Fatal("later rejected candidate qualified")
	}
	if graph.budget.searchBytes != searched {
		t.Fatalf("later candidate searched again: %d to %d", searched, graph.budget.searchBytes)
	}
	if graph.budget.used <= used {
		t.Fatal("later candidate did not charge the per-occurrence visit")
	}
}

func TestRepeatedSegmentSearchStopsAtBudget(t *testing.T) {
	segment := repeatedSegmentText
	parent := strings.Repeat("q", 4_000) + segment + "q" + segment
	graph, node := repeatedSegmentFixture(parent)
	if node == nil {
		t.Fatal("segment node was not admitted")
	}
	// Remaining room covers the old per-occurrence charge and not the parent suffix.
	const room = 500
	graph.budget.used = maxDecodeTotalBytes - room
	before := graph.budget.used
	if node.visitSources(0, len(segment), rejectSegment) || !graph.incomplete || !graph.budget.incomplete {
		t.Fatalf("oversized suffix ran or stayed complete: used=%d incomplete=%v budget=%v", graph.budget.used, graph.incomplete, graph.budget.incomplete)
	}
	if graph.budget.searchBytes != 0 || graph.budget.used-before >= len(parent)/2 {
		t.Fatalf("refused search still read the parent: searched=%d used=%d before=%d", graph.budget.searchBytes, graph.budget.used, before)
	}
}

func TestRepeatedSegmentSearchReturnsOnFirstQualifiedOccurrence(t *testing.T) {
	segment := repeatedSegmentText
	tail := strings.Repeat("q", 20_000)
	parent := segment + "q" + segment + tail + segment
	graph, node := repeatedSegmentFixture(parent)
	if node == nil {
		t.Fatal("segment node was not admitted")
	}
	calls := 0
	if !node.visitSources(0, len(segment), func(string, int, int) bool {
		calls++
		return true
	}) || calls != 1 {
		t.Fatalf("first qualifying occurrence did not stop the walk: calls=%d", calls)
	}
	afterQualify := graph.budget.searchBytes
	if afterQualify >= len(parent)-len(tail)/2 {
		t.Fatalf("qualifying occurrence kept scanning the distant tail: searched %d of %d", afterQualify, len(parent))
	}
	calls = 0
	if node.visitSources(0, len(segment), func(string, int, int) bool {
		calls++
		return false
	}) {
		t.Fatal("rejected replay qualified")
	}
	if calls < 3 {
		t.Fatalf("replay skipped a cached or later occurrence: calls=%d", calls)
	}
	if graph.budget.searchBytes-afterQualify < len(tail) {
		t.Fatalf("rejected replay did not charge the uncached tail: searched %d then %d", afterQualify, graph.budget.searchBytes)
	}
	finished := graph.budget.searchBytes
	if node.visitSources(0, len(segment), rejectSegment) {
		t.Fatal("third visit qualified")
	}
	if graph.budget.searchBytes != finished {
		t.Fatalf("finished search ran again: %d to %d", finished, graph.budget.searchBytes)
	}
}

func TestUniqueSegmentRepeatDecisionCached(t *testing.T) {
	segment := repeatedSegmentText
	parent := strings.Repeat("q", 50_000) + segment
	graph, node := repeatedSegmentFixture(parent)
	if node == nil {
		t.Fatal("segment node was not admitted")
	}
	calls := 0
	visit := func(string, int, int) bool {
		calls++
		return true
	}
	if !node.visitSources(0, len(segment), visit) || calls != 1 || graph.incomplete {
		t.Fatalf("unique segment did not map: calls=%d incomplete=%v", calls, graph.incomplete)
	}
	if graph.budget.searchBytes < len(parent) {
		t.Fatalf("unique probe searched %d of %d", graph.budget.searchBytes, len(parent))
	}
	searched := graph.budget.searchBytes
	calls = 0
	if !node.visitSources(0, len(segment), visit) || calls != 1 || graph.budget.searchBytes != searched || graph.incomplete {
		t.Fatalf("unique decision was not cached: calls=%d searched %d to %d incomplete=%v", calls, searched, graph.budget.searchBytes, graph.incomplete)
	}
}

func TestReassemblyAnchoredKeywordDistantFromOnlyCarrier(t *testing.T) {
	sc := reassemblyAnchoredScanner(t)
	gap := strings.Repeat(" ", config.DefaultDLPKeywordWindow+1)
	for _, escape := range []string{"html", "json"} {
		t.Run(escape, func(t *testing.T) {
			long := reassemblyAnchoredCarrier(escape, 5000)
			distant := long + gap + "lookup"
			result := sc.ScanTextForDLP(t.Context(), distant)
			if reassemblyAnchoredFound(result) || result.Incomplete || HasInspectionLimit(result.Matches) {
				t.Fatalf("distant keyword qualified the only carrier: %+v", result)
			}
		})
	}
}

func BenchmarkRepeatedSegmentRejectedCandidates(b *testing.B) {
	segment := repeatedSegmentText
	gap := strings.Repeat("q", 64*1024)
	parent := gap + segment + gap + segment
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		graph, node := repeatedSegmentFixture(parent)
		if node == nil {
			b.Fatal("segment node was not admitted")
		}
		for range 40 {
			node.visitSources(0, len(segment), rejectSegment)
		}
		if graph.budget.incomplete {
			b.Fatal("bounded walk exhausted the keyword budget")
		}
	}
}
