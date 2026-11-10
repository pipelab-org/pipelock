// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"fmt"
	"reflect"
	"testing"
)

// referenceBindParents is the previous variant scan. Binding order,
// sourceVersion, and budget.used must stay identical to it.
func referenceBindParents(s *keywordDecodeSources, text string, parents []*keywordDecodeSource) {
	root := s.nodes[text]
	for _, parent := range parents {
		if parent == root || referenceHasSourceAncestor(parent, root) {
			continue
		}
		encoding := "identity"
		if parent.text != text {
			encoding = "projection"
		}
		if root.parent == parent && root.encoding == encoding {
			continue
		}
		duplicate := false
		for _, variant := range root.variants {
			duplicate = duplicate || variant.parent == parent && variant.encoding == encoding
		}
		if duplicate {
			continue
		}
		if root.parent == nil {
			s.budget.sourceVersion++
			root.parent = parent
			root.encoding = encoding
			continue
		}
		if !s.chargeNode() {
			return
		}
		s.budget.sourceVersion++
		root.variants = append(root.variants, &keywordDecodeSource{text: text, encoding: encoding, parent: parent, owner: s})
	}
}

func referenceHasSourceAncestor(n, target *keywordDecodeSource) bool {
	pending := []*keywordDecodeSource{n}
	seen := make(map[*keywordDecodeSource]bool)
	for len(pending) > 0 {
		next := pending[len(pending)-1]
		pending = pending[:len(pending)-1]
		if next == target {
			return true
		}
		if next == nil || seen[next] {
			continue
		}
		seen[next] = true
		pending = append(pending, next.parent)
		pending = append(pending, next.variants...)
	}
	return false
}

func referenceAdd(s *keywordDecodeSources, parent, text, encoding string) *keywordDecodeSource {
	if !s.rootCharged {
		s.rootCharged = true
		if !s.chargeNode() {
			return nil
		}
	}
	p := s.nodes[parent]
	if p == nil {
		s.incomplete = true
		return nil
	}
	if node := s.nodes[text]; node != nil {
		if text == s.root || node == p || node.parent == p && node.encoding == encoding {
			return node
		}
		for _, variant := range node.variants {
			if variant.parent == p && variant.encoding == encoding {
				return node
			}
		}
		if referenceHasSourceAncestor(p, node) {
			return node
		}
		if !s.chargeNode() {
			return node
		}
		s.budget.sourceVersion++
		node.variants = append(node.variants, &keywordDecodeSource{text: text, encoding: encoding, parent: p, owner: s})
		return node
	}
	if !s.chargeNode() {
		return nil
	}
	node := &keywordDecodeSource{text: text, encoding: encoding, parent: p, owner: s}
	s.nodes[text] = node
	return node
}

type keywordEdgeSnap struct {
	Parent     int
	ParentText string
	Encoding   string
	Text       string
}

type keywordBindingSnap struct {
	Primary          keywordEdgeSnap
	Variants         []keywordEdgeSnap
	SourceVersion    uint64
	Used             int
	Nodes            int
	Incomplete       bool
	BudgetIncomplete bool
}

func bindWith(ref bool, s *keywordDecodeSources, parents []*keywordDecodeSource) {
	const text = "root"
	if ref {
		referenceBindParents(s, text, parents)
		return
	}
	s.bindParents(text, parents)
}

func addWith(ref bool, s *keywordDecodeSources, parent, text string) *keywordDecodeSource {
	const encoding = "projection"
	if ref {
		return referenceAdd(s, parent, text, encoding)
	}
	return s.add(parent, text, encoding)
}

func keywordParentID(parents []*keywordDecodeSource, parent *keywordDecodeSource) int {
	if parent == nil {
		return -1
	}
	for i, candidate := range parents {
		if candidate == parent {
			return i
		}
	}
	return -1
}

func keywordEdgeSnapOf(parents []*keywordDecodeSource, node *keywordDecodeSource) keywordEdgeSnap {
	if node == nil {
		return keywordEdgeSnap{Parent: -1}
	}
	parentText := ""
	if node.parent != nil {
		parentText = node.parent.text
	}
	return keywordEdgeSnap{Parent: keywordParentID(parents, node.parent), ParentText: parentText, Encoding: node.encoding, Text: node.text}
}

func keywordBindingSnapOf(graph *keywordDecodeSources, node *keywordDecodeSource, parents []*keywordDecodeSource) keywordBindingSnap {
	snap := keywordBindingSnap{
		Primary:          keywordEdgeSnapOf(parents, node),
		SourceVersion:    graph.budget.sourceVersion,
		Used:             graph.budget.used,
		Nodes:            graph.budget.nodes,
		Incomplete:       graph.incomplete,
		BudgetIncomplete: graph.budget.incomplete,
	}
	for _, variant := range node.variants {
		snap.Variants = append(snap.Variants, keywordEdgeSnapOf(parents, variant))
	}
	return snap
}

func keywordBindingMixed(ref bool) keywordBindingSnap {
	graph := newKeywordDecodeSources("root")
	root := graph.nodes["root"]
	identity := newKeywordDecodeSources("root").nodes["root"]
	identityAgain := newKeywordDecodeSources("root").nodes["root"]
	projected := newKeywordDecodeSources("projected").nodes["projected"]
	cycle := &keywordDecodeSource{text: "cycle", owner: graph, parent: root}
	via := &keywordDecodeSource{text: "via", owner: graph}
	via.variants = []*keywordDecodeSource{{text: "edge", owner: graph, parent: root, encoding: "projection"}}
	loose := &keywordDecodeSource{text: "loose"}
	parents := []*keywordDecodeSource{cycle, via, root, identity, identity, projected, projected}
	for i := range 48 {
		text := fmt.Sprintf("parent-%02d", i)
		parents = append(parents, newKeywordDecodeSources(text).nodes[text])
	}
	parents = append(parents, identityAgain, loose, projected)
	bindWith(ref, graph, parents)
	bindWith(ref, graph, parents)
	return keywordBindingSnapOf(graph, root, parents)
}

func keywordBindingExisting(ref bool) keywordBindingSnap {
	graph := newKeywordDecodeSources("root")
	root := graph.nodes["root"]
	pre := newKeywordDecodeSources("preexisting").nodes["preexisting"]
	root.variants = []*keywordDecodeSource{{text: "root", encoding: "projection", parent: pre, owner: graph}}
	other := newKeywordDecodeSources("other").nodes["other"]
	sameText := newKeywordDecodeSources("root").nodes["root"]
	parents := []*keywordDecodeSource{pre, other, sameText, pre}
	bindWith(ref, graph, parents)
	return keywordBindingSnapOf(graph, root, parents)
}

func keywordBindingExhausted(ref bool) keywordBindingSnap {
	graph := newKeywordDecodeSources("root")
	root := graph.nodes["root"]
	graph.budget.nodes = maxDecodeCandidates - 1
	primary := newKeywordDecodeSources("root").nodes["root"]
	parents := []*keywordDecodeSource{primary}
	for i := range 4 {
		text := fmt.Sprintf("extra-%d", i)
		parents = append(parents, newKeywordDecodeSources(text).nodes[text])
	}
	bindWith(ref, graph, parents)
	return keywordBindingSnapOf(graph, root, parents)
}

func keywordBindingAddedEdges(ref bool) keywordBindingSnap {
	graph := newKeywordDecodeSources("root")
	added := []*keywordDecodeSource{
		addWith(ref, graph, "root", "view"),
	}
	graph.nodes["other"] = &keywordDecodeSource{text: "other", owner: graph}
	added = append(added,
		addWith(ref, graph, "other", "view"),
		addWith(ref, graph, "other", "view"),
		addWith(ref, graph, "view", "deeper"),
		addWith(ref, graph, "deeper", "view"),
	)
	snap := keywordBindingSnapOf(graph, graph.nodes["view"], nil)
	for _, node := range added {
		if node == nil {
			snap.Used = -1
		}
	}
	return snap
}

func TestKeywordBindingMatchesReference(t *testing.T) {
	for _, tc := range []struct {
		name string
		run  func(bool) keywordBindingSnap
	}{
		{name: "identity and projection", run: keywordBindingMixed},
		{name: "existing variants", run: keywordBindingExisting},
		{name: "budget exhaustion", run: keywordBindingExhausted},
		{name: "added edges", run: keywordBindingAddedEdges},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, want := tc.run(false), tc.run(true)
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("binding result\n got %+v\nwant %+v", got, want)
			}
			if tc.name == "identity and projection" {
				if got.Primary.Encoding != "identity" || got.Primary.Parent < 0 {
					t.Fatalf("primary identity binding = %+v", got.Primary)
				}
				var identityEdges, projectionEdges int
				if got.Primary.Encoding == "identity" {
					identityEdges++
				}
				for _, variant := range got.Variants {
					switch variant.Encoding {
					case "identity":
						identityEdges++
					case "projection":
						projectionEdges++
					default:
						t.Fatalf("encoding %q", variant.Encoding)
					}
				}
				if identityEdges < 2 || projectionEdges < 40 {
					t.Fatalf("edges identity=%d projection=%d", identityEdges, projectionEdges)
				}
			}
			if tc.name == "budget exhaustion" && (!got.Incomplete || !got.BudgetIncomplete || len(got.Variants) != 1) {
				t.Fatalf("exhaustion retained %+v", got)
			}
		})
	}
}
