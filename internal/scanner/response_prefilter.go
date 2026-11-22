// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"regexp"
	"regexp/syntax"
)

import "github.com/luckyPipewrench/pipelock/internal/config"

// responsePreFilter applies necessary literal and distance conditions plus
// bounded negative proofs before matching response patterns on the full text.
//
// This sits ahead of passes 1+2 and the opt-space pass. Literal presence and
// regex-derived distance conditions are necessary conditions, never limits on
// which input positions the original matcher can inspect.
//
// Conservative: false positives (running regex unnecessarily) are fine.
// False negatives (skipping a real match) are not.
type responsePreFilter struct {
	gates           []*responseGate
	proofs          []*responseSuffixProof
	prefixes        []*responseSuffixProof
	companionProofs [][]*responseSuffixProof
	windows         map[*regexp.Regexp]*regexpWindowPlan
	chains          map[*regexp.Regexp]*responseLiteralChain
	chainLiterals   []string
	windowAnchors   []string
	deltaWidths     map[*regexp.Regexp]responseDeltaWidth

	// alwaysRun holds indices of patterns with no extractable keyword gate.
	// A separate negative proof can still exclude these patterns.
	alwaysRun []int
}

// A view is owned by one sequential response scan and keyed by exact input
// bytes in its memo. It shares the gate's derived text across pattern groups.
type responsePreFilterView struct {
	outboundMatch  func(*compiledPattern, string) []ResponseMatch
	delta          *responseDeltaView
	folded         string
	literals       responseLiteralMemo
	ready          bool
	positions      *matchingView
	buffers        *responseMatchingBuffers
	maxWindowRun   int
	windowRunReady bool
}

// newResponsePreFilter builds a pre-filter from response patterns.
// Extracts keyword anchors from each pattern, handling literal prefixes
// and leading alternation groups.
func newResponsePreFilter(patterns []*compiledPattern) *responsePreFilter {
	pf := &responsePreFilter{
		gates:           make([]*responseGate, len(patterns)),
		proofs:          make([]*responseSuffixProof, len(patterns)),
		prefixes:        make([]*responseSuffixProof, len(patterns)),
		companionProofs: make([][]*responseSuffixProof, len(patterns)),
	}

	for i, p := range patterns {
		// Companion detectors need independent necessary conditions. A negative
		// for the main expression alone must never skip the companion arms.
		if p.name != externalDataTransferDirectivePatternName || p.re.String() != config.ExternalDataTransferDirectiveRegex {
			tree, err := syntax.Parse(p.re.String(), syntax.Perl)
			if err == nil {
				pf.gates[i] = responseLiteralGate(tree)
				pf.proofs[i] = newResponseSuffixProof(p.re)
				if p.responseMemoRegexp != nil && p.responseMemoRegexp == p.re {
					pf.addChain(p.re, tree)
					if width, ok := newResponseDeltaWidth(tree); ok {
						if pf.deltaWidths == nil {
							pf.deltaWidths = make(map[*regexp.Regexp]responseDeltaWidth)
						}
						pf.deltaWidths[p.re] = width
					}
					plan := newResponseRegexpWindowPlan(p.re, tree)
					if plan == nil {
						plan = newRegexpWindowPlan(p.re, tree)
					}
					if plan != nil && len(plan.anchors) != 0 {
						if pf.windows == nil {
							pf.windows = make(map[*regexp.Regexp]*regexpWindowPlan)
						}
						pf.windows[p.re] = plan
						pf.windowAnchors = append(pf.windowAnchors, plan.anchors...)
					}
					pf.prefixes[i] = newResponsePrefixProof(p.re)
				}
			}
		} else {
			pf.gates[i] = externalTransferGate(p.re)
			if p.responseMemoRegexp != nil && p.responseMemoRegexp == p.re {
				for _, re := range externalTransferExpressions(p.re) {
					pf.companionProofs[i] = append(pf.companionProofs[i], newResponsePrefixProof(re))
					if tree, err := syntax.Parse(re.String(), syntax.Perl); err == nil {
						pf.addChain(re, tree)
					}
				}
			}
		}
		if pf.gates[i] == nil {
			pf.alwaysRun = append(pf.alwaysRun, i)
		}
	}

	return pf
}

func (pf *responsePreFilter) addChain(re *regexp.Regexp, tree *syntax.Regexp) {
	if pf.chains[re] != nil {
		return
	}
	if chain := newResponseLiteralChain(tree); chain != nil {
		if pf.chains == nil {
			pf.chains = make(map[*regexp.Regexp]*responseLiteralChain)
		}
		pf.chains[re] = chain
		pf.chainLiterals = append(pf.chainLiterals, chain.literals()...)
	}
}

// patternsToCheck returns pattern indices not excluded by gates or proofs.
// Returns nil when no patterns need to run.
func (pf *responsePreFilter) patternsToCheck(content string) []int {
	return pf.patternsToCheckWithMemo(content, nil, nil, nil)
}

func (pf *responsePreFilter) patternsToCheckWithMemo(content string, cached *responsePreFilterView, patterns []*compiledPattern, chains responseChainRanges) []int {
	if cached == nil {
		cached = &responsePreFilterView{}
	}
	var pairs responseGatePairs
	gateReady := false
	identical := cached.outboundMatch == nil && cached.delta != nil && len(cached.delta.edits) == 0
	var view *responseFoldView
	var forward *responseFoldView
	hits := make([]int, 0, len(pf.gates))
	for i, gate := range pf.gates {
		if identical && cached.delta.isKnown(patterns[i]) {
			continue
		}
		if chains != nil {
			if windows, complete := chains.patternWindows(patterns[i]); complete {
				if len(windows) != 0 {
					hits = append(hits, i)
				}
				continue
			}
		}
		if !gateReady {
			pairs = cached.prepareLegacy(content)
			gateReady = true
		}
		folded, literals := cached.folded, cached.literals
		if gate != nil && !gate.matchesWithPairs(content, folded, "", literals, &pairs) {
			continue
		}
		if len(content) >= responseMemoMinBytes && len(content) <= responseMemoMaxBytes && i < len(pf.prefixes) && pf.prefixes[i] != nil {
			if forward == nil {
				forward = newResponseFoldView(content, folded)
				forward.literals = literals
			}
			if pf.prefixes[i].provesEmpty(forward) {
				continue
			}
		}
		if len(content) >= responseMemoMinBytes && len(content) <= responseMemoMaxBytes && i < len(pf.companionProofs) && len(pf.companionProofs[i]) == 3 {
			if forward == nil {
				forward = newResponseFoldView(content, folded)
				forward.literals = literals
			}
			allEmpty := true
			for _, proof := range pf.companionProofs[i] {
				if !proof.provesEmpty(forward) {
					allEmpty = false
					break
				}
			}
			if allEmpty {
				continue
			}
		}
		// Small bodies already match cheaply. Bound the additional text and offset
		// storage; every ineligible or inconclusive proof runs the ordinary matcher.
		if len(content) >= responseMemoMinBytes && len(content) <= responseMemoMaxBytes && i < len(pf.proofs) && pf.proofs[i] != nil {
			if view == nil {
				// Folding is per rune and maps invalid bytes to U+FFFD, so the
				// reversed fold equals the fold of the reversed text.
				view = newResponseFoldView(reverseResponseText(content), reverseResponseText(folded))
			}
			if pf.proofs[i].provesEmpty(view) {
				continue
			}
		}
		hits = append(hits, i)
	}
	return hits
}

func (view *responsePreFilterView) prepareLegacy(content string) responseGatePairs {
	if !view.ready {
		view.folded = responseSimpleFold(content)
		view.ready = true
	}
	if view.literals == nil && len(content) >= responseMemoMinBytes && len(content) <= responseMemoMaxBytes {
		view.literals = make(responseLiteralMemo)
	}
	// Rebuilt per call on the stack: a pass over the text costs less than
	// retaining two filters on every cached view.
	var pairs responseGatePairs
	if positions := view.positions; positions != nil && positions.isASCII() {
		pairs.positions = positions
	}
	// A missing pair rules out a literal without a substring search.
	// Only build the index after repeated queries pass the pair filter.
	if pairs.positions == nil || pairs.positions.hits == nil {
		pairs.raw.add(content)
		pairs.fold.add(view.folded)
		pairs.pairsReady = true
		pairs.densePairs = pairs.positions != nil && responseGatePairsDense(&pairs.fold)
	}
	return pairs
}

func responseChainWindowBytes(windows []regexpWindowRange) int {
	bytes := 0
	for _, window := range windows {
		bytes += window.end - window.start
	}
	return bytes
}

// hasEncodedRun checks whether content contains a contiguous run of
// base64 or hex alphabet characters long enough to be a meaningful
// encoded payload. Used to skip expensive decode attempts on content
// that is clearly not encoded. Set low (8) to catch short encoded
// payloads like base64("system:") = "c3lzdGVtOg==" (12 chars).
const minEncodedRunLen = 8

func hasEncodedRun(content string) bool {
	run := 0
	for i := 0; i < len(content); i++ {
		c := content[i]
		if isBase64DataByte(c) || c == '=' {
			run++
			if run >= minEncodedRunLen {
				return true
			}
		} else {
			run = 0
		}
	}
	return false
}

// externalTransferExpressions lists every expression that can report a match
// for the transfer directive: the pattern itself and its companion arms.
func externalTransferExpressions(re *regexp.Regexp) []*regexp.Regexp {
	return []*regexp.Regexp{re, externalTransferURLCandidateRE, externalTransferFileDirectiveRE}
}

// externalTransferGate admits text that holds the mandatory literals of at
// least one of the directive's expressions. responsePatternMatchLocations
// reports a match only from one of them, so text no expression can match is
// skipped for all three. Any expression without a gate keeps the pattern
// ungated.
func externalTransferGate(re *regexp.Regexp) *responseGate {
	var branches []*responseGate
	for _, expr := range externalTransferExpressions(re) {
		tree, err := syntax.Parse(expr.String(), syntax.Perl)
		if err != nil {
			return nil
		}
		gate := responseLiteralGate(tree)
		if gate == nil {
			return nil
		}
		branches = append(branches, gate)
	}
	return &responseGate{any: branches}
}

func responseMatchingProgram(filters ...*responsePreFilter) *matchingLiterals {
	var literals []string
	var collect func(*responseGate)
	collect = func(g *responseGate) {
		if g == nil {
			return
		}
		if g.literal != "" {
			literal := g.literal
			if g.hasFold {
				literal = g.folded
			}
			if isASCIIString(literal) {
				literals = append(literals, literal)
			}
		}
		for _, child := range g.all {
			collect(child)
		}
		for _, child := range g.any {
			collect(child)
		}
	}
	for _, filter := range filters {
		if filter != nil {
			literals = append(literals, filter.windowAnchors...)
			for _, gate := range filter.gates {
				collect(gate)
			}
		}
	}
	// Give gates and their fallback windows first use of the bounded
	// index. A chain can fall back when a later anchor doesn't fit.
	for _, filter := range filters {
		if filter != nil {
			literals = append(literals, filter.chainLiterals...)
		}
	}
	program := newMatchingLiterals(literals)
	if program != nil {
		program.response = true
	}
	return program
}
