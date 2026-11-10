// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"crypto/sha256"
	"fmt"
	"math"
	"regexp"
	"regexp/syntax"
	"slices"
	"strings"
	"unicode/utf8"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

// RFC 4648 sections 4-8 define the symbol bits. Aho and Corasick (1975)
// supplies raw literal search. Regex bounds come from regexp/syntax.
// Inputs are raw bytes; non-alphabet bytes do not advance the symbol index.
// This terminal handles one RFC layer, with no sparse or escape transducer.
type assembledPlan struct {
	nestedHex      bool
	nestedMinimum  int
	shapeGroups    [textDLPCardPatterns + 1][5][]assembledShapeGroup
	shapes         []*assembledShape
	unscreened     []int // Named residuals; these retain only historical scanner coverage.
	admitted       []*regexp.Regexp
	active         []bool
	decoderAllowed []bool
	raw            [5]reassemblyAC
	verify         []*regexp.Regexp
	literalBytes   []int
}

func compileAssembledPlan(p *reassemblyPlan) (*assembledPlan, error) {
	a := &assembledPlan{verify: make([]*regexp.Regexp, len(p.patterns)), literalBytes: make([]int, len(p.patterns))}
	a.active = make([]bool, len(p.patterns))
	a.decoderAllowed = make([]bool, len(p.patterns))
	a.admitted = make([]*regexp.Regexp, len(p.patterns))
	a.nestedHex = true
	canonical := make(map[string]string)
	for _, d := range config.DefaultDLPPatterns() {
		canonical[d.Name] = "(?i)" + d.Regex
	}
	minimum := math.MaxInt
	for _, pattern := range p.patterns {
		tree, err := syntax.Parse(pattern.re.String(), syntax.Perl)
		if err != nil {
			return nil, err
		}
		if canonical[pattern.name] != pattern.re.String() {
			tree, _ = assembledAdmittedTree(tree)
			if tree == nil {
				continue
			}
		}
		minimum = min(minimum, shapeMinLen(tree))
	}
	a.nestedHex = minimum != math.MaxInt
	if minimum != math.MaxInt {
		// RFC 4648's widest alphabet carries six bits per symbol. A match
		// consuming at least m bytes needs at least ceil(8m/6) inner symbols.
		a.nestedMinimum = (minimum*8 + 5) / 6
	}
	for codec := range a.raw {
		a.raw[codec] = reassemblyAC{codec: codec, building: []reassemblyBuildNode{{}}}
	}

	for id, pattern := range p.patterns {
		literals := p.required[id]
		tree, err := syntax.Parse(pattern.re.String(), syntax.Perl)
		if err != nil {
			return nil, err
		}
		// newReassemblyPlan derived the cue set from this tree.
		anchors, err := syntax.Parse(strings.TrimPrefix(pattern.re.String(), "(?i)"), syntax.Perl)
		if err != nil {
			return nil, err
		}
		if canonical[pattern.name] != pattern.re.String() {
			selected, residual := assembledAdmittedTree(tree)
			if residual {
				a.unscreened = append(a.unscreened, id)
			}
			if selected == nil {
				continue
			}
			if residual {
				tree = selected
				anchors = selected
				a.admitted[id] = assembledAdmissionRegexp(tree)
				literals = assembledAdmissionLiterals(tree)
			}
		}
		a.active[id] = true
		a.decoderAllowed[id] = canonical[pattern.name] == pattern.re.String() || assembledRawAdmits(tree)
		kind := 0
		if canonical[pattern.name] == pattern.re.String() {
			switch pattern.name {
			case "Social Security Number", "Credit Card Number", "IBAN", "Bitcoin WIF Private Key", "Ethereum Private Key":
				shape, err := getAssembledShape(id, pattern.re.String())
				if err != nil {
					return nil, err
				}
				shape.validateRule = pattern.name == "IBAN" || pattern.name == "Bitcoin WIF Private Key"
				a.shapes = append(a.shapes, shape)
			}
		}
		if canonical[pattern.name] == pattern.re.String() {
			switch pattern.name {
			case "Discord Bot Token":
				literals = []string{".", "mfa."}
				kind = 1
			case "Twilio API Key":
				literals = []string{"SK"}
				kind = 2
			}
		}
		// The admission unit is the existing normalizer cap. Under independent
		// folded ASCII bytes, sum assembledEmissionRatio*(2/256)^length over the literal set.
		// One expected cue per cap-sized raw region gives a three-byte minimum.
		rate := 0.0
		for _, lit := range literals {
			rate += assembledEmissionRatio * math.Pow(1.0/128, float64(len(lit)))
		}
		// A finite grammar without an admitted raw literal can join the
		// paired screen when its syntax supplies a positive run bound.
		// Unsupported grammars keep their existing scanner paths.
		if (len(literals) == 0 || kind == 0 && rate > 1.0/float64(maxReassembledTokenLen) || slices.ContainsFunc(literals, func(literal string) bool { return strings.ContainsRune(literal, utf8.RuneError) })) && !slices.ContainsFunc(a.shapes, func(shape *assembledShape) bool { return shape.id == id }) {
			for _, branch := range assembledShapeBranches(tree) {
				// The correlated-pair proof needs floor(8*m/6)-2 >= 1
				// even for RFC 4648's widest alphabet. Declined configured
				// branches retain only their historical scanner paths.
				if reassemblyMaxBytes(branch) < 0 || shapeMinLen(branch)*8/6-2 < 1 {
					if !slices.Contains(a.unscreened, id) {
						a.unscreened = append(a.unscreened, id)
					}
					continue
				}
				shape, err := getAssembledShape(id, branch.String())
				if err != nil {
					return nil, fmt.Errorf("compile reassembly screen: %w", err)
				}
				a.shapes = append(a.shapes, shape)
			}
		}
		if kind == 0 && rate > 1.0/float64(maxReassembledTokenLen) {
			continue
		}
		var quoted []string
		for _, literal := range literals {
			quoted = append(quoted, assembledLiteralExpr(tree, literal))
			a.literalBytes[id] = max(a.literalBytes[id], len(literal)*utf8.UTFMax)
			for _, v := range reassemblyVariants(literal) {
				for codec := range a.raw {
					for pad := range 8 {
						core, delta := reassemblyCore(v, codec, pad)
						if len(core) > 0 {
							a.raw[codec].add(core, reassemblyNeedle{pattern: id, delta: delta, kind: kindForLiteral(kind, literal)})
							continue
						}
						// A one-rune literal can have no complete interior RFC symbol.
						// Enumerate the unknown edge bits, retaining the known literal bits.
						for _, edge := range assembledEdges(v, codec, pad) {
							a.raw[codec].add(edge, reassemblyNeedle{pattern: id, delta: pad*8/reassemblyCodecs[codec].width*reassemblyCodecs[codec].width - pad*8, kind: kindForLiteral(kind, literal)})
						}
					}
				}
			}
		}
		if len(quoted) > 0 {
			a.verify[id] = regexp.MustCompile("^(?:" + strings.Join(quoted, "|") + ")")
			if prefix, size := assembledCueVerifier(tree, anchors, literals); prefix != nil {
				a.verify[id] = prefix
				a.literalBytes[id] = max(a.literalBytes[id], size)
			}
		}
	}
	for codec := range a.raw {
		a.raw[codec].build()
	}
	return a, nil
}

// Preserve exact-case anchors from the compiled syntax tree. Composite
// anchors retain a conservative folded verifier if no single node owns them.
// This verifier only admits replay; the complete regex still accepts findings.
func assembledLiteralExpr(tree *syntax.Regexp, literal string) string {
	var expressions []string
	wanted := []rune(literal)
	var visit func(*syntax.Regexp)
	add := func(value string, fold bool) {
		expr := regexp.QuoteMeta(value)
		if fold {
			expr = "(?i:" + expr + ")"
		}
		if !slices.Contains(expressions, expr) {
			expressions = append(expressions, expr)
		}
	}
	visit = func(r *syntax.Regexp) {
		if r.Op == syntax.OpLiteral && strings.EqualFold(string(r.Rune), literal) {
			add(string(r.Rune), r.Flags&syntax.FoldCase != 0)
		}
		if r.Op == syntax.OpCharClass && len(wanted) == 1 {
			if values, ok := smallCharClassAlternatives(r.Rune); ok {
				for _, value := range values {
					if strings.EqualFold(value, literal) {
						add(value, r.Flags&syntax.FoldCase != 0)
					}
				}
			}
		}
		for _, sub := range r.Sub {
			visit(sub)
		}
	}
	visit(tree)
	if len(expressions) == 0 {
		return "(?i:" + regexp.QuoteMeta(literal) + ")"
	}
	return "(?:" + strings.Join(expressions, "|") + ")"
}

func assembledEdges(value string, codec, pad int) [][]byte {
	c := reassemblyCodecs[codec]
	first, last := pad*8/c.width, ((pad+len(value))*8+c.width-1)/c.width
	out := [][]byte{{}}
	for symbol := first; symbol < last; symbol++ {
		var next [][]byte
		for v := 0; v < 1<<c.width; v++ {
			good := true
			for bit := range c.width {
				at := symbol*c.width + bit - pad*8
				if at >= 0 && at < len(value)*8 && (v>>uint(c.width-1-bit))&1 != int(value[at/8]>>uint(7-at%8))&1 {
					good = false
					break
				}
			}
			if good {
				for _, prefix := range out {
					next = append(next, append(slices.Clone(prefix), c.alphabet[v]))
				}
			}
		}
		out = next
	}
	return out
}

type assembledIdentity struct {
	pattern int
	value   [32]byte
}

type (
	assembledBudget struct {
		memo          *decodingMemo
		patterns      textDLPPatternSet
		decoderOnly   bool
		charged       map[string]*assembledCharges
		registry      *assembledChargeRegistry
		used          int
		incomplete    bool
		produced      map[assembledIdentity]struct{}
		admitted      bool
		admissionOnly bool
	}
	assembledScan struct {
		p         *reassemblyPlan
		text      string
		result    reassemblyResult
		budget    *assembledBudget
		charges   *assembledCharges
		lanes     [5][8]*assembledLane
		checked   [5][]uint8
		encoding  string
		viewLabel string
	}
)

// Recover the last n decoded bytes by counting only RFC symbols backwards.
// Coordinates use the true phase origin, so an under-cap prefix cannot shift it.
type assembledPosition struct{ codec, phase, symbols, end int }

func assembledOrigin(text string, position assembledPosition, n int) reassemblyRef {
	codec, phase, symbols, end := position.codec, position.phase, position.symbols, position.end
	c := reassemblyCodecs[codec]
	count := max(0, (symbols-phase)*c.width/8)
	startByte := max(0, count-n)
	bit := phase*c.width + startByte*8
	startSymbol := bit / c.width
	need := symbols - startSymbol
	raw := end
	for need > 0 && raw > 0 {
		raw--
		if c.values[text[raw]] >= 0 {
			need--
		}
	}
	return reassemblyRef{raw: raw, skip: uint8(bit % c.width & 7)}
}

func (s *assembledScan) literal(codec, phase, symbols, end int, hit reassemblyNeedle) {
	id := hit.pattern
	a := s.p.assembled
	c := reassemblyCodecs[codec]
	startBit := (symbols-hit.length)*c.width - hit.delta
	if startBit < phase*c.width {
		return
	}
	literalByte := (startBit - phase*c.width) / 8
	count := (symbols - phase) * c.width / 8
	ref := assembledOrigin(s.text, assembledPosition{codec, phase, symbols, end}, count-literalByte)
	data := make([]byte, 0, a.literalBytes[id])
	assembledReplay(s.text, codec, ref.raw, len(s.text), ref.skip, func(b byte, _ int) bool {
		data = append(data, b)
		return len(data) < cap(data)
	})
	loc := a.verify[id].FindIndex(data)
	if loc == nil {
		return
	}
	s.searchLane(codec, phase, id)
}

// A lane is the exact RFC-decoded view, with its true phase origin and EOF.
// Search state stays in this scan; the shared decode store remains immutable.
type assembledLane struct {
	view          string
	keyword       *keywordCandidateContext
	presence      map[*config.DLPKeywordMatcher]bool
	keywordMapped bool
	retained      bool
}

func (s *assembledScan) searchLane(codec, phase, id int) {
	if s.budget.admissionOnly {
		s.budget.admitted = true
		return
	}
	if s.budget.incomplete {
		s.result.incomplete = true
		return
	}
	if s.checked[codec] == nil {
		s.checked[codec] = make([]uint8, len(s.p.patterns))
	}
	phaseBit := uint8(1) << uint(phase)
	if s.checked[codec][id]&phaseBit != 0 {
		return
	}
	s.checked[codec][id] |= phaseBit
	s.budget.admitted = true
	lane := s.lanes[codec][phase]
	if lane == nil {
		if s.charges == nil {
			s.charges = s.budget.chargesFor(s.text)
		}
		data := make([]byte, 0)
		decodedByte := 0
		assembledReplay(s.text, codec, 0, len(s.text), uint8(phase*reassemblyCodecs[codec].width&0xff), func(b byte, _ int) bool {
			if !s.budget.charge(s.charges, codec, phase, decodedByte) {
				return false
			}
			decodedByte++
			data = append(data, b)
			return true
		})
		if s.budget.incomplete {
			s.result.incomplete = true
			return
		}
		lane = &assembledLane{view: string(data)}
		s.lanes[codec][phase] = lane
	}
	pattern := s.p.assembled.terminalPattern(id, s.p.patterns[id])
	if !pattern.admitsView(lane.view) {
		return
	}
	// firstAcceptedSpan preserves validator and canonical WIF overlap handling.
	// Unlike a sliced confirmation, this complete lane has no artificial UTF-8
	// edges: regexp sees the true phase origin, neighboring runes and EOF.
	matchPattern := pattern
	if pattern.keywords != nil {
		copyPattern := *pattern
		copyPattern.keywords = nil // Context is checked per candidate below.
		matchPattern = &copyPattern
	}
	accepted := false
	matchPattern.firstAcceptedSpan(lane.view, func(begin, finish int) bool {
		if pattern.withoutLeftBoundary != nil {
			loc := pattern.withoutLeftBoundary.FindStringIndex(lane.view[begin:finish])
			if loc == nil {
				return false
			}
			finish = begin + loc[1]
			begin += loc[0]
		}
		if pattern.keywords != nil && s.budget.produced != nil {
			key := assembledIdentity{pattern: id, value: sha256.Sum256([]byte(lane.view[begin:finish]))}
			if _, exists := s.budget.produced[key]; exists {
				return false
			}
		}
		if pattern.keywords != nil && !s.keywordPossible(pattern, lane) {
			s.rememberKeyword(lane, codec, phase, id, -1, -1)
			return true
		}
		if pattern.keywords != nil {
			s.rememberKeyword(lane, codec, phase, id, begin, finish)
			if accepted || s.budget.incomplete {
				return false
			}
		}
		if !s.keywordMatches(pattern, lane, codec, phase, begin, finish) {
			return false
		}
		s.encoding = reassemblyCodecs[codec].name
		s.viewLabel = fmt.Sprintf("reassembly:%s:phase_%d", s.encoding, phase)
		accepted = s.produce(id, lane.view, begin, finish)
		return accepted && pattern.keywords == nil
	})
}

func (s *assembledScan) produce(id int, view string, begin, finish int) bool {
	if s.budget.decoderOnly && !s.p.assembled.decoderAllowed[id] {
		return false
	}
	identity := sha256.Sum256([]byte(view[begin:finish]))
	key := assembledIdentity{pattern: id, value: identity}
	if s.budget.produced != nil {
		if _, exists := s.budget.produced[key]; exists {
			return false
		}
		s.budget.produced[key] = struct{}{}
	}
	pattern := s.p.patterns[id]
	s.result.findings = append(s.result.findings, TextDLPMatch{Encoded: s.encoding, span: newMatchSpan(begin, finish, s.viewLabel, pattern.name, pattern.bundle, pattern.bundleVersion), keywordGated: pattern.keywords != nil, PatternName: pattern.name, Severity: pattern.severity, Bundle: pattern.bundle, BundleVersion: pattern.bundleVersion, Warn: pattern.warn, genericCard: pattern.genericCard, cardPrefixRetry: pattern.cardPrefixRetry, valueIdentity: identity, hasValueIdentity: true, credentialAudienceHosts: pattern.credentialAudienceHosts, credentialAudienceAuthorizationOnly: pattern.credentialAudienceAuthorizationOnly, credentialAudienceCarrierMask: pattern.credentialAudienceCarrierMask, credentialAudienceGitHosts: pattern.credentialAudienceGitHosts, credentialAudienceRegistryHosts: pattern.credentialAudienceRegistryHosts})
	return true
}

// admitsAssembledView runs the same context-independent admission grammar as
// matching, without decoding lanes or spending their inspection allowance.
func (p *reassemblyPlan) admitsAssembledView(text string) bool {
	probe := assembledBudget{admissionOnly: true}
	assembledLayer(p, text, &probe, 0)
	return probe.admitted || p.assembled.nestedHex && assembledOuterAdmits(p, text, 0)
}

func assembledLayer(p *reassemblyPlan, text string, budget *assembledBudget, skip uint8) reassemblyResult {
	patternSet := budget.patterns
	if patternSet != textDLPAllPatterns && patternSet != textDLPCardPatterns {
		patternSet = textDLPNonCardPatterns
	}
	scan := assembledScan{p: p, text: text, budget: budget}
	for codec := range reassemblyCodecs {
		if skip&(1<<uint(codec)) != 0 {
			continue
		}
		c := &reassemblyCodecs[codec]
		a := &p.assembled.raw[codec]
		state := uint32(0)
		symbols, rawEnd := 0, 0
		previous := int16(0)
		groups := p.assembled.shapeGroups[patternSet][codec]
		var scratch [7]uint64 // Canonical shape groups fit on the stack; configured groups may allocate.
		shapeStates := scratch[:]
		if len(groups) > len(shapeStates) {
			shapeStates = make([]uint64, len(groups))
		}
		for i := range groups {
			shapeStates[i] = groups[i].bias
		}
		cue := func(phase, id int, literal *reassemblyNeedle) {
			if id < 0 || budget.decoderOnly && !p.assembled.decoderAllowed[id] || !budget.patterns.includes(p.patterns[id].genericCard) {
				return
			}
			if scan.checked[codec] != nil && scan.checked[codec][id]&(uint8(1)<<uint(phase)) != 0 {
				return
			}
			if literal != nil && literal.kind != 0 && !assembledShortEligible(text, codec, phase, symbols, rawEnd, *literal) {
				return
			}
			if literal != nil {
				scan.literal(codec, phase, symbols, rawEnd, *literal)
			} else {
				scan.searchLane(codec, phase, id)
			}
		}
		for i := range len(text) {
			v := c.values[text[i]]
			if v < 0 {
				continue
			}
			symbols++
			rawEnd = i + 1
			state = a.nodes[state].next[v]
			for j := range groups {
				group := &groups[j]
				hits := group.step((symbols-1)&(c.quantum-1), int(v), &shapeStates[j])
				for hits != 0 {
					lane := shapePhase(hits)
					hits &^= uint64(128) << uint(lane*8)
					entry := group.lanes[lane]
					shape, phase := entry.shape, entry.phase
					if budget.decoderOnly && !p.assembled.decoderAllowed[shape.id] || scan.checked[codec] != nil && scan.checked[codec][shape.id]&(uint8(1)<<uint(phase)) != 0 {
						continue
					}
					if (symbols-phase)*c.width >= 8 && shape.pair(codec, phase, symbols, previous, v) && shape.run(text, codec, phase, symbols, rawEnd) {
						cue(phase, shape.id, nil)
					}
				}
			}
			previous = v
			for _, hit := range a.nodes[state].out {
				startSymbol := symbols - hit.length
				for phase := range c.quantum {
					if ((startSymbol-phase)*c.width-hit.delta)%8 == 0 {
						cue(phase, hit.pattern, &hit)
					}
				}
			}
			if budget.admissionOnly && budget.admitted {
				return reassemblyResult{}
			}
		}
	}
	scan.result.incomplete = budget.incomplete
	return scan.result
}

// Preserve each top-level alternative's own lower bound, including captures.
// regexp/syntax supplies the grammar; only admitted alternatives confirm cues.
func assembledShapeBranches(tree *syntax.Regexp) []*syntax.Regexp {
	if tree.Op == syntax.OpAlternate {
		var out []*syntax.Regexp
		for _, sub := range tree.Sub {
			out = append(out, assembledShapeBranches(sub)...)
		}
		return out
	}
	if tree.Op == syntax.OpCapture && len(tree.Sub) == 1 {
		branches := assembledShapeBranches(tree.Sub[0])
		out := make([]*syntax.Regexp, 0, len(branches))
		for _, branch := range branches {
			copyTree := *tree
			copyTree.Sub = []*syntax.Regexp{branch}
			out = append(out, &copyTree)
		}
		return out
	}
	return []*syntax.Regexp{tree}
}

// Reassembly consumers share the admitted language. Historical plaintext and
// normalizer scans keep the original compiled pattern unchanged.
func (a *assembledPlan) terminalPattern(id int, original *compiledPattern) *compiledPattern {
	if len(a.active) > 0 && !a.active[id] {
		return nil
	}
	if id < len(a.admitted) && a.admitted[id] != nil {
		copyPattern := *original
		copyPattern.re = a.admitted[id]
		return &copyPattern
	}
	return original
}
