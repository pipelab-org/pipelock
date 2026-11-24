// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package jsonnumber

import (
	"encoding/json"
	"io"
	"regexp"
	"strings"

	"github.com/luckyPipewrench/pipelock/internal/carddlp"
)

// NumberBoundary marks a typed scalar join in the card-only view. It is not
// forwarded content. A comma remains the ordinary view's number barrier;
// this marker lets the separate candidate pass recover only typed joins.
const NumberBoundary = ",\x1f,"

// Mixed boundaries retain which side came from a string. NumberBoundary is
// reserved for two numeric pieces in extractor-produced views.
const (
	NumberStringBoundary = ",\x1fs,"
	StringNumberBoundary = ",\x1fn,"
	StringBoundary       = ",\x1ft,"
)

var boundarySeparator = regexp.MustCompile(`,\x1f([sntu]?),`)

// CardRun retains the provenance of a candidate as well as its digits.
// NumberOnly requires at least two pieces, all JSON number integer components.
type CardRun struct {
	Digits         string
	SpaceCandidate string // complete pieces joined by one ASCII space, or an exact WINDOW hit
	NumberOnly     bool
	RetryOnly      bool // WINDOW found this candidate only by shortening a failed greedy hit
}

// ShippedCardPattern is the canonical generic card rule. Config and the
// structured redactor share it; the scanner applies the configured luhn rule.
const ShippedCardPattern = `\b(?:\d{14,19}|\d{4}(?:[ ._/-]{1,2}\d{4}){2}[ ._/-]{1,2}\d{2,4}|\d{4}[ ._/-]{1,2}\d{6}[ ._/-]{1,2}\d{4,5}|\d{4}(?:[ ._/-]{1,2}\d{4}){3}[ ._/-]{1,2}\d{1,3})\b`

// LegacyCardPattern remains recognized in existing operator preset copies.
const LegacyCardPattern = `\b\d{4}(?:[- ]?\d){11,15}\b`

var shippedCardRule = regexp.MustCompile(LegacyCardPattern)

// IsShippedCardPattern reports whether regex is the canonical card rule. Only
// that rule retries shorter candidates; an operator regex that merely carries
// the luhn validator keeps whole-match semantics.
func IsShippedCardPattern(regex string) bool {
	return regex == ShippedCardPattern || regex == LegacyCardPattern
}

// Enforces applies UNION to a validated candidate: either a complete-piece
// rule match or a shipped-rule WINDOW hit. Number-only runs stay informational.
func (run CardRun) Enforces(pattern *regexp.Regexp) bool {
	if run.NumberOnly {
		return false
	}
	loc := pattern.FindStringIndex(run.SpaceCandidate)
	return loc != nil && loc[0] == 0 && loc[1] == len(run.SpaceCandidate)
}

// EnforcesShippedRule shares the scanner's default criterion with consumers
// that cannot import the scanner, such as the structured redactor.
func (run CardRun) EnforcesShippedRule() bool {
	if run.NumberOnly {
		return false
	}
	if run.Enforces(shippedCardRule) {
		return true
	}
	return carddlp.Visit(run.SpaceCandidate, false, func(c carddlp.Candidate) bool { return c.Start == 0 && c.End == len(run.SpaceCandidate) })
}

type cardPiece struct {
	digits    string
	spelling  string // string piece as written when it contains rule separators
	number    bool
	untrusted bool
}

// stringCardPiece accepts a whole string value made of digit groups joined by
// single separators from the shipped rule's [- ] class. Any other character
// leaves the value outside every typed run, as before.
func stringCardPiece(value string) (cardPiece, bool) {
	if !groupedDigits.MatchString(value) {
		return cardPiece{}, false
	}
	digits := cardSeparatorRemover.Replace(value)
	if digits == value {
		return cardPiece{digits: digits}, true
	}
	return cardPiece{digits: digits, spelling: value}, true
}

var (
	groupedDigits        = regexp.MustCompile(`^[0-9]+(?:[- ][0-9]+)*$`)
	cardSeparatorRemover = strings.NewReplacer(" ", "", "-", "")
	cardBoundaryEscaper  = strings.NewReplacer("\x1fn,", "\x1fu,", "\x1fs,", "\x1fu,", "\x1ft,", "\x1fu,", "\x1f,", "\x1fu,")
)

// EscapeCardBoundaries retains scans of input markers without granting type
// provenance. The u marker retains untrusted spelling without granting
// synthetic-piece classification to input control bytes.
func EscapeCardBoundaries(text string) string {
	return cardBoundaryEscaper.Replace(text)
}

// CardBoundary encodes the types at a join in an extractor-produced view.
func CardBoundary(leftNumber, rightNumber bool) string {
	if leftNumber && rightNumber {
		return NumberBoundary
	}
	if leftNumber {
		return NumberStringBoundary
	}
	if rightNumber {
		return StringNumberBoundary
	}
	return StringBoundary
}

// These are the existing validateLuhn length bounds. Run enumeration uses
// them only to cap work; the configured regex and validator decide findings.
const (
	cardRunMinDigits = carddlp.MinDigits
	cardRunMaxDigits = 19
)

// HasShippedCardCandidate shares the bounded candidate language with the
// terminal decoder's admission check. The full lane still confirms every span.
func HasShippedCardCandidate(text string, validate func(string) bool) bool {
	return carddlp.VisitWindow(text, func(c carddlp.Candidate) bool { return validate(text[c.Start:c.End]) })
}

// ValidCardNumber applies the card issuer ranges and Luhn checksum used by
// the scanner's luhn validator. The JSON run pass and redactor share it.
func ValidCardNumber(s string) bool { return carddlp.ValidCardNumber(s) }

// ValidCardIssuer shares issuer validation with every card consumer.
func ValidCardIssuer(digits []byte, n int) bool { return carddlp.ValidCardIssuer(digits, n) }

func appendCardSubruns(runs []CardRun, pieces []cardPiece) []CardRun {
	for start, first := range pieces {
		var candidate strings.Builder
		var spaced strings.Builder
		numberOnly := true
		untrusted := false
		for end := start; end < len(pieces); end++ {
			candidate.WriteString(pieces[end].digits)
			if end > start {
				spaced.WriteByte(' ')
			}
			if pieces[end].spelling != "" {
				spaced.WriteString(pieces[end].spelling)
			} else {
				spaced.WriteString(pieces[end].digits)
			}
			numberOnly = numberOnly && pieces[end].number
			untrusted = untrusted || pieces[end].untrusted
			size := candidate.Len()
			if size > cardRunMaxDigits {
				break
			}
			if (end > start || first.number) && size >= cardRunMinDigits {
				if value := candidate.String(); ValidCardNumber(value) {
					spaceCandidate := spaced.String()
					if untrusted {
						spaceCandidate = value
					}
					runs = append(runs, CardRun{Digits: value, SpaceCandidate: spaceCandidate, NumberOnly: numberOnly && end > start && !untrusted})
				}
			}
		}
	}
	return runs
}

// appendCardWindows enumerates overlapping candidates in the typed scalar
// sequence while retaining its existing whole-match grammar. Keep literal string context and separators: compacting
// them would invent matches outside that rule. Only hits crossing a typed join
// belong here; whole-leaf matching remains the caller's ordinary scan.
func appendCardWindows(runs []CardRun, pieces []cardPiece) []CardRun {
	if len(pieces) < 2 {
		return runs
	}
	var joined strings.Builder
	type span struct {
		start, end int
		number     bool
	}
	spans := make([]span, 0, len(pieces))
	for i, piece := range pieces {
		if i > 0 {
			joined.WriteByte(' ')
		}
		start := joined.Len()
		if piece.spelling != "" {
			joined.WriteString(piece.spelling)
		} else {
			joined.WriteString(piece.digits)
		}
		spans = append(spans, span{start, joined.Len(), piece.number})
	}
	text := joined.String()
	seen := make(map[CardRun]struct{}, len(runs))
	for _, run := range runs {
		seen[run] = struct{}{}
	}

	next := 0
	carddlp.Visit(text, true, func(c carddlp.Candidate) bool {
		// Typed WINDOW reconstruction retains the original bounded grammar. New
		// literal group presentations are inspected on each leaf independently.
		loc := shippedCardRule.FindStringIndex(text[c.Start:c.End])
		if loc == nil || loc[0] != 0 || loc[1] != c.End-c.Start {
			return false
		}
		if c.Start > 0 {
			b := text[c.Start-1]
			if b >= 'a' && b <= 'z' || b >= 'A' && b <= 'Z' || b >= '0' && b <= '9' || b == '_' {
				return false
			}
		}

		for next < len(spans) && spans[next].end <= c.Start {
			next++
		}
		count, stringHit := 0, false
		for _, span := range spans[next:] {
			if span.start >= c.End {
				break
			}
			if span.end > c.Start {
				count++
				stringHit = stringHit || !span.number
			}
		}
		if count > 1 {
			run := CardRun{Digits: c.Digits, SpaceCandidate: text[c.Start:c.End], NumberOnly: !stringHit}
			// Preserve whole-match semantics for operator Luhn regexes. WINDOW
			// candidates absent from complete-piece reconstruction are fallback-only.
			if _, exists := seen[run]; exists {
				return false
			}
			// The old greedy grammar could swallow a following digit group. Only
			// that shortening is canonical-only; ordinary WINDOW hits stay shared.
			window := text[c.Start:min(len(text), c.Start+40)]
			if greedy := shippedCardRule.FindStringIndex(window); greedy != nil && greedy[0] == 0 && greedy[1] > c.End-c.Start {
				run.RetryOnly = true
			}
			if _, exists := seen[run]; !exists {
				seen[run] = struct{}{}
				runs = append(runs, run)
			}
		}
		return false
	})

	return runs
}

// BoundaryCardRuns returns runs made by joining typed scalar atoms. A run
// needs a typed boundary, so ordinary comma-separated prose is not promoted.
func BoundaryCardRuns(view string) []CardRun {
	boundaries := boundarySeparator.FindAllStringSubmatch(view, -1)
	if len(boundaries) == 0 {
		return nil
	}
	parts := boundarySeparator.Split(view, -1)
	var runs []CardRun
	var pieces []cardPiece
	var windows []cardPiece
	flush := func() {
		if len(pieces) > 1 {
			runs = appendCardSubruns(runs, pieces)
		}
		pieces = nil
	}
	for i, part := range parts {
		number := true
		if i > 0 && (boundaries[i-1][1] == "s" || boundaries[i-1][1] == "t") {
			number = false
		}
		if i < len(boundaries) && (boundaries[i][1] == "n" || boundaries[i][1] == "t") {
			number = false
		}
		untrusted := i > 0 && boundaries[i-1][1] == "u" || i < len(boundaries) && boundaries[i][1] == "u"
		// Only numeric atoms carry IntegralView's trailing comma mask. A string
		// prefix, suffix, sign or comma must not be cropped into a new piece.
		if number || untrusted {
			part = strings.TrimRight(part, ",")
		}
		windows = append(windows, cardPiece{spelling: part, number: number && !untrusted})
		piece := cardPiece{digits: part}
		if number && !untrusted {
			if !allDigits(part) {
				flush()
				continue
			}
		} else if grouped, ok := stringCardPiece(part); ok {
			piece = grouped
		} else {
			flush()
			continue
		}
		piece.number = number && !untrusted
		piece.untrusted = untrusted
		pieces = append(pieces, piece)
	}
	flush()
	return appendCardWindows(runs, windows)
}

// CardRuns returns adjacent scalar candidates and single numeric cards.
// NumberOnly is true only for at least two numeric pieces. Object keys are
// skipped; arrays and nesting do not break a run. A non-digit scalar value
// interrupts complete-piece candidates and remains literal WINDOW context.
// Each number contributes
// only its written integer component, preserving the single-number fraction
// policy while still examining separate numbers together. Callers apply their
// existing card rule to these candidates. Invalid, over-depth or over-budget
// documents have no typed run and retain the caller's conservative raw scan.
func CardRuns(text string, maxDepth int) []CardRun {
	runs, _ := CardRunsWithLimit(text, maxDepth)
	return runs
}

// CardRunLimit identifies why a valid JSON document could not be inspected.
type CardRunLimit uint8

const (
	CardRunWithinBudget CardRunLimit = iota
	CardRunDepthLimit
	CardRunNumberLimit
)

// CardRunsWithLimit also reports a valid document whose number or nesting
// exceeds the typed inspection budget. Callers must refuse that document.
// Invalid JSON is left to the transport parser or the ordinary text scan.
func CardRunsWithLimit(text string, maxDepth int) ([]CardRun, CardRunLimit) {
	if !json.Valid([]byte(text)) {
		return nil, CardRunWithinBudget
	}
	dec := json.NewDecoder(strings.NewReader(text))
	dec.UseNumber()
	type frame struct {
		object    bool
		expectKey bool
	}
	var stack []frame
	var runs []CardRun
	var pieces []cardPiece
	var windows []cardPiece
	flush := func() {
		runs = appendCardSubruns(runs, pieces)
		pieces = nil
	}
	for {
		tok, err := dec.Token()
		if err == io.EOF {
			flush()
			return appendCardWindows(runs, windows), CardRunWithinBudget
		}
		if err != nil {
			return nil, CardRunNumberLimit
		}
		switch v := tok.(type) {
		case json.Delim:
			switch v {
			case '{', '[':
				stack = append(stack, frame{object: v == '{', expectKey: v == '{'})
				if len(stack) > maxDepth {
					return nil, CardRunDepthLimit
				}
			case '}', ']':
				stack = stack[:len(stack)-1]
			}
		case string:
			if len(stack) > 0 && stack[len(stack)-1].object && stack[len(stack)-1].expectKey {
				stack[len(stack)-1].expectKey = false
				continue
			}
			windows = append(windows, cardPiece{spelling: v})
			if piece, ok := stringCardPiece(v); ok {
				pieces = append(pieces, piece)
			} else {
				flush()
			}
		case json.Number:
			if _, ok := boundedComponents(v.String()); !ok {
				return nil, CardRunNumberLimit
			}
			integer, _, _ := strings.Cut(v.String(), ".")
			integer, _, _ = strings.Cut(integer, "e")
			integer, _, _ = strings.Cut(integer, "E")
			windows = append(windows, cardPiece{spelling: integer, number: true})
			if allDigits(integer) {
				pieces = append(pieces, cardPiece{digits: integer, number: true})
			} else {
				flush()
				// A minus sign ends adjacency, but does not exempt a single card.
				if unsigned, signed := strings.CutPrefix(integer, "-"); signed && allDigits(unsigned) {
					runs = appendCardSubruns(runs, []cardPiece{{digits: unsigned, number: true}})
				}
			}
		default:
			// Booleans and null must retain their place in the scalar sequence.
			barrier, _ := json.Marshal(v)
			windows = append(windows, cardPiece{spelling: string(barrier)})
			flush()
		}
		if len(stack) > 0 && stack[len(stack)-1].object && !stack[len(stack)-1].expectKey {
			stack[len(stack)-1].expectKey = true
		}
	}
}

// ScalarIntegerCardRuns returns the single-number card candidate of one bare
// JSON number that exceeds the typed budget. It only cuts the written
// spelling, so no exponent is evaluated and the budget is not needed; an
// oversized exponent or fraction cannot hide an integer component card.
func ScalarIntegerCardRuns(number string) []CardRun {
	integer, _, _ := strings.Cut(strings.TrimSpace(number), ".")
	integer, _, _ = strings.Cut(integer, "e")
	integer, _, _ = strings.Cut(integer, "E")
	integer = strings.TrimPrefix(integer, "-")
	if !allDigits(integer) || len(integer) > cardRunMaxDigits {
		return nil
	}
	return appendCardSubruns(nil, []cardPiece{{digits: integer, number: true}})
}

func allDigits(value string) bool {
	if value == "" {
		return false
	}
	for i := range len(value) {
		if value[i] < '0' || value[i] > '9' {
			return false
		}
	}
	return true
}

// IntegralView retains the written integer component of a bounded RFC 8259
// number. Pipelock's card policy excludes fraction and exponent syntax; it
// neither evaluates exponents nor rounds numbers. Invalid or over-budget
// spellings retain their original conservative scan view.
//
// Commas preserve byte coordinates and the numeric-leaf channel's value
// separation convention (jsonrpc.ExtractNumericLeaves). Unlike whitespace,
// they survive DLP compaction, so masked numbers cannot fabricate a card by
// joining their integer components. This internal scan view is never parsed
// as JSON or forwarded; known values and other detectors use the original.
func IntegralView(n json.Number) string {
	s := n.String()
	if _, ok := boundedComponents(s); !ok {
		return s
	}
	end := strings.IndexAny(s, ".eE")
	if end < 0 {
		return s
	}
	return s[:end] + strings.Repeat(",", len(s)-end)
}

// CardView applies IntegralView only to numeric tokens in one complete JSON
// document. Strings and keys keep their original spelling; JSON-looking string
// values are never parsed recursively. Malformed or over-depth documents retain
// the original view. maxDepth comes from the consuming JSON extractor's contract.
func CardView(text string, maxDepth int) string {
	if !strings.ContainsAny(text, ".eE") || !json.Valid([]byte(text)) {
		return text
	}
	dec := json.NewDecoder(strings.NewReader(text))
	dec.UseNumber()
	var view []byte
	depth := 0
	for {
		tok, err := dec.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return text
		}
		switch v := tok.(type) {
		case json.Delim:
			if v == '{' || v == '[' {
				depth++
				if depth > maxDepth {
					return text
				}
			} else {
				depth--
			}
		case json.Number:
			if _, ok := boundedComponents(v.String()); !ok {
				return text
			}
			projected := IntegralView(v)
			if projected != v.String() {
				if view == nil {
					view = []byte(text)
				}
				end := int(dec.InputOffset())
				copy(view[end-len(projected):end], projected)
			}
		}
	}
	if view == nil {
		return text
	}
	return string(view)
}

// StructuredCardView applies the numeric policy only to complete JSON objects
// and arrays. Text transports retain ordinary card scanning for scalar payloads.
func StructuredCardView(text string, maxDepth int) string {
	trimmed := strings.TrimSpace(text)
	if len(trimmed) == 0 || (trimmed[0] != '{' && trimmed[0] != '[') {
		return text
	}
	return CardView(text, maxDepth)
}
