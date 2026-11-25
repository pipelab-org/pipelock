// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"crypto/sha256"
	"encoding/json"
	"strings"
	"unicode/utf8"

	"github.com/luckyPipewrench/pipelock/internal/config"

	"github.com/luckyPipewrench/pipelock/internal/extract"
	"github.com/luckyPipewrench/pipelock/internal/jsonnumber"

	"github.com/luckyPipewrench/pipelock/internal/carddlp"
	"github.com/luckyPipewrench/pipelock/internal/normalize"
)

// corroboratedCardMatches only adds enforcing evidence. It preserves labels
// omitted from typed card joins without admitting unlabelled number joins.
func (s *Scanner) corroboratedCardMatches(text string) []TextDLPMatch {
	matches := s.scanCorroboratedCardView(text, "")
	if json.Valid([]byte(text)) {
		atoms := extract.AllStringsFromJSONResult(json.RawMessage(text)).Atoms
		for _, atom := range atoms {
			if atom.Key || atom.ContextKey == "" {
				continue
			}
			source := atom.Card
			if atom.Number {
				source = atom.Text
			}
			matches = append(matches, s.scanCorroboratedCardView(source, atom.ContextKey)...)
		}
		extract.VisitKeyedCardRuns(atoms, func(key string, run jsonnumber.CardRun) bool {
			if carddlp.CorroboratedKey(key) {
				matches = append(matches, s.scanCorroboratedCardView(run.Digits, key)...)
			}
			return false
		})
	}
	return matches
}

func (s *Scanner) scanCorroboratedCardView(text, key string) []TextDLPMatch {
	text = normalize.ForCardText(text)
	var matches []TextDLPMatch
	for _, idx := range s.dlpCardPatternIndices {
		p := s.dlpPatterns[idx]
		if !p.cardPrefixRetry {
			continue
		}
		carddlp.VisitWithKey(text, key, func(c carddlp.Candidate) bool {
			if c.PublicExample || (!carddlp.CorroboratedKey(key) && !carddlp.Corroborated(text, c)) || !p.accepts(text, c.Start, c.End) {
				return false
			}
			m := p.textDLPFinding(text, "", c.Start, c.End, false)
			m.CardConfidence = "high"
			m.keywordGated = true
			matches = append(matches, m)
			return true
		})
	}
	return matches
}

// cardLiteralProof records unchanged intervals once per normalized view.
// Queries follow candidate order and advance one cursor, so total mapping work
// is linear. Removed runes split intervals even when they emit no view bytes.
type cardLiteralProof struct {
	spans             []textByteSpan
	length            int
	cursor, lastStart int
	valid, unchanged  bool
}

func newCardLiteralProof(source, view string) *cardLiteralProof {
	proof := &cardLiteralProof{length: len(view), lastStart: -1}
	if source == view {
		proof.valid = true
		proof.unchanged = true
		return proof
	}
	if normalize.ForCardText(source) != view {
		return proof
	}
	var projected strings.Builder
	start, open := 0, false
	for at := 0; at < len(source); {
		_, size := utf8.DecodeRuneInString(source[at:])
		raw := source[at : at+size]
		folded := raw
		if size != 1 || source[at] < 0x20 || source[at] == 0x7f {
			folded = normalize.ForCardText(raw)
		}
		if raw == folded {
			if !open {
				start = projected.Len()
				open = true
			}
		} else if open {
			proof.spans = append(proof.spans, textByteSpan{start, projected.Len()})
			open = false
		}
		projected.WriteString(folded)
		at += size
	}
	if open {
		proof.spans = append(proof.spans, textByteSpan{start, projected.Len()})
	}
	proof.valid = projected.String() == view
	return proof
}

func (p *cardLiteralProof) literal(c carddlp.Candidate) bool {
	if !p.valid || c.Start < 0 || c.End <= c.Start || c.End > p.length {
		return false
	}
	if p.unchanged {
		return true
	}
	if c.Start < p.lastStart {
		return false
	}
	p.lastStart = c.Start
	for p.cursor < len(p.spans) && p.spans[p.cursor].end <= c.Start {
		p.cursor++
	}
	return p.cursor < len(p.spans) && p.spans[p.cursor].start <= c.Start && c.End <= p.spans[p.cursor].end
}

// ApplyReceiptCardPolicy adds the strict plaintext floor without weakening
// any supplied detector finding. Decoded views use ScanTextForReceiptDLP.
func ApplyReceiptCardPolicy(text string, result TextDLPResult) TextDLPResult {
	for _, match := range result.Matches {
		if match.genericCard && !match.IsInformational() {
			return result
		}
	}
	if match, found := strictReceiptCardMatch(text, ""); found {
		result.Matches = append(result.Matches[:len(result.Matches):len(result.Matches)], match)
		result.Clean = false
	}
	return result
}

func strictReceiptCardMatch(text, encoding string) (TextDLPMatch, bool) {
	text = normalize.ForCardText(text)
	var candidate carddlp.Candidate
	found := carddlp.VisitStrict(text, func(c carddlp.Candidate) bool { candidate = c; return true })
	viewLabel := dlpViewLabel(encoding)
	if !found && json.Valid([]byte(text)) {
		for _, atom := range extract.AllStringsFromJSONResult(json.RawMessage(text)).Atoms {
			view := normalize.ForCardText(atom.Text)
			if carddlp.VisitStrict(view, func(c carddlp.Candidate) bool { candidate = c; return true }) {
				text = view
				found = true
				viewLabel = spanViewLabel("json_value", viewLabel)
				break
			}
		}
	}
	if !found {
		return TextDLPMatch{}, false
	}
	const pattern = "Credit Card Number"
	return TextDLPMatch{
		genericCard: true, cardPrefixRetry: true, PatternName: pattern, Severity: config.SeverityHigh, CardConfidence: "high", Encoded: encoding,
		valueIdentity: sha256.Sum256([]byte(text[candidate.Start:candidate.End])), hasValueIdentity: true,
		span: newMatchSpan(candidate.Start, candidate.End, viewLabel, pattern, "", ""),
	}, true
}
