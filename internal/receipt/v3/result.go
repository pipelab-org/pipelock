// Copyright 2026 Pipelab
// SPDX-License-Identifier: Apache-2.0

package v3

import (
	"bytes"
	"cmp"
	"encoding/json"
	"fmt"
	"slices"
	"strings"
)

type Position struct {
	Record string `json:"record"`
	Seq    int64  `json:"seq"`
}

type Finding struct {
	Class  string `json:"class"`
	Code   string `json:"code"`
	Record string `json:"record,omitempty"`
	Seq    *int64 `json:"seq,omitempty"`
	Stream string `json:"stream,omitempty"`
}

type StreamResult struct {
	End             string    `json:"end"`
	Last            *Position `json:"last,omitempty"`
	Previous        string    `json:"previous,omitempty"`
	Records         int64     `json:"records"`
	Signer          string    `json:"signer"`
	Stream          string    `json:"stream"`
	Tip             *Position `json:"tip,omitempty"`
	UnconfirmedFrom *int64    `json:"unconfirmed_from,omitempty"`
}

type HistoryResult struct {
	Lineage string         `json:"lineage"`
	Streams []StreamResult `json:"streams"`
}

type ContestedStream struct {
	Records []string `json:"records"`
	Stream  string   `json:"stream"`
}

type TrustResult struct {
	Keys []string `json:"keys"`
	Mode string   `json:"mode"`
}

type Acceptance struct {
	Kind  string `json:"kind"`
	Value string `json:"value"`
}

type StateCount struct {
	Count int64  `json:"count"`
	State string `json:"state"`
}

type KindCount struct {
	Count int64  `json:"count"`
	Kind  string `json:"kind"`
}

type Counts struct {
	Complete         *bool         `json:"complete,omitempty"`
	Decisions        *[]StateCount `json:"decisions,omitempty"`
	EffectsCompleted *int64        `json:"effects_completed,omitempty"`
	EffectsUnknown   *int64        `json:"effects_unknown,omitempty"`
	Scope            string        `json:"scope"`
	Uninterpreted    *[]KindCount  `json:"uninterpreted,omitempty"`
}

type LegacyResult struct {
	Chain   string `json:"chain"`
	Format  string `json:"format"`
	Verdict string `json:"verdict"`
}

// Result is the version 1 verification document.
type Result struct {
	Accepted         []Acceptance      `json:"accepted"`
	Completeness     string            `json:"completeness"`
	ContestedStreams []ContestedStream `json:"contested_streams"`
	Counts           Counts            `json:"counts"`
	ExitCode         int               `json:"exit_code"`
	Findings         []Finding         `json:"findings"`
	Histories        []HistoryResult   `json:"histories"`
	IgnoredFiles     int               `json:"ignored_files"`
	Integrity        string            `json:"integrity"`
	Kind             string            `json:"kind"`
	Legacy           []LegacyResult    `json:"legacy"`
	Limits           []string          `json:"limits"`
	Trust            TrustResult       `json:"trust"`
	TrustState       string            `json:"trust_state"`
	V                int               `json:"v"`
	Verdict          string            `json:"verdict"`
}

const (
	invalid       = "invalid"
	unsupported   = "unsupported"
	incomplete    = "incomplete"
	endUnproven   = "end_unproven"
	prefixVerdict = "VALID PREFIX, END UNPROVEN"
	gapsVerdict   = "VALID, GAPS ACCEPTED"
)

func newResult(opts Options) Result {
	mode, trust := "pinned_keys", "pinned"
	if len(opts.Keys) == 0 {
		mode, trust = "unpinned", "unpinned"
	}
	return Result{
		Kind: "verify_result", V: 1, Accepted: []Acceptance{},
		ContestedStreams: []ContestedStream{}, Findings: []Finding{}, Histories: []HistoryResult{},
		Legacy: []LegacyResult{}, Limits: []string{"L-FSYNC-ERROR-REOPEN", "L-FSYNC-HONESTY"},
		Trust: TrustResult{Keys: []string{}, Mode: mode}, TrustState: trust,
	}
}

func compareFindings(a, b Finding) int {
	return cmp.Or(cmp.Compare(a.Code, b.Code), cmp.Compare(a.Stream, b.Stream),
		cmp.Compare(seqOrAbsent(a.Seq), seqOrAbsent(b.Seq)), cmp.Compare(a.Record, b.Record))
}

func seqOrAbsent(seq *int64) int64 {
	if seq == nil {
		return -1
	}
	return *seq
}

func (r Result) acceptedFinding(f Finding) bool {
	return slices.ContainsFunc(r.Accepted, func(a Acceptance) bool {
		return f.Code == codePredecessorNotPresented && a.Kind == "allow-partial-history" && a.Value == f.Stream ||
			(f.Code == codeEndUnproven || f.Code == codeLegacyEndUnproven) &&
				a.Kind == "accept-discontinuity" && a.Value == f.Record
	})
}

func (r *Result) finish(opts Options) {
	slices.Sort(r.Limits)
	slices.SortFunc(r.Findings, compareFindings)
	r.Findings = slices.CompactFunc(r.Findings, func(a, b Finding) bool { return compareFindings(a, b) == 0 })
	slices.SortFunc(r.Accepted, func(a, b Acceptance) int {
		return cmp.Or(cmp.Compare(a.Kind, b.Kind), cmp.Compare(a.Value, b.Value))
	})
	r.Accepted = slices.Compact(r.Accepted)
	classes := make(map[string]bool)
	for _, finding := range r.Findings {
		if !r.acceptedFinding(finding) {
			classes[finding.Class] = true
		}
	}
	r.Integrity, r.Completeness = "ok", "complete"
	if classes[invalid] {
		r.Integrity = "failed"
	}
	if classes[incomplete] {
		r.Completeness = "incomplete"
	} else if classes[endUnproven] {
		r.Completeness = "end_unproven"
	}
	if r.Counts.Scope == "full_history" {
		complete := !classes[invalid] && !classes[unsupported] && !classes[incomplete]
		r.Counts.Complete = &complete
	}
	switch {
	case classes[invalid]:
		r.Verdict, r.ExitCode = "INVALID", 1
	case classes[unsupported]:
		r.Verdict, r.ExitCode = "UNSUPPORTED", 3
	case classes[incomplete]:
		r.Verdict, r.ExitCode = "INCOMPLETE", 3
	default:
		switch {
		case classes[endUnproven]:
			r.Verdict = prefixVerdict
		case len(opts.Keys) == 0:
			r.Verdict = "SELF-CONSISTENT ONLY"
		case slices.ContainsFunc(r.Accepted, func(a Acceptance) bool {
			return a.Kind == "allow-partial-history" || a.Kind == "accept-discontinuity"
		}):
			r.Verdict = gapsVerdict
		default:
			r.Verdict = "VALID"
		}
		if classes[endUnproven] && !opts.AllowPrefix {
			r.ExitCode = 3
		} else if len(opts.Keys) == 0 && !opts.AllowUnpinned {
			r.ExitCode = 1
		}
	}
}

// JSON returns the canonical result document.
func (r Result) JSON() ([]byte, error) {
	return canonicalJSON(r)
}

// Projection returns the canonical subset compared by conformance vectors.
func (r Result) Projection() ([]byte, error) {
	deciding := map[string]string{"INVALID": invalid, "UNSUPPORTED": unsupported, "INCOMPLETE": incomplete, prefixVerdict: endUnproven}
	codes := []string{}
	for _, f := range r.Findings {
		if f.Class == deciding[r.Verdict] && !r.acceptedFinding(f) {
			codes = append(codes, f.Code)
		}
	}
	slices.Sort(codes)
	projection := map[string]any{
		"accepted": r.Accepted, "completeness": r.Completeness, "exit_code": r.ExitCode,
		"finding_codes": slices.Compact(codes), "integrity": r.Integrity, "trust": r.Trust,
		"trust_state": r.TrustState, "verdict": r.Verdict,
	}
	if r.Verdict != "INVALID" && r.Verdict != "UNSUPPORTED" && r.Verdict != "INCOMPLETE" {
		histories := make([]map[string]any, 0, len(r.Histories))
		for _, h := range r.Histories {
			streams := make([]map[string]any, 0, len(h.Streams))
			for _, s := range h.Streams {
				row := map[string]any{"end": s.End, "records": s.Records, "stream": s.Stream}
				if s.Previous != "" {
					row["previous"] = s.Previous
				}
				if s.Tip != nil {
					row["tip"] = s.Tip
				}
				streams = append(streams, row)
			}
			histories = append(histories, map[string]any{"lineage": h.Lineage, "streams": streams})
		}
		projection["histories"], projection["counts"] = histories, r.Counts
	}
	return canonicalJSON(projection)
}

// Result objects use fixed ASCII member names and integer values only. The
// conversion also allows typed structs to share the same ordering as maps.
func canonicalJSON(value any) ([]byte, error) {
	initial, err := json.Marshal(value)
	if err != nil {
		return nil, fmt.Errorf("marshal verification document: %w", err)
	}
	decoder := json.NewDecoder(bytes.NewReader(initial))
	decoder.UseNumber()
	var document any
	if err := decoder.Decode(&document); err != nil {
		return nil, fmt.Errorf("decode verification document: %w", err)
	}
	var out strings.Builder
	appendCanonical(&out, document)
	return []byte(out.String()), nil
}

func appendCanonical(out *strings.Builder, value any) {
	switch item := value.(type) {
	case string:
		appendJSONString(out, item)
	case json.Number:
		out.WriteString(item.String())
	case bool:
		if item {
			out.WriteString("true")
		} else {
			out.WriteString("false")
		}
	case []any:
		out.WriteByte('[')
		for i, member := range item {
			if i != 0 {
				out.WriteByte(',')
			}
			appendCanonical(out, member)
		}
		out.WriteByte(']')
	case map[string]any:
		out.WriteByte('{')
		keys := sortedKeys(item)
		for i, key := range keys {
			if i != 0 {
				out.WriteByte(',')
			}
			appendJSONString(out, key)
			out.WriteByte(':')
			appendCanonical(out, item[key])
		}
		out.WriteByte('}')
	}
}

func appendJSONString(out *strings.Builder, text string) {
	const controlHex = "0123456789abcdef"
	out.WriteByte('"')
	for _, chr := range text {
		switch chr {
		case '"', '\\':
			out.WriteByte('\\')
			out.WriteRune(chr)
		case '\b':
			out.WriteString("\\b")
		case '\t':
			out.WriteString("\\t")
		case '\n':
			out.WriteString("\\n")
		case '\f':
			out.WriteString("\\f")
		case '\r':
			out.WriteString("\\r")
		default:
			if chr < 0x20 {
				out.WriteString("\\u00")
				out.WriteByte(controlHex[chr>>4])
				out.WriteByte(controlHex[chr&15])
			} else {
				out.WriteRune(chr)
			}
		}
	}
	out.WriteByte('"')
}

func sortedKeys[V any](items map[string]V) []string {
	keys := make([]string, 0, len(items))
	for key := range items {
		keys = append(keys, key)
	}
	slices.Sort(keys)
	return keys
}
