// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"errors"
	"net/url"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/envelope"
	"github.com/rs/zerolog"
)

// logEntry builds zerolog event and emit fields in parallel, eliminating
// the double-build pattern across all Log* methods.
type logEntry struct {
	event  *zerolog.Event
	fields map[string]any
}

func newLogEntry(event *zerolog.Event, eventType EventType) *logEntry {
	return &logEntry{
		event:  event.Str("event", string(eventType)),
		fields: map[string]any{},
	}
}

// newLogEntryRaw creates a logEntry with a raw event name string.
func newLogEntryRaw(event *zerolog.Event, eventName string) *logEntry {
	return &logEntry{
		event:  event.Str("event", eventName),
		fields: map[string]any{},
	}
}

func (e *logEntry) str(key, value string) *logEntry {
	sanitized := sanitizeString(value)
	e.event = e.event.Str(key, sanitized)
	e.fields[key] = sanitized
	return e
}

// agentField emits the agent label together with its provenance grade. Use
// this instead of optStr("agent", ...) everywhere: an agent name without its
// grade is indistinguishable from a caller-controlled label once it reaches an
// external consumer, so the two must never be emitted separately. An unknown
// grade is written explicitly rather than omitted, so a consumer can tell
// "not graded" apart from "field absent".
func (e *logEntry) agentField(agent, auth string) *logEntry {
	if agent == "" {
		return e
	}
	if auth == "" {
		auth = string(envelope.ActorAuthUnknown)
	}
	return e.str("agent", agent).str("agent_auth", auth)
}

func (e *logEntry) optStr(key, value string) *logEntry {
	if value == "" {
		return e
	}
	return e.str(key, value)
}

func (e *logEntry) intField(key string, value int) *logEntry {
	e.event = e.event.Int(key, value)
	e.fields[key] = value
	return e
}

func (e *logEntry) int64Field(key string, value int64) *logEntry {
	e.event = e.event.Int64(key, value)
	e.fields[key] = value
	return e
}

func (e *logEntry) scoreField(value float64) *logEntry {
	const key = "score"
	e.event = e.event.Float64(key, value)
	e.fields[key] = value
	return e
}

// durMS adds a "duration_ms" duration field to both zerolog and emit.
// All duration fields in audit use the same key, so it is hardcoded to
// satisfy the unparam linter.
func (e *logEntry) durMS(value time.Duration) *logEntry {
	e.event = e.event.Dur("duration_ms", value)
	e.fields["duration_ms"] = value.Milliseconds()
	return e
}

// upstreamMS adds the "upstream_ms" wait for an intercepted request.
func (e *logEntry) upstreamMS(value time.Duration) *logEntry {
	e.event = e.event.Dur("upstream_ms", value)
	e.fields["upstream_ms"] = value.Milliseconds()
	return e
}

func (e *logEntry) boolField(key string, value bool) *logEntry {
	e.event = e.event.Bool(key, value)
	e.fields[key] = value
	return e
}

func (e *logEntry) strs(key string, values []string) *logEntry {
	sanitized := make([]string, len(values))
	for i, v := range values {
		sanitized[i] = sanitizeString(v)
	}
	e.event = e.event.Strs(key, sanitized)
	e.fields[key] = sanitized
	return e
}

func (e *logEntry) errField(err error) *logEntry {
	err = redactURLErrors(err)
	e.event = e.event.Err(err)
	errStr := ""
	if err != nil {
		errStr = sanitizeString(err.Error())
	}
	e.fields["error"] = errStr
	return e
}

// redactURLErrors applies the destination policy to typed URL errors. Parse
// reasons and malformed-redirect details can echo input outside the URL field.
func redactURLErrors(err error) error {
	found, valid := collectURLErrors(err)
	if !valid {
		return errors.New("[redacted invalid error tree]")
	}
	if len(found) == 0 {
		return err
	}
	// Longest first so a URL that is a prefix of another cannot leave a tail.
	sort.SliceStable(found, func(i, j int) bool { return len(found[i].URL) > len(found[j].URL) })
	msg := err.Error()
	for _, ue := range found {
		if ue.Err != nil {
			cause := ue.Err.Error()
			switch {
			case ue.Op == "parse":
				msg = strings.ReplaceAll(msg, cause, "invalid URL")
			case strings.HasPrefix(cause, "failed to parse Location header "):
				// net/http.Client formats the Location parse error with %v, not %w.
				// The URL and parse reason in this detail aren't in the error tree.
				msg = strings.ReplaceAll(msg, cause, "invalid redirect URL")
			}
		}
		if ue.URL != "" {
			destination := dropURLContentSegments(ue.URL, false)
			// url.Error uses %q; the raw URL won't match quotes or backslashes.
			msg = strings.ReplaceAll(msg, strconv.Quote(ue.URL), strconv.Quote(destination))
			msg = strings.ReplaceAll(msg, ue.URL, destination)
		}
	}
	return errors.New(msg)
}

// collectURLErrors walks direct children once. Calling errors.As at each node
// would recursively search descendants again, and wouldn't terminate on cycles.
// Active/done marks distinguish cycles from a shared errors.Join subtree.
func collectURLErrors(err error) ([]*url.Error, bool) {
	type visit struct {
		err   error
		leave bool
	}
	stack := []visit{{err: err}}
	state := make(map[error]bool)
	var found []*url.Error
	for len(stack) > 0 {
		item := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		node := item.err
		if node == nil {
			continue
		}
		value := reflect.ValueOf(node)
		switch value.Kind() {
		case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
			if value.IsNil() {
				return nil, false
			}
		}
		canCompare := value.Comparable()
		if canCompare {
			if item.leave {
				state[node] = true
				continue
			}
			if done, seen := state[node]; seen {
				if !done {
					return nil, false
				}
				continue
			}
			state[node] = false
			stack = append(stack, visit{err: node, leave: true})
		}
		//nolint:errorlint // Inspect this node only; errors.As recursively searches descendants.
		if ue, ok := node.(*url.Error); ok {
			found = append(found, ue)
		} else if alias, ok := node.(interface{ As(any) bool }); ok {
			var ue *url.Error
			if alias.As(&ue) {
				if ue == nil {
					return nil, false
				}
				stack = append(stack, visit{err: ue})
			}
		}
		//nolint:errorlint // Visit direct children; errors.As recursively revisits descendants.
		switch wrapped := node.(type) {
		case interface{ Unwrap() []error }:
			// Non-comparable wrappers have no stable identity for cycle detection.
			if !canCompare {
				return nil, false
			}
			for _, child := range wrapped.Unwrap() {
				stack = append(stack, visit{err: child})
			}
		case interface{ Unwrap() error }:
			if !canCompare {
				return nil, false
			}
			stack = append(stack, visit{err: wrapped.Unwrap()})
		}
	}
	return found, true
}

// bundleRulesField adds "bundle_rules" to both zerolog and emit. All
// Interface-typed audit fields use this key, so it is hardcoded to satisfy
// the unparam linter. Called as a statement (never chained) because it is
// always conditional on len(bundleRules) > 0.
//
// When the slice is the typed []BundleRuleHit form (the normal case), the
// primary hit's RuleID and BundleVersion are also emitted as scalar fields
// so emit-side consumers can read them without importing this package.
// The primary hit is selected DETERMINISTICALLY by lexicographic sort on
// RuleID, NOT by slice order, so the same detection produces the same
// externally visible rule_id across runs even if scanner iteration order
// changes upstream. Auditability depends on this property.
// See internal/emit/otlp_agent_threat.go.
func (e *logEntry) bundleRulesField(value any) {
	e.event = e.event.Interface("bundle_rules", value)
	e.fields["bundle_rules"] = value
	if hits, ok := value.([]BundleRuleHit); ok && len(hits) > 0 {
		primary := selectPrimaryBundleHit(hits)
		if primary.RuleID != "" {
			e.fields["primary_rule_id"] = primary.RuleID
		}
		if primary.BundleVersion != "" {
			e.fields["bundle_version"] = primary.BundleVersion
		}
	}
}

// selectPrimaryBundleHit returns the canonical primary BundleRuleHit
// for a multi-hit detection, using lexicographic sort on RuleID as the
// stable tie-breaker. Hits with empty RuleID are deprioritised so a
// well-formed hit wins over a malformed one. The input slice is not
// mutated.
//
// Selection is intentionally NOT based on slice order. Pipelock's
// scanner emits hits in pattern-iteration order, which is stable in
// practice but not part of any documented contract. Pinning the
// "primary" choice to a content-addressed criterion (RuleID) means
// the externally visible agent.threat.detection.rule_id stays stable
// regardless of upstream ordering changes.
func selectPrimaryBundleHit(hits []BundleRuleHit) BundleRuleHit {
	primary := hits[0]
	for _, h := range hits[1:] {
		// Empty-RuleID hits never win against a non-empty one.
		if primary.RuleID == "" && h.RuleID != "" {
			primary = h
			continue
		}
		if h.RuleID == "" {
			continue
		}
		if h.RuleID < primary.RuleID {
			primary = h
		}
	}
	return primary
}

// msg sends the zerolog message. Call this instead of e.event.Msg() to keep
// the logEntry API consistent.
func (e *logEntry) msg(text string) {
	e.event.Msg(text)
}
