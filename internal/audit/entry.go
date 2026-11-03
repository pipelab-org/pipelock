// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"reflect"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/envelope"
	"github.com/rs/zerolog"
	"golang.org/x/net/http2"
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

// redactURLErrors summarizes URL-bearing trees from typed fields only. Neither
// a wrapper nor a cause's free-form text is safe: either can echo request data.
// Non-URL errors retain their existing diagnostic text.
func redactURLErrors(err error) error {
	found, details, valid := collectURLErrors(err)
	if !valid {
		return errors.New("[redacted invalid error tree]")
	}
	if len(found) == 0 {
		return err
	}
	var destinations []string
	for _, ue := range found {
		op := auditURLOperation(ue.Op)
		destination := op + " " + strconv.Quote(dropURLContentSegments(ue.URL, false))
		if op == "parse" {
			destination += ": invalid URL"
		}
		destinations = append(destinations, destination)
	}
	if len(details) == 0 {
		details = append(details, "request failed")
	}
	return errors.New(strings.Join(destinations, "; ") + ": " + strings.Join(details, "; "))
}

// net/http uses these operations for the standard methods (net/http/client.go,
// urlErrorOp); net/url uses parse. Custom methods remain a fixed label.
func auditURLOperation(op string) string {
	switch op {
	case "Get", "Head", "Post", "Put", "Patch", "Delete", "Connect", "Options", "Trace", "parse":
		return op
	default:
		return "request"
	}
}

// auditErrorDetail reads the published net, tls, x509, io and http2 error fields,
// never their formatted messages, addresses, certificate names or cause text.
func auditErrorDetail(err error) string {
	//nolint:errorlint // Inspect only this node; errors.Is would walk descendants again.
	switch err {
	case context.Canceled:
		return "context canceled"
	case context.DeadlineExceeded:
		return "deadline exceeded"
	case io.EOF:
		return "EOF"
	case io.ErrUnexpectedEOF:
		return "unexpected EOF"
	case syscall.ECONNREFUSED:
		return "connection refused"
	case syscall.ECONNRESET:
		return "connection reset"
	case syscall.EPIPE:
		return "broken pipe"
	case syscall.ENETUNREACH:
		return "network unreachable"
	case syscall.EHOSTUNREACH:
		return "host unreachable"
	}
	//nolint:errorlint // Inspect direct typed fields, not recursively formatted errors.
	switch e := err.(type) {
	case *url.Error:
		return ""
	case *net.OpError:
		op := "network operation"
		switch e.Op {
		case "dial", "read", "write", "listen", "accept":
			op = e.Op
		}
		network := "network"
		switch e.Net {
		case "tcp", "tcp4", "tcp6", "udp", "udp4", "udp6", "unix", "unixgram", "unixpacket":
			network = e.Net
		}
		return op + " " + network + " failed"
	case *net.DNSError:
		switch {
		case e.IsTimeout:
			return "DNS timeout"
		case e.IsNotFound:
			return "DNS name not found"
		case e.IsTemporary:
			return "DNS temporary failure"
		default:
			return "DNS lookup failed"
		}
	case tls.RecordHeaderError:
		return "TLS record header error"
	case *tls.CertificateVerificationError:
		return "TLS certificate verification failed"
	case x509.UnknownAuthorityError:
		return "TLS unknown certificate authority"
	case x509.HostnameError:
		return "TLS certificate hostname mismatch"
	case x509.CertificateInvalidError:
		return "TLS certificate invalid"
	case x509.SystemRootsError:
		return "TLS system roots unavailable"
	case tls.AlertError:
		return fmt.Sprintf("TLS alert %d", uint8(e))
	case http2.StreamError:
		return fmt.Sprintf("HTTP/2 stream error code %d", uint32(e.Code))
	default:
		if timeout, ok := err.(interface{ Timeout() bool }); ok && timeout.Timeout() {
			return "timeout"
		}
		return ""
	}
}

// collectURLErrors walks direct children once. Calling errors.As at each node
// would recursively search descendants again, and wouldn't terminate on cycles.
// Active/done marks distinguish cycles from a shared errors.Join subtree.
func collectURLErrors(err error) ([]*url.Error, []string, bool) {
	type visit struct {
		err   error
		leave bool
	}
	stack := []visit{{err: err}}
	state := make(map[error]bool)
	var found []*url.Error
	var nodes []error
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
				return nil, nil, false
			}
		}
		canCompare := value.Comparable()
		// A value unequal to itself (a NaN field) can't be marked and found again.
		if canCompare && !sameError(node, node) {
			return nil, nil, false
		}
		if canCompare {
			if item.leave {
				state[node] = true
				continue
			}
			if done, seen := state[node]; seen {
				if !done {
					return nil, nil, false
				}
				continue
			}
			state[node] = false
			stack = append(stack, visit{err: node, leave: true})
		}
		nodes = append(nodes, node)
		//nolint:errorlint // Inspect this node only; errors.As recursively searches descendants.
		if ue, ok := node.(*url.Error); ok {
			found = append(found, ue)
		} else if alias, ok := node.(interface{ As(any) bool }); ok {
			var ue *url.Error
			if alias.As(&ue) {
				if ue == nil {
					return nil, nil, false
				}
				stack = append(stack, visit{err: ue})
			}
		}
		//nolint:errorlint // Visit direct children; errors.As recursively revisits descendants.
		switch wrapped := node.(type) {
		case interface{ Unwrap() []error }:
			// Non-comparable wrappers have no stable identity for cycle detection.
			if !canCompare {
				return nil, nil, false
			}
			for _, child := range wrapped.Unwrap() {
				stack = append(stack, visit{err: child})
			}
		case interface{ Unwrap() error }:
			if !canCompare {
				return nil, nil, false
			}
			stack = append(stack, visit{err: wrapped.Unwrap()})
		}
	}
	var details []string
	if len(found) > 0 {
		seenDetails := make(map[string]bool)
		for _, node := range nodes {
			if detail := auditErrorDetail(node); detail != "" && !seenDetails[detail] {
				details = append(details, detail)
				seenDetails[detail] = true
			}
		}
	}
	return found, details, true
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

// sameError reports whether a and b compare equal. The caller has checked that
// the dynamic type is comparable, so this can't panic.
func sameError(a, b error) bool { return a == b } //nolint:errorlint // Identity, not wrapping, is what the walk needs.
