// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package reqpolicy

import (
	"regexp"
	"strings"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/jsonscan"
)

// discOutcome is the result of evaluating a discriminator predicate against a
// parsed JSON body. It is intentionally three-valued: a present-but-unmatched
// string and an absent field are both "no match" (the allow-by-default rail
// forwards), but a present-but-non-string value - or a non-object body - is
// opaque so the caller can fail closed per on_opaque_operation rather than let
// a type the upstream might still dispatch on slip through unmatched.
type discOutcome uint8

const (
	discNoMatch discOutcome = iota
	discMatch
	discOpaque
)

// discPredicate is the compiled form of a rule's JSON discriminator predicate:
// a top-level object key and the RE2 patterns its string value must match.
type discPredicate struct {
	field    string
	valueRes []*regexp.Regexp
}

type exactException struct {
	field    string
	values   map[string]struct{}
	requests map[exactRequestKey]time.Time
}

type exactRequestKey struct {
	url    string
	method string
	digest string
}

func compileExactException(e *config.RequestPolicyException) *exactException {
	if e == nil {
		return nil
	}
	x := &exactException{field: strings.TrimSpace(e.Field), values: make(map[string]struct{}, len(e.Values))}
	if len(e.Requests) > 0 {
		x.requests = make(map[exactRequestKey]time.Time, len(e.Requests))
		for _, request := range e.Requests {
			expires, err := time.Parse(time.RFC3339, request.ExpiresAt)
			if err != nil {
				continue
			} // NewMatcher rejects invalid configuration.
			canonical, ok := config.CanonicalExactRequestURL(request.URL)
			if !ok {
				continue
			}
			key := exactRequestKey{url: canonical, method: request.Method, digest: request.BodySHA256}
			if previous, ok := x.requests[key]; !ok || expires.After(previous) {
				x.requests[key] = expires
			}
		}
	}
	for _, value := range e.Values {
		x.values[value] = struct{}{}
	}
	return x
}

// matches returns true only when the inspected body proves an exact exception.
// A missing, duplicate, non-string, or unparsed field leaves the block active.
func (e *exactException) matches(meta RequestMeta) bool {
	if !meta.JSONBodyParsed {
		return false
	}
	if len(e.requests) > 0 {
		if meta.ExactURL == "" || meta.JSONBodySHA256 == "" {
			return false
		}
		expires, ok := e.requests[exactRequestKey{url: meta.ExactURL, method: meta.Method, digest: meta.JSONBodySHA256}]
		return ok && time.Now().Before(expires)
	}
	obj, ok := meta.JSONBody.(map[string]any)
	if !ok {
		return false
	}
	if _, duplicated := meta.JSONDupKeys[e.field]; duplicated || jsonscan.HasKeyAlias(obj, e.field) {
		return false
	}
	value, ok := obj[e.field].(string)
	if !ok {
		return false
	}
	_, ok = e.values[value]
	return ok
}

// compileDiscriminatorPredicate compiles a rule's discriminator predicate,
// returning nil when the rule has none. Field and patterns are validated at
// config load, so a compile failure here is defense in depth.
func compileDiscriminatorPredicate(d *config.RequestPolicyDiscriminator) (*discPredicate, error) {
	if d == nil {
		return nil, nil
	}
	p := &discPredicate{field: strings.TrimSpace(d.Field)}
	for _, pat := range d.ValuePatterns {
		re, err := regexp.Compile(strings.TrimSpace(pat))
		if err != nil {
			return nil, err
		}
		p.valueRes = append(p.valueRes, re)
	}
	return p, nil
}

// eval classifies the request body against the predicate. It is evaluated only
// when meta.JSONBodyParsed is true; the not-read and invalid-JSON cases are the
// caller's fail-closed responsibility (on_opaque_operation / on_parse_error),
// so an unparsed body is reported as no match here and handled there.
func (d *discPredicate) eval(meta RequestMeta) discOutcome {
	if !meta.JSONBodyParsed {
		return discNoMatch
	}
	obj, ok := meta.JSONBody.(map[string]any)
	if !ok {
		// Valid JSON but a non-object top level (array, scalar): the targeted
		// field cannot exist, yet the upstream may still dispatch on the body,
		// so treat it as opaque rather than a benign no-match.
		return discOpaque
	}
	if _, dup := meta.JSONDupKeys[d.field]; dup || jsonscan.HasKeyAlias(obj, d.field) {
		// The targeted field appears more than once at the top level. Go keeps
		// the last value, but a first-wins upstream could dispatch on a
		// different one, so we cannot trust the collapsed value: fail closed.
		return discOpaque
	}
	v, present := obj[d.field]
	if !present {
		return discNoMatch
	}
	s, ok := v.(string)
	if !ok {
		// Present but null / number / bool / array / object: unclassifiable
		// against string value patterns. Fail closed via opaque.
		return discOpaque
	}
	for _, re := range d.valueRes {
		if re.MatchString(s) {
			return discMatch
		}
	}
	return discNoMatch
}
