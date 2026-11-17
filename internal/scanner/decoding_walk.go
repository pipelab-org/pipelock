// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"slices"
	"strings"
)

type outboundDecodePause struct{ state *outboundDecodeState }

type outboundDecodeOptions struct {
	includeURL bool
	minPrefix  int
	withHTML   bool
	sources    *keywordDecodeSources
	pause      *outboundDecodePause
}

type outboundDecodeState struct {
	out                        []decodedResult
	queue                      []string
	seen                       *decodeSeen
	opts                       outboundDecodeOptions
	consumed, limit, freeRoots int
	complete                   bool
	scratch                    [16]decodedResult
	views                      []decodedResult
	head, next                 int
	loaded, charged            bool
}

func newOutboundDecodeState(out []decodedResult, queue []string, seen *decodeSeen, opts outboundDecodeOptions) outboundDecodeState {
	return outboundDecodeState{out: out, queue: queue, seen: seen, opts: opts, limit: maxDecodeCandidates, freeRoots: len(queue), complete: true}
}

func (s *outboundDecodeState) admit(d decodedResult) bool {
	if len(d.text) < max(s.opts.minPrefix, 1) || s.seen.has(d.text) {
		return true
	}
	if len(s.out) >= s.limit {
		return false
	}
	s.seen.add(d.text)
	s.out = append(s.out, d)
	s.queue = append(s.queue, d.text)
	return true
}

// run retains its exact queue, sibling and parent charge at a candidate stop.
// Byte exhaustion cannot be resumed and never receives another allowance.
func (s *outboundDecodeState) run() ([]decodedResult, bool, bool) {
	for s.head < len(s.queue) {
		if !s.loaded {
			if s.views == nil {
				s.views = s.scratch[:0]
			}
			var stepComplete bool
			s.views, stepComplete = decodeEncodingsOnceInto(s.views[:0], s.queue[s.head], s.opts.includeURL, s.opts.minPrefix, s.opts.withHTML)
			s.complete = s.complete && stepComplete
			s.charged, s.loaded, s.next = s.head < s.freeRoots, true, 0
		}
		for s.next < len(s.views) {
			d := s.views[s.next]
			if s.opts.sources != nil {
				d.source = s.opts.sources.add(s.queue[s.head], d.text, d.encoding)
			}
			if len(d.text) < max(s.opts.minPrefix, 1) || s.seen.has(d.text) {
				s.next++
				continue
			}
			if !s.charged {
				if len(s.queue[s.head]) > maxDecodeTotalBytes-s.consumed {
					return s.out, false, false
				}
				s.consumed += len(s.queue[s.head])
				s.charged = true
			}
			if !s.admit(d) {
				return s.out, false, true
			}
			s.next++
		}
		s.head++
		s.loaded = false
	}
	return s.out, s.complete, false
}

func (s *outboundDecodeState) resume(prefix []decodedResult, credit int) ([]decodedResult, bool) {
	s.out = prefix
	s.limit = len(prefix) + max(0, min(credit, maxDecodeCandidates))
	out, complete, _ := s.run()
	return out, complete
}

// Only known-secret walks with paired candidate credit retain paused state.
func decodeOutboundWalk(out []decodedResult, queue []string, start []decodedResult, seen *decodeSeen, opts outboundDecodeOptions) ([]decodedResult, bool) {
	consumed := 0
	freeRoots := len(queue)
	complete := true
	admit := func(d decodedResult) bool {
		if len(d.text) < max(opts.minPrefix, 1) {
			return true
		}
		if seen.has(d.text) {
			return true
		}
		if len(out) >= maxDecodeCandidates {
			return false
		}
		seen.add(d.text)
		out = append(out, d)
		queue = append(queue, d.text)
		return true
	}
	for _, d := range start {
		if !admit(d) {
			return out, false
		}
	}
	var scratch [16]decodedResult
	views := scratch[:0]
	for head := 0; head < len(queue); head++ {
		var stepComplete bool
		views, stepComplete = decodeEncodingsOnceInto(views[:0], queue[head], opts.includeURL, opts.minPrefix, opts.withHTML)
		complete = complete && stepComplete
		charged := head < freeRoots
		for next, d := range views {
			if opts.sources != nil {
				d.source = opts.sources.add(queue[head], d.text, d.encoding)
			}
			if len(d.text) < max(opts.minPrefix, 1) {
				continue
			}
			if seen.has(d.text) {
				continue
			}
			if !charged {
				if len(queue[head]) > maxDecodeTotalBytes-consumed {
					return out, false
				}
				consumed += len(queue[head])
				charged = true
			}
			if !admit(d) {
				if opts.pause != nil {
					seenCopy := *seen
					// Copy stack-backed storage only at a real candidate stop.
					// HTML/tag phases may extend the original graph before resume.
					opts.pause.state = &outboundDecodeState{
						out: slices.Clone(out), queue: slices.Clone(queue), seen: &seenCopy,
						opts:     outboundDecodeOptions{includeURL: opts.includeURL, minPrefix: opts.minPrefix, withHTML: opts.withHTML, sources: opts.sources},
						consumed: consumed, limit: maxDecodeCandidates, freeRoots: freeRoots, complete: complete,
						views: slices.Clone(views), head: head, next: next, loaded: true, charged: charged,
					}
				}
				return out, false
			}
		}
	}
	return out, complete
}

// The original HTML/tag phases have already spent their own allowances. A
// resumed first walk may complete only when those phases are still closed;
// discovering work they did not inspect remains an incomplete scan.
func resumedDecodePhasesClosed(tail []decodedResult, seen *decodeSeen) bool {
	for _, view := range tail {
		if view.encoding == encodingUnicodeTags {
			return false
		}
		if strings.IndexByte(view.text, '&') < 0 {
			continue
		}
		decoded, complete := decodeHTMLEntitiesChecked(view.text)
		if !complete || decoded != "" && decoded != view.text && !seen.has(decoded) {
			return false
		}
	}
	return true
}

// decodeKnownEncodingsForScan owns the state that can survive the first walk.
// The ordinary decoder does not pass stack-backed bookkeeping to this path.
func decodeKnownEncodingsForScan(text string, includeURL bool, minPrefix int, mode decodeBudgetMode) ([]decodedResult, bool) {
	var seen decodeSeen
	seen.add(text)
	var queue [8]string
	var views [32]decodedResult
	var pause outboundDecodePause
	collected, complete := decodeOutboundWalk(views[:0], append(queue[:0], text), nil, &seen, outboundDecodeOptions{includeURL: includeURL, minPrefix: minPrefix, pause: &pause})
	collected, phasesComplete := finishDecodePhases(text, collected, &seen, decodePhaseOptions{includeURL: includeURL, minPrefix: minPrefix, mode: mode})
	complete = complete && phasesComplete
	if pause.state != nil && phasesComplete {
		*pause.state.seen = seen
		before := len(collected)
		collected, complete = pause.state.resume(collected, min(mode.knownCredit, maxDecodeCandidates))
		if mode.knownResumed != nil {
			*mode.knownResumed = true
		}
		complete = complete && resumedDecodePhasesClosed(collected[before:], &seen)
	}
	if len(collected) == 0 {
		return nil, complete
	}
	return slices.Clone(collected), complete
}
