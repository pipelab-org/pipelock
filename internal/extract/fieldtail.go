// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package extract

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"
)

// Field tail bounds. A stream retains at most its path budget
// (FieldTailMaxPaths unless the caller sets one, never more than
// FieldTailMaxPathsLimit) with at most FieldTailBytes each, plus the
// digests of at most twice that many evicted paths, so the state per stream
// stays bounded regardless of what the peer sends. A frame is partitioned
// into at most FieldTailFrameMaxLeaves scalar leaves; a wider frame keeps
// the leaves that fit and marks the stream lossy.
const (
	FieldTailBytes          = 512
	FieldTailMaxPaths       = 128
	FieldTailMaxPathsLimit  = 4096
	FieldTailFrameMaxLeaves = 1024
)

var fieldTailLeafLimits = JSONLeafLimits{
	MaxDepth:     DefaultJSONLeafMaxDepth,
	MaxStreams:   FieldTailFrameMaxLeaves,
	MaxPathBytes: DefaultJSONLeafMaxPathBytes,
}

// FieldTailFrame is one message or event partitioned into JSON string
// leaves. OK is false when the frame is not a valid JSON document; callers
// then rely on their raw cross-message tail alone. Overflow marks a valid
// JSON document with more leaves than FieldTailFrameMaxLeaves: only the
// leaves that fit are joined, see Incomplete.
//
// Only string leaves are kept. Numbers and booleans are never concatenated
// by a client reassembling a stream, and joining them (token ids, byte
// arrays, sequence numbers) only adds unrelated digit runs.
//
// Paths are keyed the way clients reassemble streamed values: an array
// element object carrying a numeric "index" member (OpenAI choices and
// tool_calls, Anthropic content blocks) is keyed by that index instead of
// its array position, and the text-bearing members of a streamed delta
// (content, reasoning_content, reasoning, refusal) share one tail.
type FieldTailFrame struct {
	OK       bool
	Overflow bool
	paths    []string
	values   map[string][]byte
}

// ParseFieldTailFrame partitions raw with JSONLeafPayloads, the same leaf
// identity cross-request detection uses for request bodies, into at most
// FieldTailFrameMaxLeaves leaves.
func ParseFieldTailFrame(raw []byte) FieldTailFrame {
	return parseFieldTailFrame(raw, FieldTailFrameMaxLeaves)
}

// ParseFrame is ParseFieldTailFrame with a leaf limit scaled to t's path
// budget: at least FieldTailFrameMaxLeaves and at least twice the budget.
func (t *FieldTails) ParseFrame(raw []byte) FieldTailFrame {
	maxLeaves := FieldTailFrameMaxLeaves
	if t != nil {
		maxLeaves = max(maxLeaves, 2*t.maxPaths)
	}
	return parseFieldTailFrame(raw, maxLeaves)
}

func parseFieldTailFrame(raw []byte, maxLeaves int) FieldTailFrame {
	limits := fieldTailLeafLimits
	limits.MaxStreams = maxLeaves
	payloads, complete := JSONLeafPayloads(json.RawMessage(raw), limits)
	overflow := false
	if !complete {
		// A valid document that still failed to partition hit a limit: keep
		// the leaves that fit. An empty or malformed one has nothing to join.
		partial, valid := JSONLeafPayloadsPartial(json.RawMessage(raw), limits)
		if !valid || len(partial) == 0 {
			return FieldTailFrame{}
		}
		payloads, overflow = partial, true
	}
	textPaths := jsonStringLeafPaths(raw, limits)
	values := make(map[string][]byte)
	sources := make([]string, 0, len(payloads))
	for path := range payloads {
		sources = append(sources, path)
	}
	sort.Strings(sources)
	for _, path := range sources {
		if textPaths != nil {
			if _, ok := textPaths[path]; !ok {
				continue
			}
		}
		key := fieldTailKey(path, payloads)
		values[key] = append(values[key], payloads[path]...)
	}
	paths := make([]string, 0, len(values))
	for path := range values {
		paths = append(paths, path)
	}
	sort.Strings(paths)
	return FieldTailFrame{OK: true, Overflow: overflow, paths: paths, values: values}
}

// fieldTailTextMembers are the members of a streamed delta whose text a
// client renders as one continuing reply.
var fieldTailTextMembers = map[string]bool{
	"content": true, "reasoning_content": true, "reasoning": true, "refusal": true,
}

// fieldTailIndexedArrays are the arrays whose elements providers stream
// one at a time with an "index" member naming the element (OpenAI choices
// and tool_calls, content block arrays). Only elements of these arrays are
// keyed by index; an "index" member anywhere else is ordinary data.
var fieldTailIndexedArrays = map[string]bool{
	"choices": true, "tool_calls": true, "content": true,
}

// fieldTailKey rewrites a leaf path into its reassembly key. "~" followed by
// a letter cannot come from JSONLeafPayloads' segment escaping (~0, ~1), so
// rewritten segments never collide with a literal key.
func fieldTailKey(path string, payloads map[string][]byte) string {
	if strings.HasPrefix(path, "$#") {
		return path
	}
	segments := strings.Split(path, "/")
	out := make([]string, 0, len(segments)+1)
	prefix := segments[0]
	out = append(out, segments[0])
	for i := 1; i < len(segments); i++ {
		seg := segments[i]
		prefix += "/" + seg
		if i < len(segments)-1 {
			if fieldTailIndexedArrays[segments[i-1]] && isDecimal(seg) {
				if idx, ok := fieldTailIndex(payloads[prefix+"/index"]); ok {
					seg = "~i" + idx
				}
			}
		} else if i > 1 && segments[i-1] == "delta" && fieldTailTextMembers[seg] {
			seg = "~t"
		}
		out = append(out, seg)
	}
	return strings.Join(out, "/")
}

func fieldTailIndex(value []byte) (string, bool) {
	if len(value) == 0 || len(value) > 9 || !isDecimal(string(value)) {
		return "", false
	}
	return string(value), true
}

func isDecimal(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

// jsonStringLeafPaths returns the leaf paths of raw that hold a string,
// built exactly as JSONLeafPayloadsPartial builds them. It returns nil
// (treat every leaf as text) when raw is invalid or has more string paths
// than four times the leaf limit.
func jsonStringLeafPaths(raw []byte, limits JSONLeafLimits) map[string]struct{} {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	out := make(map[string]struct{})
	if !walkJSONStringLeaves(decoder, out, []byte("$"), 0, limits) || len(out) > 4*limits.MaxStreams {
		return nil
	}
	return out
}

func walkJSONStringLeaves(decoder *json.Decoder, out map[string]struct{}, path []byte, depth int, limits JSONLeafLimits) bool {
	if depth > limits.MaxDepth {
		return skipJSONValue(decoder)
	}
	token, err := decoder.Token()
	if err != nil {
		return false
	}
	switch value := token.(type) {
	case json.Delim:
		switch value {
		case '{':
			for decoder.More() {
				key, err := decoder.Token()
				if err != nil {
					return false
				}
				keyString, ok := key.(string)
				if !ok {
					return false
				}
				if !walkJSONStringLeaves(decoder, out, appendJSONLeafPathPartPartial(path, keyString, limits.MaxPathBytes), depth+1, limits) {
					return false
				}
			}
		case '[':
			for index := 0; decoder.More(); index++ {
				if !walkJSONStringLeaves(decoder, out, appendJSONLeafPathPartPartial(path, strconv.Itoa(index), limits.MaxPathBytes), depth+1, limits) {
					return false
				}
			}
		default:
			return false
		}
		_, err := decoder.Token()
		return err == nil
	case string:
		if len(out) <= 4*limits.MaxStreams {
			out[string(path)] = struct{}{}
		}
	}
	return true
}

// FieldTails keeps the trailing bytes of every JSON string leaf path seen
// on one stream, so a value a peer splits across frames is scanned the way
// the receiving client reassembles it: each field joined only with its own
// earlier content. Concatenating whole frames instead puts the closing
// syntax of one frame and the envelope of the next (or, for a sorted
// key/value walk, the field name) between the two halves, and no pattern
// can match across that.
//
// A value identical to the previous value on the same path is not appended:
// envelope fields such as ids and model names repeat on every frame and
// would otherwise grow into a tail that only adds false positives.
//
// When the path budget is exhausted a path is evicted, preferring the least
// recently seen path that is not a streamed text member, and its last
// value is remembered. A different later value on an evicted path, a new
// path after the eviction record or a frame overflowed, or an overflowing
// frame while content is retained make Incomplete report true, so the
// caller fails closed instead of scanning a value without the content it
// continues. The zero value is not usable; call NewFieldTails.
type FieldTails struct {
	separator string
	maxPaths  int
	tails     map[string]*fieldTail
	evicted   map[[sha256.Size]byte][sha256.Size]byte
	saturated bool
	clock     uint64
	// stream is the stream-level text tail: every frame's text-bearing
	// leaves joined in arrival order regardless of path, so a value whose
	// array index or text member changes between frames is still joined.
	stream     string
	streamLast [sha256.Size]byte
}

type fieldTail struct {
	text     string
	last     [sha256.Size]byte
	seen     uint64
	priority bool
}

// NewFieldTails returns an empty tail set with the default path budget.
// separator is inserted between a retained tail and the next value; ""
// joins a field exactly the way a client appending streamed deltas does.
func NewFieldTails(separator string) *FieldTails {
	return NewFieldTailsWithLimit(separator, FieldTailMaxPaths)
}

// NewFieldTailsWithLimit is NewFieldTails with a path budget. A budget of
// zero or less selects FieldTailMaxPaths; larger budgets are clamped to
// FieldTailMaxPathsLimit.
func NewFieldTailsWithLimit(separator string, maxPaths int) *FieldTails {
	if maxPaths <= 0 {
		maxPaths = FieldTailMaxPaths
	}
	maxPaths = min(maxPaths, FieldTailMaxPathsLimit)
	return &FieldTails{
		separator: separator,
		maxPaths:  maxPaths,
		tails:     make(map[string]*fieldTail),
		evicted:   make(map[[sha256.Size]byte][sha256.Size]byte),
	}
}

func (t *FieldTails) evictedMax() int { return 2 * t.maxPaths }

// FieldTailView is one value of the current frame and the bytes retained
// before it on the same field. Joined is the text a cross-frame scan
// inspects.
type FieldTailView struct {
	Tail   string
	Value  string
	Joined string
}

// Views returns what to scan for frame: for every leaf whose value changed
// and whose path retains earlier content, that content followed by the
// value. A leaf without retained bytes adds no view, since the caller's
// per-frame scan already covers the value alone.
func (t *FieldTails) Views(frame FieldTailFrame) []FieldTailView {
	if t == nil || !frame.OK {
		return nil
	}
	var views []FieldTailView
	for _, path := range frame.paths {
		value := frame.values[path]
		if len(value) == 0 {
			continue
		}
		state := t.tails[path]
		if state == nil || state.text == "" || state.last == sha256.Sum256(value) {
			continue
		}
		views = append(views, FieldTailView{Tail: state.text, Value: string(value), Joined: state.text + t.separator + string(value)})
	}
	if text := t.streamText(frame); text != "" && t.stream != "" && t.streamLast != sha256.Sum256([]byte(text)) {
		stream := FieldTailView{Tail: t.stream, Value: text, Joined: t.stream + t.separator + text}
		duplicate := false
		for _, view := range views {
			duplicate = duplicate || view.Joined == stream.Joined
		}
		if !duplicate {
			views = append(views, stream)
		}
	}
	return views
}

// Incomplete reports that frame cannot be joined with the content this
// stream retained: it overflowed the leaf limit while content is retained,
// it carries a changed value on a path whose content was evicted, or it
// adds a path after the stream lost track of which paths it dropped.
// Callers must treat that as a failed cross-frame inspection rather than
// forward the frame on the strength of the raw tail alone, which cannot see
// across the JSON envelope.
func (t *FieldTails) Incomplete(frame FieldTailFrame) bool {
	if t == nil || !frame.OK {
		return false
	}
	if frame.Overflow {
		if t.saturated || len(t.evicted) > 0 {
			return true
		}
		for _, state := range t.tails {
			if state.text != "" {
				return true
			}
		}
	}
	if !t.saturated && len(t.evicted) == 0 {
		return false
	}
	for _, path := range frame.paths {
		value := frame.values[path]
		if len(value) == 0 || t.tails[path] != nil {
			continue
		}
		if t.saturated {
			return true
		}
		if last, ok := t.evicted[sha256.Sum256([]byte(path))]; ok && last != sha256.Sum256(value) {
			return true
		}
	}
	return false
}

// Advance records frame's changed values into their path tails. reset drops
// every retained byte and eviction record first (the caller reported a
// finding and must not report the same bytes again), while still
// remembering the current values so repeated envelope fields stay out of the
// next tail. An overflowing frame is recorded as far as it was partitioned
// and marks the stream lossy, since its dropped leaves are unknown.
func (t *FieldTails) Advance(frame FieldTailFrame, reset bool) {
	if t == nil {
		return
	}
	if reset {
		for _, state := range t.tails {
			state.text = ""
		}
		clear(t.evicted)
		t.saturated = false
		t.stream = ""
	}
	if !frame.OK {
		return
	}
	if text := t.streamText(frame); text != "" {
		if sum := sha256.Sum256([]byte(text)); sum != t.streamLast {
			t.streamLast = sum
			if !reset {
				t.stream = rollFieldTail(t.stream, text, t.separator)
			}
		}
	}
	if frame.Overflow && !reset {
		t.saturated = true
		clear(t.evicted)
	}
	t.clock++
	for _, path := range frame.paths {
		value := frame.values[path]
		if len(value) == 0 {
			continue
		}
		sum := sha256.Sum256(value)
		state := t.tails[path]
		if state == nil {
			t.evictFor()
			state = &fieldTail{priority: fieldTailPriority(path)}
			t.tails[path] = state
			delete(t.evicted, sha256.Sum256([]byte(path)))
		}
		state.seen = t.clock
		if state.last == sum {
			continue
		}
		state.last = sum
		if reset {
			continue
		}
		state.text = rollFieldTail(state.text, string(value), t.separator)
	}
}

// streamText is the input of the stream-level text tail for frame: in path
// order, every text-bearing member, plus every other string member of an
// index-keyed element (choices, tool_calls, content) whose value changed
// since the last frame, so repeated envelope values stay out. It keeps the
// last FieldTailBytes, where a value continued by the next frame ends. It
// must run before Advance records frame.
func (t *FieldTails) streamText(frame FieldTailFrame) string {
	var text strings.Builder
	for _, path := range frame.paths {
		value := frame.values[path]
		if len(value) == 0 {
			continue
		}
		if !fieldTailPriority(path) {
			if !strings.Contains(path, "/~i") {
				continue
			}
			if state := t.tails[path]; state != nil && state.last == sha256.Sum256(value) {
				continue
			}
		}
		text.Write(value)
	}
	return rollFieldTail("", text.String(), "")
}

// fieldTailPriority reports whether path is a member that streams carry
// running text in, which eviction keeps as long as any other path remains.
func fieldTailPriority(path string) bool {
	last := path[strings.LastIndexByte(path, '/')+1:]
	switch last {
	case "~t", "text", "arguments", "partial_json", "delta", "thinking", "input", "output":
		return true
	}
	return false
}

// evictFor makes room for one more path by dropping the least recently
// seen path, non-priority paths first. A path that still held content is
// remembered with its last value so a changed return is reported by
// Incomplete.
func (t *FieldTails) evictFor() {
	if len(t.tails) < t.maxPaths {
		return
	}
	var oldest string
	var oldestState *fieldTail
	for path, state := range t.tails {
		if oldestState == nil || fieldTailEvictsBefore(path, state, oldest, oldestState) {
			oldest, oldestState = path, state
		}
	}
	if oldestState.text != "" && !t.saturated {
		if len(t.evicted) >= t.evictedMax() {
			t.saturated = true
			clear(t.evicted)
		} else {
			t.evicted[sha256.Sum256([]byte(oldest))] = oldestState.last
		}
	}
	delete(t.tails, oldest)
}

func fieldTailEvictsBefore(path string, state *fieldTail, otherPath string, other *fieldTail) bool {
	if state.priority != other.priority {
		return !state.priority
	}
	if state.seen != other.seen {
		return state.seen < other.seen
	}
	return path < otherPath
}

func rollFieldTail(tail, value, separator string) string {
	combined := value
	if tail != "" {
		combined = tail + separator + value
	}
	if len(combined) > FieldTailBytes {
		start := len(combined) - FieldTailBytes
		for start < len(combined) && !utf8.RuneStart(combined[start]) {
			start++
		}
		combined = combined[start:]
	}
	return combined
}
