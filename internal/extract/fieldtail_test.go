// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package extract

import (
	"strconv"
	"strings"
	"testing"
	"unicode/utf8"
)

func joinedViews(views []FieldTailView) []string {
	out := make([]string, 0, len(views))
	for _, v := range views {
		out = append(out, v.Joined)
	}
	return out
}

func TestFieldTailsJoinsEachFieldWithItsOwnHistory(t *testing.T) {
	t.Parallel()
	tails := NewFieldTails("")
	first := ParseFieldTailFrame([]byte(`{"id":"c1","delta":{"content":"abc"},"other":"x1"}`))
	if !first.OK {
		t.Fatal("first frame not partitioned")
	}
	if views := tails.Views(first); len(views) != 0 {
		t.Fatalf("first frame views = %q, want none", joinedViews(views))
	}
	tails.Advance(first, false)

	second := ParseFieldTailFrame([]byte(`{"id":"c1","delta":{"content":"def"},"other":"x2"}`))
	got := joinedViews(tails.Views(second))
	// Sorted by path; the stream-level text view equals the content view
	// and is not repeated; the repeated id adds nothing.
	want := []string{"abcdef", "x1x2"}
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Fatalf("views = %q, want %q", got, want)
	}
}

func TestFieldTailsSkipsRepeatedValues(t *testing.T) {
	t.Parallel()
	tails := NewFieldTails("")
	for i := range 5 {
		frame := ParseFieldTailFrame([]byte(`{"model":"m-1","n":` + strconv.Itoa(i) + `}`))
		for _, v := range tails.Views(frame) {
			if strings.Contains(v.Joined, "m-1") {
				t.Fatalf("repeated envelope value joined into a view: %q", v.Joined)
			}
		}
		tails.Advance(frame, false)
	}
}

func TestFieldTailsNonJSONAndResetKeepNoState(t *testing.T) {
	t.Parallel()
	tails := NewFieldTails("")
	for _, raw := range []string{"[DONE]", "plain text", `{"a":`, ""} {
		if frame := ParseFieldTailFrame([]byte(raw)); frame.OK || tails.Views(frame) != nil {
			t.Fatalf("non-JSON frame %q was partitioned", raw)
		}
	}
	tails.Advance(ParseFieldTailFrame([]byte(`{"t":"secret-half"}`)), false)
	tails.Advance(ParseFieldTailFrame([]byte(`{"t":"after"}`)), true)
	if views := tails.Views(ParseFieldTailFrame([]byte(`{"t":"next"}`))); len(views) != 0 {
		t.Fatalf("reset kept bytes: %q", joinedViews(views))
	}
}

func TestFieldTailsBoundedAndEvictedPathFailsClosed(t *testing.T) {
	t.Parallel()
	tails := NewFieldTails("")
	tails.Advance(ParseFieldTailFrame([]byte(`{"target":"first-half"}`)), false)
	// Push enough other paths through to evict "target".
	for i := range FieldTailMaxPaths + 4 {
		frame := ParseFieldTailFrame([]byte(`{"p` + strconv.Itoa(i) + `":"v"}`))
		if tails.Incomplete(frame) {
			t.Fatalf("new path %d reported incomplete", i)
		}
		tails.Advance(frame, false)
	}
	if len(tails.tails) > FieldTailMaxPaths {
		t.Fatalf("tracked paths = %d, want <= %d", len(tails.tails), FieldTailMaxPaths)
	}
	if !tails.Incomplete(ParseFieldTailFrame([]byte(`{"target":"second-half"}`))) {
		t.Fatal("value on an evicted path not reported incomplete")
	}
	if tails.Incomplete(ParseFieldTailFrame([]byte(`{"brand-new":"value"}`))) {
		t.Fatal("never-seen path reported incomplete")
	}
	if tails.Incomplete(ParseFieldTailFrame([]byte(`{"p70":"changed"}`))) {
		t.Fatal("tracked path reported incomplete")
	}

	long := strings.Repeat("é", FieldTailBytes)
	tails.Advance(ParseFieldTailFrame([]byte(`{"long":"`+long+`"}`)), false)
	for path, state := range tails.tails {
		if len(state.text) > FieldTailBytes || !utf8.ValidString(state.text) {
			t.Fatalf("tail %q not bounded on a rune boundary: len=%d", path, len(state.text))
		}
	}
}

func TestFieldTailsEvictionRecordIsBounded(t *testing.T) {
	t.Parallel()
	tails := NewFieldTails("")
	for i := range FieldTailMaxPaths + 2*FieldTailMaxPaths + 1 {
		tails.Advance(ParseFieldTailFrame([]byte(`{"p`+strconv.Itoa(i)+`":"v"}`)), false)
		if len(tails.evicted) > tails.evictedMax() {
			t.Fatalf("eviction record grew to %d", len(tails.evicted))
		}
	}
	if !tails.saturated {
		t.Fatal("eviction record did not saturate")
	}
	if !tails.Incomplete(ParseFieldTailFrame([]byte(`{"brand-new":"value"}`))) {
		t.Fatal("untracked path after saturation not reported incomplete")
	}
	tails.Advance(ParseFieldTailFrame(nil), true)
	if tails.saturated || tails.Incomplete(ParseFieldTailFrame([]byte(`{"brand-new":"value"}`))) {
		t.Fatal("reset did not clear the eviction record")
	}
}

func wideFieldTailFrame(text string, extra int) string {
	var b strings.Builder
	b.WriteString(`{"text":` + strconv.Quote(text))
	for i := range extra {
		b.WriteString(`,"f` + strconv.Itoa(i) + `":"v"`)
	}
	b.WriteString("}")
	return b.String()
}

func TestFieldTailsWideFrameNeverLeavesEmptyState(t *testing.T) {
	t.Parallel()
	// Wider than the old 128-leaf limit, within the frame limit: joined.
	medium := ParseFieldTailFrame([]byte(wideFieldTailFrame("first-half", DefaultJSONLeafMaxStreams+1)))
	if !medium.OK || medium.Overflow {
		t.Fatalf("medium frame: OK=%v Overflow=%v", medium.OK, medium.Overflow)
	}
	tails := NewFieldTails("")
	tails.Advance(medium, false)
	got := joinedViews(tails.Views(ParseFieldTailFrame([]byte(`{"text":"-second"}`))))
	if strings.Join(got, "|") != "first-half-second" {
		t.Fatalf("medium frame views = %q", got)
	}

	// Over the frame limit: the frame keeps what fits and the stream is
	// lossy, so a continuation on any untracked path fails closed.
	wide := ParseFieldTailFrame([]byte(wideFieldTailFrame("first-half", FieldTailFrameMaxLeaves+8)))
	if !wide.OK || !wide.Overflow {
		t.Fatalf("wide frame: OK=%v Overflow=%v, want overflow", wide.OK, wide.Overflow)
	}
	for _, raw := range []string{"{}", `{"a":null}`, "[]", "not json"} {
		if frame := ParseFieldTailFrame([]byte(raw)); frame.Overflow {
			t.Fatalf("%q marked overflow", raw)
		}
	}
	fresh := NewFieldTails("")
	if fresh.Incomplete(wide) {
		t.Fatal("empty tails reported a first wide frame incomplete")
	}
	fresh.Advance(wide, false)
	if !fresh.Incomplete(ParseFieldTailFrame([]byte(`{"text":"-second"}`))) {
		t.Fatal("continuation after a lossy wide frame not reported incomplete")
	}
	retained := NewFieldTails("")
	retained.Advance(ParseFieldTailFrame([]byte(`{"text":"first"}`)), false)
	if !retained.Incomplete(wide) {
		t.Fatal("wide frame after retained content not reported incomplete")
	}
	retained.Advance(ParseFieldTailFrame([]byte(`{"text":"x"}`)), true)
	if retained.Incomplete(wide) {
		t.Fatal("reset tails still reported incomplete")
	}
}

func TestFieldTailsKeysByIndexAndTextMembers(t *testing.T) {
	t.Parallel()
	call := func(idx int, args string) []byte {
		return []byte(`{"choices":[{"index":0,"delta":{"tool_calls":[{"index":` + strconv.Itoa(idx) + `,"function":{"arguments":` + strconv.Quote(args) + `}}]}}]}`)
	}
	tails := NewFieldTails("")
	tails.Advance(ParseFieldTailFrame(call(0, "A1")), false)
	tails.Advance(ParseFieldTailFrame(call(1, "B")), false)
	got := joinedViews(tails.Views(ParseFieldTailFrame(call(0, "A2"))))
	if !slicesContains(got, "A1A2") {
		t.Fatalf("interleaved tool call views = %q, want A1A2", got)
	}

	alias := NewFieldTails("")
	alias.Advance(ParseFieldTailFrame([]byte(`{"choices":[{"index":0,"delta":{"content":"one-"}}]}`)), false)
	got = joinedViews(alias.Views(ParseFieldTailFrame([]byte(`{"choices":[{"index":0,"delta":{"reasoning_content":"two"}}]}`))))
	if strings.Join(got, "|") != "one-two" {
		t.Fatalf("text member views = %q, want one-two", got)
	}
}

func TestFieldTailsIgnoresNonStringLeaves(t *testing.T) {
	t.Parallel()
	tails := NewFieldTails("")
	for i := range 50 {
		frame := ParseFieldTailFrame([]byte(`{"seq":` + strconv.Itoa(i) + `,"ok":true,"bytes":[1,2,3],"s":"1` + strconv.Itoa(i) + `"}`))
		for _, v := range tails.Views(frame) {
			if v.Tail != "" && !strings.HasPrefix(v.Value, "1") {
				t.Fatalf("non-string leaf joined: %q", v.Joined)
			}
		}
		tails.Advance(frame, false)
	}
	if len(tails.tails) != 1 {
		t.Fatalf("tracked paths = %d, want only the string leaf", len(tails.tails))
	}
}

func TestFieldTailsEvictionKeepsTextAndToleratesRepeats(t *testing.T) {
	t.Parallel()
	tails := NewFieldTails("")
	frame := ParseFieldTailFrame([]byte(`{"choices":[{"index":0,"delta":{"content":"hello"}}],` + wideFieldTailFrame("x", FieldTailMaxPaths+20)[1:]))
	if tails.Incomplete(frame) {
		t.Fatal("first frame incomplete")
	}
	tails.Advance(frame, false)
	if tails.tails["$/choices/~i0/delta/~t"] == nil {
		t.Fatal("text member evicted before envelope paths")
	}
	if tails.Incomplete(frame) {
		t.Fatal("identical repeat of a frame with evicted paths reported incomplete")
	}
	if !tails.Incomplete(ParseFieldTailFrame([]byte(`{"f0":"changed"}`))) {
		t.Fatal("changed value on an evicted path not reported incomplete")
	}
	if tails.Incomplete(ParseFieldTailFrame([]byte(`{"choices":[{"index":0,"delta":{"content":" world"}}]}`))) {
		t.Fatal("tracked text member reported incomplete")
	}
	limited := NewFieldTailsWithLimit("", 1<<20)
	if limited.maxPaths != FieldTailMaxPathsLimit {
		t.Fatalf("budget not clamped: %d", limited.maxPaths)
	}
}

func TestFieldTailsIndexOnlyInsideStreamedArrays(t *testing.T) {
	t.Parallel()
	frame := ParseFieldTailFrame([]byte(`{"index":3,"text":"a","meta":[{"index":2,"v":"b"}],"choices":[{"index":1,"delta":{"content":"c"}}]}`))
	got := strings.Join(frame.paths, " ")
	for _, want := range []string{"$/text", "$/meta/0/v", "$/choices/~i1/delta/~t"} {
		if !strings.Contains(got+" ", want+" ") {
			t.Fatalf("paths %q missing %q", got, want)
		}
	}
}

func TestFieldTailsStreamTextJoinsAcrossIndexAndMember(t *testing.T) {
	t.Parallel()
	for name, frames := range map[string][2]string{
		"root index changes":   {`{"index":1,"text":"one-"}`, `{"index":2,"text":"two"}`},
		"block index changes":  {`{"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"one-"}}`, `{"type":"content_block_delta","index":1,"delta":{"type":"text_delta","text":"two"}}`},
		"tool call index jump": {`{"choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"function":{"arguments":"one-"}}]}}]}`, `{"choices":[{"index":0,"delta":{"tool_calls":[{"index":7,"function":{"arguments":"two"}}]}}]}`},
		"thinking then text":   {`{"index":0,"delta":{"type":"thinking_delta","thinking":"one-"}}`, `{"index":0,"delta":{"type":"text_delta","text":"two"}}`},
	} {
		tails := NewFieldTails("")
		tails.Advance(ParseFieldTailFrame([]byte(frames[0])), false)
		got := joinedViews(tails.Views(ParseFieldTailFrame([]byte(frames[1]))))
		if !slicesContains(got, "one-two") {
			t.Errorf("%s: views = %q, want one-two", name, got)
		}
	}
	tails := NewFieldTails("")
	tails.Advance(ParseFieldTailFrame([]byte(`{"text":"one"}`)), false)
	tails.Advance(ParseFieldTailFrame([]byte(`{"text":"x"}`)), true)
	if views := tails.Views(ParseFieldTailFrame([]byte(`{"other":"y","text":"z"}`))); len(views) != 0 {
		t.Fatalf("reset kept stream text: %q", joinedViews(views))
	}
}

func slicesContains(list []string, want string) bool {
	for _, v := range list {
		if v == want {
			return true
		}
	}
	return false
}

func TestFieldTailsStreamTextKeepsFrameEndAndIndexedMembers(t *testing.T) {
	t.Parallel()
	long := NewFieldTails("")
	long.Advance(ParseFieldTailFrame([]byte(`{"tool_calls":[{"index":0,"arguments":"`+strings.Repeat("a", 630)+`one-"}]}`)), false)
	got := joinedViews(long.Views(ParseFieldTailFrame([]byte(`{"tool_calls":[{"index":4,"arguments":"two"}]}`))))
	if len(got) != 1 || !strings.HasSuffix(got[0], "one-two") {
		t.Fatalf("long frame views = %q, want a join ending one-two", got)
	}
	member := NewFieldTails("")
	member.Advance(ParseFieldTailFrame([]byte(`{"choices":[{"index":0,"delta":{"payload":"one-","role":"assistant"}}]}`)), false)
	member.Advance(ParseFieldTailFrame([]byte(`{"choices":[{"index":0,"delta":{"payload":"x","role":"assistant"}}]}`)), true)
	member.Advance(ParseFieldTailFrame([]byte(`{"choices":[{"index":0,"delta":{"payload":"one-","role":"assistant"}}]}`)), false)
	views := member.Views(ParseFieldTailFrame([]byte(`{"choices":[{"index":1,"delta":{"payload":"two","role":"assistant"}}]}`)))
	found := false
	for _, v := range views {
		found = found || strings.Contains(v.Joined, "one-two")
		if strings.Contains(v.Tail, "assistant") {
			t.Fatalf("repeated member kept in the stream text: %q", v.Tail)
		}
	}
	if !found {
		t.Fatalf("indexed member views = %q, want a join containing one-two", joinedViews(views))
	}
}
