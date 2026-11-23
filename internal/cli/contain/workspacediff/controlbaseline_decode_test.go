// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package workspacediff

import (
	"bytes"
	"encoding/json"
	"errors"
	"io/fs"
	"runtime"
	"strings"
	"testing"
	"testing/iotest"
)

func TestDecodeControlBaselineRejectsInvalidPaths(t *testing.T) {
	const root = "/workspace"
	mode := fs.FileMode(0o644)
	entry := func(path string) baselineEntry {
		return baselineEntry{Path: []byte(path), Mode: &mode}
	}
	pass := func() *baselinePass {
		return &baselinePass{
			Entries:      []baselineEntry{entry("."), entry(".claude/raw-\xff"), entry("nested/.claude/settings.json")},
			Sources:      []baselineSource{{Path: []byte("nested/.claude/settings.json"), From: [][]byte{[]byte(".git/config")}}},
			Undiscovered: [][]byte{[]byte("vendor")}, PartlyListed: [][]byte{[]byte(".")},
			Unreadable: []baselineUnreadable{{Path: []byte("locked"), Reason: []byte("permission denied")}},
		}
	}
	cases := []struct {
		name   string
		mutate func(p *baselinePass)
	}{
		{"valid", func(*baselinePass) {}},
		{"duplicate entry", func(p *baselinePass) { p.Entries = append(p.Entries, entry(".")) }},
		{"empty entry path", func(p *baselinePass) { p.Entries[1].Path = nil }},
		{"entry without mode", func(p *baselinePass) { p.Entries[1].Mode = nil }},
		{"absolute entry", func(p *baselinePass) { p.Entries[1].Path = []byte("/") }},
		{"parent entry", func(p *baselinePass) { p.Entries[1].Path = []byte("..") }},
		{"unclean entry", func(p *baselinePass) { p.Entries[1].Path = []byte("a/../b") }},
		{"duplicate source", func(p *baselinePass) { p.Sources = append(p.Sources, p.Sources[0]) }},
		{"absolute source", func(p *baselinePass) { p.Sources[0].Path = []byte("/") }},
		{"absolute source reference", func(p *baselinePass) { p.Sources[0].From[0] = []byte("/") }},
		{"absolute undiscovered", func(p *baselinePass) { p.Undiscovered[0] = []byte("/") }},
		{"absolute partly listed", func(p *baselinePass) { p.PartlyListed[0] = []byte("/") }},
		{"absolute unreadable", func(p *baselinePass) { p.Unreadable[0].Path = []byte("/etc") }},
	}
	for _, tc := range cases {
		for _, nestedPass := range []bool{false, true} {
			priority, nested := pass(), pass()
			if nestedPass {
				tc.mutate(nested)
			} else {
				tc.mutate(priority)
			}
			data, err := json.Marshal(controlBaseline{
				Schema: controlBaselineSchema, Root: []byte(root), CapBytes: 1,
				Identity: &controlRootIdentity{}, Priority: priority, Nested: nested,
			})
			if err != nil {
				t.Fatal(err)
			}
			_, err = DecodeControlBaseline(bytes.NewReader(data), root)
			if want := tc.name != "valid"; (err != nil) != want {
				t.Errorf("%s (nested=%t): error = %v, want error %t", tc.name, nestedPass, err, want)
			}
		}
	}
}

func TestDecodeControlBaselineRejectsInvalidDocuments(t *testing.T) {
	const root = "/workspace"
	mode := fs.FileMode(0o644)
	doc := func() controlBaseline {
		pass := func() *baselinePass {
			return &baselinePass{Entries: []baselineEntry{{Path: []byte("."), Mode: &mode}}}
		}
		return controlBaseline{
			Schema: controlBaselineSchema, Root: []byte(root), CapBytes: 1,
			Identity: &controlRootIdentity{}, Priority: pass(), Nested: pass(),
		}
	}
	decode := func(d controlBaseline) (ControlSurfaceSnapshot, error) {
		data, err := json.Marshal(d)
		if err != nil {
			t.Fatal(err)
		}
		return DecodeControlBaseline(bytes.NewReader(data), root)
	}
	valid, err := decode(doc())
	if err != nil {
		t.Fatalf("valid document: %v", err)
	}
	if valid.CapBytes() != 1 {
		t.Fatalf("CapBytes = %d, want 1", valid.CapBytes())
	}
	for name, mutate := range map[string]func(*controlBaseline){
		"other root":          func(d *controlBaseline) { d.Root = []byte("/elsewhere") },
		"unknown schema":      func(d *controlBaseline) { d.Schema = "workspace-control-baseline/v0" },
		"zero digest cap":     func(d *controlBaseline) { d.CapBytes = 0 },
		"missing identity":    func(d *controlBaseline) { d.Identity = nil },
		"missing priority":    func(d *controlBaseline) { d.Priority = nil },
		"missing nested":      func(d *controlBaseline) { d.Nested = nil },
		"invalid priority":    func(d *controlBaseline) { d.Priority.Entries[0].Path = []byte("/") },
		"no priority entries": func(d *controlBaseline) { d.Priority.Entries = nil },
		"no nested entries":   func(d *controlBaseline) { d.Nested.Entries = nil },
	} {
		d := doc()
		mutate(&d)
		if _, err := decode(d); err == nil {
			t.Errorf("%s: decode accepted an invalid baseline", name)
		}
	}
	incomplete := doc()
	incomplete.Priority.Entries, incomplete.Problem = nil, []byte("discovery stopped")
	if _, err := decode(incomplete); err != nil {
		t.Errorf("an incomplete observation without entries must still load: %v", err)
	}
	if _, err := DecodeControlBaseline(iotest.ErrReader(errors.New("read failed")), root); err == nil {
		t.Error("decode ignored a read error")
	}
	if _, err := DecodeControlBaseline(strings.NewReader("{"), root); err == nil {
		t.Error("decode accepted malformed JSON")
	}
	if _, err := EncodeControlBaseline(ControlSurfaceSnapshot{root: "relative", capBytes: 1}); err == nil {
		t.Error("encode accepted a relative root")
	}
	if _, err := EncodeControlBaseline(ControlSurfaceSnapshot{root: root}); err == nil {
		t.Error("encode accepted a zero digest cap")
	}
	if runtime.GOOS == "linux" {
		statement, err := CompareControlBaseline(valid, valid)
		if err != nil {
			t.Fatal(err)
		}
		if !statement.Incomplete || !strings.Contains(statement.IncompleteReason, "identity unavailable") {
			t.Errorf("unknown root identity must make the comparison incomplete: %+v", statement)
		}
	}
}
