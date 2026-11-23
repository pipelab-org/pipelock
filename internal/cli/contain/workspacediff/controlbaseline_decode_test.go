// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package workspacediff

import (
	"bytes"
	"encoding/json"
	"io/fs"
	"testing"
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
