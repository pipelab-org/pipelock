// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package policy

import (
	"encoding/json"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

// A file tool can carry its target under a key that is not a recognized
// pathname field. Local identity resolution must still follow that value when
// it contains a space, as it does for a space-free value under the same key.
func TestLocalPathIdentity_WhitespaceValueUnderUnrecognizedKey(t *testing.T) {
	for _, tt := range []struct {
		name, file string
		relative   bool
		hard       bool
	}{
		{name: "space-free name", file: "notes.txt"},
		{name: "name with a space", file: "my notes.txt"},
		{name: "name with a tab", file: "my\tnotes.txt"},
		{name: "relative name with a space", file: "my notes.txt", relative: true},
		{name: "relative name with a tab", file: "my\tnotes.txt", relative: true},
		{name: "hard link with a space", file: "my notes.txt", hard: true},
		{name: "hard link with a tab", file: "my\tnotes.txt", hard: true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			f := newLocalPathFixture(t)
			f.write(t, filepath.Join(f.home, ".profile"))
			alias := filepath.Join(f.ws, tt.file)
			if tt.hard {
				hardLink(t, filepath.Join(f.home, ".profile"), alias)
			} else {
				f.link(t, filepath.Join(f.home, ".profile"), alias)
			}
			if tt.relative {
				alias = tt.file
			}
			if v := checkPath(f.policy(false), testWriteTool, "workspace_entry", alias); v.Matched {
				t.Fatalf("control matched without local identity: %+v", v)
			}
			raw, err := json.Marshal(map[string]string{"workspace_entry": alias})
			if err != nil {
				t.Fatal(err)
			}
			pc := f.policy(true)
			pc.Action = config.ActionBlock
			for surface, v := range map[string]Verdict{
				"MCP":  pc.CheckToolCallWithArgs(testWriteTool, []string{alias}, raw),
				"hook": pc.CheckToolCallJSON(testWriteTool, []string{alias}, []string{"workspace_entry", alias}, raw),
			} {
				if !slices.Contains(v.Rules, testShellProfileRule) || v.Action != config.ActionBlock {
					t.Fatalf("%s: alias under an unrecognized key was not blocked: %+v", surface, v)
				}
			}
		})
	}
}

func TestLocalPathIdentity_ContentCandidateBoundary(t *testing.T) {
	f := newLocalPathFixture(t)
	profile := filepath.Join(f.home, ".profile")
	f.write(t, profile)
	const alias = "release notes"
	f.link(t, profile, filepath.Join(f.ws, alias))
	f.link(t, profile, filepath.Join(f.ws, "release-notes"))
	f.write(t, filepath.Join(f.ws, "ordinary notes"))
	pc := f.policy(true)
	for _, tt := range []struct {
		name, value string
		want        bool
	}{
		{"existing relative alias", alias, true},
		{"space-free content alias", "release-notes", true},
		{"ordinary file", "ordinary notes", false},
		{"absent bare content", "some other notes", false},
		{"NUL", alias + "\x00", false},
		{"LF", alias + "\n", false},
		{"CR", alias + "\r", false},
		{"hierarchical URL", "https://api.vendor.example/" + alias, false},
		{"oversized", strings.Repeat("x", localPathMaxLen+1), false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			raw, err := json.Marshal(map[string]string{"path": filepath.Join(f.ws, "output.txt"), "content": tt.value})
			if err != nil {
				t.Fatal(err)
			}
			values, _ := ArgValues(raw)
			got, _, truncated := pc.expandToolPaths(values, raw, true, nil)
			if truncated || slices.Contains(got, profile) != tt.want {
				t.Fatalf("expanded=%q truncated=%v, want protected identity=%v", got, truncated, tt.want)
			}
			if tt.want {
				if v := pc.CheckToolCallWithArgs(testWriteTool, values, raw); !slices.Contains(v.Rules, testShellProfileRule) {
					t.Fatalf("content naming a protected alias lost the conservative match: %+v", v)
				}
			}
		})
	}
	for _, key := range []string{"oldText", "newText"} {
		edit := map[string]string{"oldText": "before", "newText": "after"}
		edit[key] = alias
		raw, err := json.Marshal(map[string]any{
			"path":  filepath.Join(f.ws, "output.txt"),
			"edits": []map[string]string{edit},
		})
		if err != nil {
			t.Fatal(err)
		}
		values, _ := ArgValues(raw)
		if v := pc.CheckToolCallWithArgs("edit_file", values, raw); !slices.Contains(v.Rules, testShellProfileRule) {
			t.Fatalf("%s naming a protected alias lost the conservative match: %+v", key, v)
		}
	}
}
