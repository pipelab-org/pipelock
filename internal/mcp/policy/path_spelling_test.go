// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package policy

import (
	"encoding/json"
	"fmt"
	"path"
	"slices"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

// pathSpelling rewrites a canonical absolute path into another spelling that
// a file backend resolves to the same file.
type pathSpelling func(p string) string

func spellFileURI(p string) string { return "file://" + p }

func spellUpperCase(s pathSpelling) pathSpelling {
	return func(p string) string { return strings.ToUpper(s(p)) }
}

func spellLocalhostAuthority(p string) string { return "file://localhost" + p }

// spellBeforeBase inserts extra segments before the final segment, joined
// with sep.
func spellBeforeBase(extra []string, sep string) pathSpelling {
	return func(p string) string {
		dir, base := path.Split(p)
		return dir + strings.Join(extra, sep) + sep + base
	}
}

// spellBackslashSeparators replaces every slash with a backslash.
func spellBackslashSeparators(s pathSpelling) pathSpelling {
	return func(p string) string { return strings.ReplaceAll(s(p), "/", `\`) }
}

// spellEscapeByte percent-escapes the first occurrence of b.
func spellEscapeByte(b byte, s pathSpelling) pathSpelling {
	return spellEscapeAt(b, strings.IndexByte, s)
}

// spellEscapeLastByte percent-escapes the last occurrence of b.
func spellEscapeLastByte(b byte, s pathSpelling) pathSpelling {
	return spellEscapeAt(b, strings.LastIndexByte, s)
}

func spellEscapeAt(b byte, index func(string, byte) int, s pathSpelling) pathSpelling {
	return func(p string) string {
		out := s(p)
		i := index(out, b)
		if i < 0 {
			return out
		}
		return out[:i] + fmt.Sprintf("%%%02X", b) + out[i+1:]
	}
}

// spellEscapeLastSlash percent-escapes the final separator.
func spellEscapeLastSlash(s pathSpelling) pathSpelling {
	return func(p string) string {
		out := s(p)
		i := strings.LastIndexByte(out, '/')
		return out[:i] + "%2F" + out[i+1:]
	}
}

func spellIdentity(p string) string { return p }

// spellDoubleEscapeByte percent-encodes every occurrence of b twice, so a
// single decode leaves a still-encoded byte and a reader that decodes a
// second time is the one that resolves it.
func spellDoubleEscapeByte(b byte, s pathSpelling) pathSpelling {
	return func(p string) string {
		return strings.ReplaceAll(s(p), string(b), fmt.Sprintf("%%25%02X", b))
	}
}

// spellBadEscapeParent inserts a segment carrying a malformed percent escape
// followed by a parent segment: a strict URL parser rejects the escape, while
// a lenient reader that keeps the segment and resolves the parent still
// reaches the base file.
func spellBadEscapeParent(p string) string {
	dir, base := path.Split(p)
	bad := "c" + "%" + "zz"
	return dir + bad + "/" + ".." + "/" + base
}

// spellBadEscapeBefore inserts a segment carrying a malformed percent escape
// followed by the given segment text before the final segment. Readers that
// decode around a malformed escape still decode the escapes in seg.
func spellBadEscapeBefore(seg string) pathSpelling {
	return func(p string) string {
		dir, base := path.Split(p)
		bad := "c" + "%" + "zz"
		return dir + bad + "/" + seg + "/" + base
	}
}

// escapeAll percent-encodes every byte of s, depth times.
func escapeAll(s string, depth int) string {
	for range depth {
		var b strings.Builder
		for i := 0; i < len(s); i++ {
			fmt.Fprintf(&b, "%%%02X", s[i])
		}
		s = b.String()
	}
	return s
}

// spellBackslashAuthority writes a file URI whose authority is empty and
// whose path uses backslash separators directly after the two slashes.
func spellBackslashAuthority(s pathSpelling) pathSpelling {
	return func(p string) string { return "file://" + spellBackslashSeparators(s)(p) }
}

// A file read tool may accept URIs, decode escapes, drop a localhost
// authority, treat a backslash as a separator, and resolve dot segments
// before it opens a path. The default credential read rule must match each
// such spelling of a protected path without local path identity, which is
// the remote upstream case where the path cannot be resolved on this host.
func TestDefaultPolicy_CredentialReadPathSpellings(t *testing.T) {
	pc := New(config.MCPToolPolicy{Enabled: true, Action: config.ActionBlock, Rules: DefaultToolPolicyRules()})
	key := path.Join("/home/dev", ".ssh", "id_rsa")
	shadow := path.Join("/etc", "shadow")
	parent := []string{"cache", ".."}
	tests := []struct {
		name   string
		target string
		spell  pathSpelling
		want   bool
	}{
		{"canonical_key", key, spellIdentity, true},
		{"canonical_shadow", shadow, spellIdentity, true},
		{"uri_form", key, spellFileURI, true},
		{"uri_form_case_variant", key, spellUpperCase(spellFileURI), true},
		{"uri_localhost_authority", key, spellLocalhostAuthority, true},
		{"current_segment", key, spellBeforeBase([]string{"."}, "/"), true},
		{"empty_segment", key, spellBeforeBase([]string{""}, "/"), true},
		{"parent_segment", key, spellBeforeBase(parent, "/"), true},
		{"parent_segment_shadow", shadow, spellBeforeBase(parent, "/"), true},
		{"uri_parent_segment", key, func(p string) string { return spellFileURI(spellBeforeBase(parent, "/")(p)) }, true},
		{"win_backslash_parent", key, spellBackslashSeparators(spellBeforeBase(parent, "/")), true},
		{"win_backslash_parent_shadow", shadow, spellBackslashSeparators(spellBeforeBase(parent, "/")), true},
		{"mixed_separator_parent", key, spellBeforeBase([]string{"cache", ".."}, `\`), true},
		{"mixed_separator_parent_trailing", key, func(p string) string {
			dir, base := path.Split(p)
			return dir + "cache" + `\` + ".." + "/" + base
		}, true},
		// Double-percent file URI: a second bounded decode resolves it.
		{"uri_double_escaped_parent", key, spellDoubleEscapeByte('.', func(p string) string { return spellFileURI(spellBeforeBase(parent, "/")(p)) }), true},
		// Backslash current segment with no parent: any backslash is cleaned.
		{"win_backslash_current_segment", key, spellBackslashSeparators(spellBeforeBase([]string{"."}, "/")), true},
		{"win_backslash_current_segment_shadow", shadow, spellBackslashSeparators(spellBeforeBase([]string{"."}, "/")), true},
		// file URI with an invalid escape: fall through to the raw remainder.
		{"uri_bad_escape_parent", key, func(p string) string { return spellFileURI(spellBadEscapeParent(p)) }, true},
		{"uri_bad_escape_parent_shadow", shadow, func(p string) string { return spellFileURI(spellBadEscapeParent(p)) }, true},
		// file URI with an invalid escape next to valid escapes: readers keep
		// the invalid escape and decode the valid ones.
		{"uri_bad_escape_encoded_parent", key, func(p string) string { return spellFileURI(spellBadEscapeBefore(escapeAll("..", 1))(p)) }, true},
		{"uri_bad_escape_encoded_parent_shadow", shadow, func(p string) string { return spellFileURI(spellBadEscapeBefore(escapeAll("..", 1))(p)) }, true},
		{"uri_bad_escape_encoded_letter", key, spellEscapeLastByte('h', func(p string) string { return spellFileURI(spellBadEscapeParent(p)) }), true},
		{"uri_bad_escape_double_encoded_parent", key, func(p string) string { return spellFileURI(spellBadEscapeBefore(escapeAll("..", 2))(p)) }, true},
		{"uri_bad_escape_double_encoded_parent_shadow", shadow, func(p string) string { return spellFileURI(spellBadEscapeBefore(escapeAll("..", 2))(p)) }, true},
		{"uri_escaped_bad_escape_double_encoded_parent", key, func(p string) string {
			dir, base := path.Split(p)
			return spellFileURI(dir + "c" + escapeAll("%", 1) + "zz" + "/" + escapeAll("..", 2) + "/" + base)
		}, true},
		// file URI whose authority ends at a backslash.
		{"uri_backslash_authority", key, spellBackslashAuthority(spellIdentity), true},
		{"uri_backslash_authority_current_segment", key, spellBackslashAuthority(spellBeforeBase([]string{"."}, "/")), true},
		{"uri_escaped_byte_dot", key, spellEscapeByte('.', spellFileURI), true},
		{"uri_escaped_byte_underscore", key, spellEscapeByte('_', spellFileURI), true},
		{"uri_escaped_byte_letter", key, spellEscapeLastByte('h', spellFileURI), true},
		{"uri_escaped_byte_shadow", shadow, spellEscapeByte('s', spellFileURI), true},
		{"uri_escaped_separator", key, spellEscapeLastSlash(spellFileURI), true},
		// Positive controls: ordinary reads stay allowed.
		{"control_project_file", "/home/dev/project/readme.md", spellIdentity, false},
		{"control_public_key", key + ".pub", spellIdentity, false},
		{"control_uri_project_file", "/home/dev/project/ notes.md", spellEscapeByte(' ', spellFileURI), false},
		{"control_uri_bad_escape_project_parent", "/home/dev/project/readme.md", func(p string) string { return spellFileURI(spellBadEscapeBefore(escapeAll("..", 1))(p)) }, false},
		{"control_uri_backslash_authority_project", "/home/dev/project/readme.md", spellBackslashAuthority(spellIdentity), false},
		{"control_win_backslash_project_parent", "/home/dev/project/readme.md", spellBackslashSeparators(spellBeforeBase(parent, "/")), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := tt.spell(tt.target)
			args, err := json.Marshal(map[string]string{"path": p})
			if err != nil {
				t.Fatalf("marshal: %v", err)
			}
			v := pc.CheckToolCallWithArgs("read_file", []string{p}, args)
			if v.Matched != tt.want {
				t.Fatalf("%s: matched = %v, want %v (rules %v)", tt.name, v.Matched, tt.want, v.Rules)
			}
		})
	}
}

func TestDefaultPolicy_PathSpellingPreprocessing(t *testing.T) {
	pc := New(config.MCPToolPolicy{Enabled: true, Action: config.ActionBlock, Rules: DefaultToolPolicyRules()})
	for _, tt := range []struct {
		name, target string
		want         bool
	}{
		{"uri_opaque_root", "file:etc/shadow", true},
		{"uri_opaque_parent", "file:foo/../etc/cache/../shadow", true},
		{"uri_opaque_project", "file:project/notes.md", false},
		{"uri_surrounding_space", " file:///etc/sha%64ow ", true},
		{"uri_embedded_tab", "fi\tle:///etc/sha\tdow", true},
		{"uri_embedded_newline", "fi\nle:///etc/sha\rdow", true},
		{"uri_surrounding_controls", "\x00file:///etc/sha%64ow\x1f", true},
		{"uri_parent_with_space", "file:///etc/cache space/../shadow", true},
		{"path_parent_with_space", "/etc/cache space/../shadow", true},
		{"path_parent_with_tab", "/etc/cache\tspace/../shadow", true},
		{"relative_parent_with_space", "config/.aws/cache space/../credentials", true},
		{"embedded_url_delimiter", "/etc/x://y/../../shadow", true},
		{"relative_url_delimiter", "cache/.aws/x://y/../../credentials", true},
		{"project_uri", " fi\tle:///project/cache space/../notes.md ", false},
		{"project_path", "/project/cache space/../notes.md", false},
		{"project_delimiter", "/project/x://y/../../notes.md", false},
		{"custom_uri", "memo://project/etc/cache/../shadow", false},
		{"url", "https://example.com/etc/cache/../shadow", false},
		{"command_text", "printf 'cache space/../notes.md'", false},
		{"multiline_text", "notes\n/etc/cache/../shadow", false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			args, err := json.Marshal(map[string]string{"path": tt.target})
			if err != nil {
				t.Fatal(err)
			}
			for _, tool := range []string{"read_file", "write_file", "edit_file", "mcp__filesystem__read_file", "filesystem.write_file"} {
				v := pc.CheckToolCallWithArgs(tool, []string{tt.target}, args)
				if v.Matched != tt.want || (tt.want && v.Action != config.ActionBlock) {
					t.Errorf("%s: verdict = %+v; want blocked %v", tool, v, tt.want)
				}
			}
		})
	}
}

func TestDefaultPolicy_ShellPathSpellings(t *testing.T) {
	pc := New(config.MCPToolPolicy{Enabled: true, Action: config.ActionBlock, Rules: DefaultToolPolicyRules()})
	for _, tt := range []struct {
		name string
		args []string
		want bool
	}{
		{"quoted_path", []string{"cat '/etc/cache space/../shadow'"}, true},
		{"double_quoted_path", []string{`cat "/etc/cache space/../shadow"`}, true},
		{"escaped_space", []string{`cat /etc/cache\ space/../shadow`}, true},
		{"argv_path", []string{"cat", "/etc/cache space/../shadow"}, true},
		{"quoted_project_path", []string{"cat '/project/cache space/../notes.md'"}, false},
		{"configured_spelling", []string{`r\m --rec notes`}, true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			checker := pc
			if tt.name == "configured_spelling" {
				checker = New(config.MCPToolPolicy{Enabled: true, Action: config.ActionBlock, Rules: []config.ToolPolicyRule{{Name: "configured command", ToolPattern: "bash", ArgPattern: `^rm --rec notes$`}}})
			}
			v := checker.CheckToolCall("bash", tt.args)
			if v.Matched != tt.want || (tt.want && v.Action != config.ActionBlock) {
				t.Fatalf("verdict=%+v, want blocked %v", v, tt.want)
			}
		})
	}
}

func TestDefaultPolicy_PathReadingPreservesIncompleteAction(t *testing.T) {
	pc := New(config.MCPToolPolicy{Enabled: true, Action: config.ActionWarn, OnIncompleteCheck: config.ActionBlock, Rules: []config.ToolPolicyRule{{Name: "path", ToolPattern: "bash", ArgPattern: `/etc/shadow`, Action: config.ActionWarn}}})
	command := strings.Repeat("{a,b}", maxPairwiseTokens) + " '/etc/cache space/../shadow'"
	v := pc.CheckToolCall("bash", []string{command})
	if v.Action != config.ActionBlock || len(v.IncompleteRules) == 0 || !slices.Contains(v.Rules, "path") {
		t.Fatalf("path interpretation cleared incomplete block: %+v", v)
	}
}

func TestPolicy_FileURIExactPath(t *testing.T) {
	pc := New(config.MCPToolPolicy{Enabled: true, Action: config.ActionBlock, Rules: []config.ToolPolicyRule{{Name: "exact path", ToolPattern: "read_file", ArgPattern: `^/etc/shadow$`}}})
	for _, target := range []string{"file:etc/shadow?cache=1", "file:etc/shadow#section", "file:etc/sha%64ow?cache=1#section", "file:///etc/shadow?cache=1", "file:etc/shadow%3Fnotes", "file:etc/shadow%23notes"} {
		t.Run(target, func(t *testing.T) {
			raw, err := json.Marshal(map[string]string{"path": target})
			if err != nil {
				t.Fatal(err)
			}
			v := pc.CheckToolCallWithArgs("read_file", []string{target}, raw)
			want := !strings.Contains(target, "%3F") && !strings.Contains(target, "%23")
			if v.Matched != want {
				t.Fatalf("verdict=%+v, want match %v", v, want)
			}
		})
	}
}

func TestPolicy_PathOperandCommandContext(t *testing.T) {
	pc := New(config.MCPToolPolicy{Enabled: true, Action: config.ActionBlock, Rules: DefaultToolPolicyRules()})
	for _, args := range [][]string{{"tee", "/etc/cache space/../cron.d/job"}, {"tee '/etc/cache space/../cron.d/job'"}, {`tee /etc/cache\ space/../cron.d/job`}} {
		v := pc.CheckToolCall("bash", args)
		if !slices.Contains(v.Rules, "Persistence Path Write via Command") {
			t.Errorf("args=%q: verdict=%+v", args, v)
		}
	}
	v := pc.CheckToolCall("bash", []string{"echo tee; printf '/etc/cache space/../cron.d/job'"})
	if slices.Contains(v.Rules, "Persistence Path Write via Command") {
		t.Fatalf("path interpretation joined separate commands: %+v", v)
	}
}

func TestPolicy_FileContentPathSpellings(t *testing.T) {
	pc := New(config.MCPToolPolicy{Enabled: true, Action: config.ActionBlock, Rules: DefaultToolPolicyRules()})
	for _, content := range []string{"/etc/cache space/../cron.d/job", "/etc/cache/../cron.d/job", "file:etc/cron.d/job?notes=1"} {
		raw, err := json.Marshal(map[string]string{"path": "/project/notes.txt", "content": content})
		if err != nil {
			t.Fatal(err)
		}
		values, _ := ArgValues(raw)
		v := pc.CheckToolCallWithArgs("write_file", values, raw)
		if v.Matched {
			t.Errorf("content=%q: verdict=%+v", content, v)
		}
	}
	pc = New(config.MCPToolPolicy{Enabled: true, Action: config.ActionBlock, Rules: []config.ToolPolicyRule{{Name: "submitted content", ToolPattern: "write_file", ArgPattern: `cache space/\.\./cron`}}})
	raw := json.RawMessage(`{"path":"/project/notes.txt","content":"/etc/cache space/../cron.d/job"}`)
	values, _ := ArgValues(raw)
	if v := pc.CheckToolCallWithArgs("write_file", values, raw); !v.Matched {
		t.Fatalf("submitted content stopped matching: %+v", v)
	}
}

func TestPolicy_PathViewCount(t *testing.T) {
	views := func(count int) []argView {
		args := []string{"cat"}
		for i := range count {
			args = append(args, fmt.Sprintf("/project/cache %d/../notes%d", i, i))
		}
		return buildArgViews(args, false, nil)
	}
	short, long := views(2), views(maxPairwiseTokens)
	if len(long) != len(short) {
		t.Fatalf("view count grows with operands: short=%d long=%d", len(short), len(long))
	}
}

func TestPolicy_FileArgumentPathScope(t *testing.T) {
	pc := New(config.MCPToolPolicy{Enabled: true, Action: config.ActionBlock, Rules: DefaultToolPolicyRules()})
	for _, tt := range []struct {
		tool string
		args map[string]any
	}{
		{"read_multiple_files", map[string]any{"paths": []string{"/project/notes.txt", "/etc/cache space/../shadow"}}},
		{"copy_file", map[string]any{"source": "/etc/cache space/../shadow", "destination": "/project/notes.txt"}},
		{"move_file", map[string]any{"source": "/project/notes.txt", "destination": "/etc/cache space/../shadow"}},
		{"filesystem.write_file", map[string]any{"path": "/etc/cache space/../shadow", "content": "notes"}},
	} {
		raw, err := json.Marshal(tt.args)
		if err != nil {
			t.Fatal(err)
		}
		values, _ := ArgValues(raw)
		if v := pc.CheckToolCallWithArgs(tt.tool, values, raw); !v.Matched || v.Action != config.ActionBlock {
			t.Errorf("%s: pathname missed: %+v", tt.tool, v)
		}
	}
	pc = New(config.MCPToolPolicy{Enabled: true, Action: config.ActionBlock, Rules: []config.ToolPolicyRule{{Name: "content only", ToolPattern: "write_file", ArgPattern: `^/etc/cron.d/job$`, ArgKey: "^content$"}}})
	raw := json.RawMessage(`{"path":"/etc/cache space/../cron.d/job","content":"notes"}`)
	values, _ := ArgValues(raw)
	if v := pc.CheckToolCallWithArgs("write_file", values, raw); v.Matched {
		t.Fatalf("scoped content rule acquired another field's path: %+v", v)
	}
}
