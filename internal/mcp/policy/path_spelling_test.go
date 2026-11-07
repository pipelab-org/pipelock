// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package policy

import (
	"encoding/json"
	"fmt"
	"path"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/extract"
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
	const rule = "Persistence Path Write via Command"
	for _, tt := range []struct {
		name string
		args []string
		want bool
	}{
		{"argv_blank", []string{"tee", "/etc/cache space/../cron.d/job"}, true},
		{"quoted_blank", []string{"tee '/etc/cache space/../cron.d/job'"}, true},
		{"escaped_blank", []string{`tee /etc/cache\ space/../cron.d/job`}, true},
		{"parents_past_the_command", []string{"tee /tmp/../../var/tmp/../spool/cron/job"}, true},
		{"parents_past_the_command_argv", []string{"tee", "/tmp/../../var/tmp/../spool/cron/job"}, true},
		{"parents_quoted_pipeline", []string{"echo hi | tee '/tmp/x y/../../../var/tmp/../spool/cron/job'"}, true},
		{"parents_redirect", []string{"echo x >/a/b/../../etc/x/../cron.d/job"}, true},
		{"parents_copy", []string{"cp notes /a/b/../../etc/x/../cron.d/job"}, true},
		{"parents_second_command", []string{"cd /srv && tee /tmp/../../var/tmp/../spool/cron/job"}, true},
		{"safe_parents", []string{"tee /tmp/../../var/tmp/../notes/job"}, false},
		{"safe_quoted_parents", []string{"tee '/tmp/x y/../../../var/tmp/../notes/job'"}, false},
		{"separate_commands", []string{"echo tee; printf '/etc/cache space/../cron.d/job'"}, false},
		{"separate_commands_parents", []string{"echo tee; printf /tmp/../../var/tmp/../spool/cron/job"}, false},
		{"quoted_separator_unsplit", []string{`tee '/home/a;b/.config/systemd/tmp/../user/s' $UNSET`}, true},
		{"quoted_pipe_unsplit", []string{`tee '/home/a|b/.config/systemd/tmp/../user/s' $UNSET`}, true},
		{"escaped_separator_unsplit", []string{`tee /home/a\&b/.config/systemd/tmp/../user/s $UNSET`}, true},
		{"quoted_separator_canonical", []string{`tee '/home/a;b/.config/systemd/user/s' $UNSET`}, true},
		{"quoted_separator_safe", []string{`tee '/home/a;b/.config/systemd/tmp/../notes/s' $UNSET`}, false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			v := pc.CheckToolCall("bash", tt.args)
			if got := slices.Contains(v.Rules, rule); got != tt.want {
				t.Fatalf("args=%q: matched=%v, want %v: %+v", tt.args, got, tt.want, v)
			}
		})
	}
}

// A patch names its files in its headers. Other values sent beside it, such as
// a description, are not pathnames and must not acquire a pathname spelling.
func TestPolicy_PatchFallbackPathScope(t *testing.T) {
	pc := New(config.MCPToolPolicy{Enabled: true, Action: config.ActionBlock, Rules: DefaultToolPolicyRules()})
	const safeTarget = "*** Begin Patch\n*** Update File: /project/notes.txt\n@@\n-a\n+b\n*** End Patch"
	for _, tt := range []struct {
		name  string
		input map[string]string
		want  bool
	}{
		{"description_with_parents", map[string]string{"input": safeTarget, "description": "/etc/other/../systemd/example"}, false},
		{"description_with_blank_and_parents", map[string]string{"input": safeTarget, "description": "/etc/other dir/../systemd/example"}, false},
		{"target_with_parents", map[string]string{"input": "*** Begin Patch\n*** Update File: /etc/other/../systemd/example\n@@\n-a\n+b\n*** End Patch"}, true},
		{"literal_protected_description", map[string]string{"input": safeTarget, "description": "/etc/systemd/example"}, true},
		{"safe_patch", map[string]string{"input": safeTarget}, false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			raw, err := json.Marshal(tt.input)
			if err != nil {
				t.Fatal(err)
			}
			values, _ := ArgValues(raw)
			v := pc.CheckToolCallWithArgs("apply_patch", values, raw)
			if v.Matched != tt.want || (tt.want && v.Action != config.ActionBlock) {
				t.Fatalf("verdict=%+v, want blocked %v", v, tt.want)
			}
		})
	}
}

// A tool may nest its operands. A pathname key is read at any depth; a rule
// scoped by arg_key still reads only the top-level keys it names, and nothing
// under another key is a pathname.
func TestPolicy_NestedFilePathScope(t *testing.T) {
	var deep any = "/etc/cache space/../cron.d/job"
	for range extract.MaxExtractDepth + 2 {
		deep = map[string]any{"a": deep}
	}
	deepJSON, err := json.Marshal(deep)
	if err != nil {
		t.Fatal(err)
	}
	pc := New(config.MCPToolPolicy{Enabled: true, Action: config.ActionBlock, Rules: DefaultToolPolicyRules()})
	scoped := New(config.MCPToolPolicy{Enabled: true, Action: config.ActionBlock, Rules: []config.ToolPolicyRule{{Name: "destination only", ToolPattern: "move_file", ArgPattern: `^/etc/cron\.d/job$`, ArgKey: "^destination$"}}})
	// The shipped rules include scoped ones, which fail closed on too-deep JSON by
	// themselves. A policy of unscoped rules shows the pathname read does so too.
	unscoped := New(config.MCPToolPolicy{Enabled: true, Action: config.ActionBlock, Rules: []config.ToolPolicyRule{{Name: "any value", ToolPattern: "write_file", ArgPattern: `^/etc/cron\.d/job$`}}})
	for _, tt := range []struct {
		name    string
		checker *Config
		tool    string
		raw     string
		want    string // rule that must be among the verdict's rules; empty for none
	}{
		{"nested_destination", pc, "move_file", `{"operation":{"source":"/project/a","destination":"/etc/cache space/../cron.d/job"}}`, "Persistence Path Write"},
		{"nested_destination_no_blank", pc, "move_file", `{"operation":{"destination":"/etc/x/../cron.d/job"}}`, "Persistence Path Write"},
		{"listed_destinations", pc, "move_file", `{"operations":[{"source":"/p/a","destination":"/p/b"},{"source":"/p/c","destination":"/etc/cache space/../cron.d/job"}]}`, "Persistence Path Write"},
		{"top_level_destination", pc, "move_file", `{"source":"/project/a","destination":"/etc/cache space/../cron.d/job"}`, "Persistence Path Write"},
		{"nested_pathname_list", pc, "read_multiple_files", `{"request":{"paths":["/p/a","/etc/cache space/../shadow"]}}`, "Credential File Access"},
		{"nested_content_is_not_a_path", pc, "write_file", `{"path":"/project/notes","edits":[{"oldText":"a","newText":"/etc/cache space/../cron.d/job"}]}`, ""},
		{"nested_content_object", pc, "write_file", `{"path":"/project/notes","content":{"body":"/etc/cache space/../cron.d/job"}}`, ""},
		{"scoped_top_level", scoped, "move_file", `{"source":"/p/a","destination":"/etc/cache space/../cron.d/job"}`, "destination only"},
		{"scoped_under_the_scoped_key", scoped, "move_file", `{"destination":{"path":"/etc/cache space/../cron.d/job"}}`, "destination only"},
		{"scoped_ignores_nested_key", scoped, "move_file", `{"destination":"/p/b","operation":{"destination":"/etc/cache space/../cron.d/job"}}`, ""},
		{"scoped_ignores_source", scoped, "move_file", `{"source":"/etc/cache space/../cron.d/job","destination":"/p/b"}`, ""},
		{"too_deep_under_a_pathname_key", pc, "write_file", `{"path":` + string(deepJSON) + `}`, uninspectableJSONDepthRule},
		{"too_deep_under_a_scoped_key", scoped, "move_file", `{"destination":` + string(deepJSON) + `}`, uninspectableJSONDepthRule},
		{"too_deep_under_a_pathname_key_unscoped_rules", unscoped, "write_file", `{"path":` + string(deepJSON) + `}`, uninspectableJSONDepthRule},
		{"nested_spelling_unscoped_rules", unscoped, "write_file", `{"request":{"file_path":"/etc/x/../cron.d/job"}}`, "any value"},
		{"unkeyed_arguments_are_candidates", pc, "write_file", `["/etc/cache space/../cron.d/job"]`, "Persistence Path Write"},
		{"unkeyed_safe", pc, "write_file", `["/project/cache space/../notes"]`, ""},
	} {
		t.Run(tt.name, func(t *testing.T) {
			raw := json.RawMessage(tt.raw)
			values, _ := ArgValues(raw)
			v := tt.checker.CheckToolCallWithArgs(tt.tool, values, raw)
			if tt.want == "" {
				if v.Matched {
					t.Fatalf("verdict=%+v, want none", v)
				}
				return
			}
			if !slices.Contains(v.Rules, tt.want) || v.Action != config.ActionBlock {
				t.Fatalf("verdict=%+v, want a block by %q", v, tt.want)
			}
		})
	}
}

// A link behind a nested pathname resolves exactly as a top-level one does,
// with and without local path identity. Unlisted fields keep the baseline
// conservative identity check as well.
func TestPolicy_NestedFilePathLocalIdentity(t *testing.T) {
	f := newLocalPathFixture(t)
	f.write(t, filepath.Join(f.home, ".bashrc"))
	alias := filepath.Join(f.ws, "notes.txt")
	f.link(t, filepath.Join(f.home, ".bashrc"), alias)
	spacedAlias := filepath.Join(f.ws, "notes with spaces.txt")
	f.link(t, filepath.Join(f.home, ".bashrc"), spacedAlias)
	for _, tt := range []struct {
		name  string
		input map[string]any
		want  bool
	}{
		{"top_level", map[string]any{"source": "/p/a", "destination": alias}, true},
		{"nested", map[string]any{"operation": map[string]any{"source": "/p/a", "destination": alias}}, true},
		{"listed", map[string]any{"operations": []any{map[string]any{"destination": "/p/b"}, map[string]any{"destination": alias}}}, true},
		{"other_key", map[string]any{"operation": map[string]any{"note": alias}}, true},
		{"spaced_path", map[string]any{"destination": spacedAlias}, true},
		{"spaced_note", map[string]any{"note": spacedAlias}, false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			raw, err := json.Marshal(tt.input)
			if err != nil {
				t.Fatal(err)
			}
			values, _ := ArgValues(raw)
			if v := f.policy(false).CheckToolCallWithArgs("move_file", values, raw); slices.Contains(v.Rules, testShellProfileRule) {
				t.Fatalf("fixture matched by text alone: %+v", v)
			}
			v := f.policy(true).CheckToolCallWithArgs("move_file", values, raw)
			if got := slices.Contains(v.Rules, testShellProfileRule); got != tt.want {
				t.Fatalf("matched=%v, want %v: %+v", got, tt.want, v)
			}
		})
	}
}

func TestPolicy_FileContentPathSpellings(t *testing.T) {
	pc := New(config.MCPToolPolicy{Enabled: true, Action: config.ActionBlock, Rules: DefaultToolPolicyRules()})
	for _, tt := range []struct {
		content string
		want    bool
	}{
		{"/etc/cache space/../cron.d/job", false},
		{"notes about /etc/cache/../cron.d/job", false},
		// Bare path-shaped values retain the checks already applied before
		// explicit pathname fields acquired whitespace-preserving readings.
		{"/etc/cache/../cron.d/job", true},
		{"file:etc/cron.d/job?notes=1", true},
	} {
		raw, err := json.Marshal(map[string]string{"path": "/project/notes.txt", "content": tt.content})
		if err != nil {
			t.Fatal(err)
		}
		values, _ := ArgValues(raw)
		v := pc.CheckToolCallWithArgs("write_file", values, raw)
		if v.Matched != tt.want {
			t.Errorf("content=%q: verdict=%+v, want match %v", tt.content, v, tt.want)
		}
	}
	pc = New(config.MCPToolPolicy{Enabled: true, Action: config.ActionBlock, Rules: []config.ToolPolicyRule{{Name: "submitted content", ToolPattern: "write_file", ArgPattern: `cache space/\.\./cron`}}})
	raw := json.RawMessage(`{"path":"/project/notes.txt","content":"/etc/cache space/../cron.d/job"}`)
	values, _ := ArgValues(raw)
	if v := pc.CheckToolCallWithArgs("write_file", values, raw); !v.Matched {
		t.Fatalf("submitted content stopped matching: %+v", v)
	}
}

// The pathname readings add views that depend on the spelling algorithm, never
// on how many operands a command names. Each case compares the same input with
// and without the readings, so an input the readings never touch cannot pass.
func TestPolicy_PathViewCount(t *testing.T) {
	operand := func(i int) string { return fmt.Sprintf("/project/cache %d/../notes%d", i, i) }
	joinWords := func(sep string, quote bool) func(n int) []string {
		return func(n int) []string {
			parts := make([]string, n)
			for i := range parts {
				parts[i] = "cat " + operand(i)
				if quote {
					parts[i] = "cat '" + operand(i) + "'"
				}
			}
			return []string{strings.Join(parts, sep)}
		}
	}
	for _, tt := range []struct {
		name  string
		build func(n int) []string
	}{
		{"argv_operands", func(n int) []string {
			args := []string{"cat"}
			for i := range n {
				args = append(args, operand(i))
			}
			return args
		}},
		{"commands_in_one_string", joinWords("; ", true)},
		{"words_in_one_string", func(n int) []string {
			words := []string{"cat"}
			for i := range n {
				words = append(words, "'"+operand(i)+"'")
			}
			return []string{strings.Join(words, " ")}
		}},
		{"piped_commands", joinWords(" | ", true)},
		{"quoted_separators", func(n int) []string {
			words := []string{"tee"}
			for i := range n {
				words = append(words, "'/project/a;b/cache "+fmt.Sprint(i)+"/../notes'")
			}
			return []string{strings.Join(words, " ") + " $UNSET"}
		}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			added := func(n int) int {
				args := tt.build(n)
				return len(buildArgViews(args, false, nil, true)) - len(buildArgViews(args, false, nil, false))
			}
			short, long := added(2), added(maxPairwiseTokens)
			if short == 0 {
				t.Fatal("the pathname readings added no view, so the comparison proves nothing")
			}
			if long != short {
				t.Fatalf("added views grow with operands: short=%d long=%d", short, long)
			}
			// Each family transposes at most the spellings of one operand into one
			// reading per normalization.
			spellings := len(withPathSpellings([]string{operand(0)}, true)) - 1
			if bound := 3 * spellings * len(argViewNorms); long > bound {
				t.Fatalf("added views = %d, exceeds %d (3 families x %d spellings x %d normalizations)", long, bound, spellings, len(argViewNorms))
			}
		})
	}
}

func TestShellPathWords(t *testing.T) {
	for _, tt := range []struct {
		name, text string
		want       []string
		span       []string
	}{
		{"blanks", "tee /a  b\tc", []string{"tee", "/a", "b", "c"}, []string{"tee", "/a", "b", "c"}},
		{"single_quoted", `cat '/etc/cache space/../shadow'`, []string{"cat", "/etc/cache space/../shadow"}, []string{"cat", `'/etc/cache space/../shadow'`}},
		{"double_quoted_escape", `cat "a\"b c" x`, []string{"cat", `a"b c`, "x"}, []string{"cat", `"a\"b c"`, "x"}},
		{"double_quoted_literal_backslash", `echo "a\bc"`, []string{"echo", `a\bc`}, []string{"echo", `"a\bc"`}},
		{"single_quote_keeps_backslash", `echo 'a\ b'`, []string{"echo", `a\ b`}, []string{"echo", `'a\ b'`}},
		{"escaped_blank", `cat /etc/cache\ space/../shadow`, []string{"cat", "/etc/cache space/../shadow"}, []string{"cat", `/etc/cache\ space/../shadow`}},
		{"adjacent_quotes", `cat /a/'b c'/"d e"`, []string{"cat", "/a/b c/d e"}, []string{"cat", `/a/'b c'/"d e"`}},
		{"operators", "a;b|c&d>e<f(g)", []string{"a", "b", "c", "d", "e", "f", "g"}, []string{"a", "b", "c", "d", "e", "f", "g"}},
		{"open_quote", "cat 'abc def", []string{"cat", "abc def"}, []string{"cat", "'abc def"}},
		{"line_continuation", "cat /a\\\n/b", []string{"cat", "/a/b"}, []string{"cat", "/a\\\n/b"}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			words := shellPathWords(tt.text)
			var got, span []string
			for _, w := range words {
				got = append(got, w.value)
				span = append(span, tt.text[w.start:w.end])
			}
			if !slices.Equal(got, tt.want) || !slices.Equal(span, tt.span) {
				t.Fatalf("words = %q (spans %q), want %q (spans %q)", got, span, tt.want, tt.span)
			}
		})
	}
}

func TestPathOperandReadings(t *testing.T) {
	for _, tt := range []struct {
		name string
		args []string
		want []string // one reading, joined with a newline between arguments
	}{
		{"argv_operand", []string{"cat", "/x y/../z"}, []string{"cat\n/z"}},
		{"parents_past_the_command", []string{"tee /tmp/../../var/tmp/../spool/cron/job"}, []string{"tee /var/spool/cron/job"}},
		{"quoted_blank", []string{"tee '/etc/cache space/../cron.d/job'"}, []string{"tee /etc/cron.d/job"}},
		{"escaped_blank", []string{`tee /etc/cache\ space/../cron.d/job`}, []string{"tee /etc/cron.d/job"}},
		{"redirect_target", []string{"echo x >/a/b/../../etc/x/../cron.d/y"}, []string{"echo x >/etc/cron.d/y"}},
		{"option_value", []string{"dd of=/a/b/../../etc/x/../cron.d/y"}, []string{"dd of=/etc/cron.d/y"}},
		{"two_operands_one_reading", []string{"cp /a/../b /c/../d"}, []string{"cp /b /d"}},
		{"quoted_separator", []string{`tee '/home/a;b/cache/../file' $UNSET`}, []string{`tee /home/a;b/file $UNSET`, `tee /home/a_b/file $UNSET`}},
		{"real_separator", []string{`tee /tmp/cache/../notes; cat /home/a/cache/../file $UNSET`}, []string{`tee /tmp/notes; cat /home/a/file $UNSET`}},
		{"no_parent_segment", []string{"tee /tmp/x /var/tmp/y"}, nil},
	} {
		t.Run(tt.name, func(t *testing.T) {
			var got []string
			for _, reading := range pathOperandReadings(tt.args) {
				got = append(got, strings.Join(reading, "\n"))
			}
			for _, want := range tt.want {
				if !slices.Contains(got, want) {
					t.Fatalf("readings = %q, want one to be %q", got, want)
				}
			}
			if tt.name == "real_separator" {
				for _, reading := range got {
					if !strings.Contains(reading, "; cat ") {
						t.Fatalf("unquoted command separator changed: %q", reading)
					}
				}
			}
			if tt.want == nil && len(got) != 0 {
				t.Fatalf("readings = %q, want none", got)
			}
		})
	}
}

func TestPolicy_PathReadingXargsInput(t *testing.T) {
	const rule = "utility options"
	for _, action := range []string{config.ActionWarn, config.ActionBlock} {
		pc := New(config.MCPToolPolicy{
			Enabled: true, Action: config.ActionBlock, OnIncompleteCheck: action,
			Rules: []config.ToolPolicyRule{{Name: rule, ToolPattern: "bash", ArgPattern: `/usr/bin/chmod\s+-R`}},
		})
		for _, tt := range []struct {
			command string
			unknown bool
		}{
			{`cat /tmp/list | xargs /usr/share/../bin/chmod`, true},
			{`cat /tmp/list | xargs /usr/share/../bin/chmod $UNSET`, true},
			{`echo 755 /tmp/notes | xargs /usr/share/../bin/chmod`, false},
			{`echo 755 /tmp/notes | xargs /usr/bin/chmod`, false},
			{`find /tmp -print0 | xargs -0 /usr/share/../bin/chmod`, false},
			{`cat /tmp/list | xargs --null /usr/share/../bin/chmod`, true},
		} {
			t.Run(action+"/"+tt.command, func(t *testing.T) {
				v := pc.CheckToolCall("bash", []string{tt.command})
				if tt.unknown {
					if !slices.Contains(v.IncompleteRules, rule) || v.Action != action {
						t.Fatalf("unknown input: %+v, want incomplete action %s", v, action)
					}
				} else if v.Matched {
					t.Fatalf("literal input: %+v, want no match", v)
				}
			})
		}
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
		{"write_file", map[string]any{"location": "/etc/x/../cron.d/job", "content": "notes"}},
		{"write_file", map[string]any{"relative_path": "/etc/x/../cron.d/job", "content": "notes"}},
		{"write_file", map[string]any{"output": "file:etc/cron.d/job?notes=1", "content": "notes"}},
		{"write_file", map[string]any{"operation": map[string]any{"location": "/etc/x/../cron.d/job"}}},
		{"write_file", map[string]any{"location": "/etc/cache space/../cron.d/job", "content": "notes"}},
		{"write_file", map[string]any{"relative_path": "/etc/cache space/../cron.d/job", "content": "notes"}},
		{"write_file", map[string]any{"output": "/etc/cache space/../cron.d/job", "content": "notes"}},
		{"write_file", map[string]any{"operation": map[string]any{"location": "/etc/cache space/../cron.d/job"}}},
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
