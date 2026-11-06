// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package policy

import (
	"encoding/json"
	"fmt"
	"path"
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
