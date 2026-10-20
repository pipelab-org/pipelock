// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package serviceenv

import (
	"fmt"
	"slices"
	"strings"
	"testing"
)

func TestEnvironmentFileGrammar(t *testing.T) {
	tests := []struct {
		name, input string
		want        []string
	}{
		{"empty", "", nil},
		{"comments and ignored lines", " # c=x\n; a=b\nno assignment\n", nil},
		{"empty assignment", " EMPTY = \t\r\n", []string{"EMPTY="}},
		{"spacing", "A=  one  two\tthree \t\r\n", []string{"A=one  two\tthree"}},
		{"interior equals", "A=a=b=c", []string{"A=a=b=c"}},
		{"unquoted quotes literal", "A=a'\"b\"'\n", []string{"A=a'\"b\"'"}},
		{"single quoted multiline", "A= 'a\nb\\c' \t\n", []string{"A=a\nb\\c"}},
		{"double quoted escapes", "A=\"a\\$b\\`c\\\"d\\\\e\\q\"\n", []string{"A=a$b`c\"d\\e\\q"}},
		{"unquoted escape", "A=one\\ two\\#three\\;four\n", []string{"A=one two#three;four"}},
		{"escaped trailing space", "A=value\\ \n", []string{"A=value "}},
		{"unquoted continuation", "A=one\\\ntwo\n", []string{"A=onetwo"}},
		{"quoted continuation", "A=\"one\\\ntwo\"\n", []string{"A=onetwo"}},
		{"literal shell constructs", "A=$HOME $(touch /never) `id` %n\n", []string{"A=$HOME $(touch /never) `id` %n"}},
		{"inline comment is data", "A=value # comment; data\n", []string{"A=value # comment; data"}},
		{"quoted spaces", "A='  x  '\n", []string{"A=  x  "}},
		{"quoted concatenation", "A='one' \"two\" three\n", []string{"A=onetwothree"}},
		{"comment continuation", "# ignored\\\nA=value\nB=kept\n", []string{"B=kept"}},
		{"duplicates retained", "A=one\nA=two\n", []string{"A=one", "A=two"}},
		{"unicode and controls", "A=\"café\t\x01\"", []string{"A=café\t\x01"}},
		{"no final newline", "A=x", []string{"A=x"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseEnvironmentFile([]byte(tt.input), 252)
			if err != nil || !slices.Equal(got, tt.want) {
				t.Fatalf("got %q, %v; want %q", got, err, tt.want)
			}
		})
	}
}

func TestEnvironmentFileMalformedInput(t *testing.T) {
	for name, input := range map[string]string{
		"utf8": "A=\xff", "nul": "A=x\x00y", "bom": "A=\ufeff", "noncharacter": "A=\ufdd0", "plane noncharacter": "A=\U0001ffff",
		"unterminated single": "A='secret-sentinel", "unterminated double": "A=\"secret-sentinel", "escaped EOF": "A=secret-sentinel\\",
		"quoted escaped EOF": "A=\"secret-sentinel\\", "empty key": "=secret-sentinel", "invalid key": "1A=secret-sentinel", "export": "export A=secret-sentinel",
	} {
		t.Run(name, func(t *testing.T) {
			_, err := parseEnvironmentFile([]byte(input), 254)
			if err == nil {
				t.Fatal("malformed input accepted")
			}
			if strings.Contains(err.Error(), "secret-sentinel") {
				t.Fatal("error exposed an environment value")
			}
		})
	}
}

func TestEnvironmentFileVersionedCommentEscapes(t *testing.T) {
	// NEWS v254 changes EnvironmentFile's COMMENT_ESCAPE at a newline.
	// systemd.syntax(7) describes unit-file continuation, a different grammar.
	// https://github.com/systemd/systemd/blob/v254/NEWS
	// https://github.com/systemd/systemd/blob/v254/man/systemd.syntax.xml
	for _, version := range []int{252, 253, 254, 257} {
		for _, marker := range []string{"#", ";"} {
			for _, newline := range []string{"\n", "\r"} {
				t.Run(fmt.Sprintf("%d/%s/%q", version, marker, newline), func(t *testing.T) {
					got, err := parseEnvironmentFile([]byte(marker+" ignored\\"+newline+"A="+newline+"B=kept"+newline), version)
					want := []string{"B=kept"}
					if version >= 254 {
						want = []string{"A=", "B=kept"}
					}
					if err != nil || !slices.Equal(got, want) {
						t.Fatalf("got %q, %v; want %q", got, err, want)
					}
				})
			}
		}
	}
}

func TestEnvironmentFileCommentAndNewlineBoundaries(t *testing.T) {
	// env-file.c uses NEWLINE (LF and CR) for comments/unquoted values, but
	// its double-quoted escape state consumes only LF. Backslash pairs in a
	// comment escape each other and do not continue a subsequent newline.
	for _, version := range []int{252, 254} {
		for _, tc := range []struct {
			input string
			want  []string
		}{
			{"# ignored\\\\\nA=kept\n", []string{"A=kept"}},
			{"# ignored\\x\nA=kept\n", []string{"A=kept"}},
			{"# ignored\\", nil},
			{"# ignored\\\r\nA=kept\n", []string{"A=kept"}},
			{"# ignored\rA=kept\r", []string{"A=kept"}},
			{"no assignment\rA=kept\r", []string{"A=kept"}},
			{"A=\rB=kept\r", []string{"A=", "B=kept"}},
			{"A=one\rB=two\r", []string{"A=one", "B=two"}},
			{"A=one\\\rtwo\r", []string{"A=onetwo"}},
			{"A='one\rtwo'\r", []string{"A=one\rtwo"}},
			{"A=\"one\\\rtwo\"\r", []string{"A=one\\\rtwo"}},
		} {
			got, err := parseEnvironmentFile([]byte(tc.input), version)
			if err != nil || !slices.Equal(got, tc.want) {
				t.Fatalf("manager %d, input %q: got %q, %v; want %q", version, tc.input, got, err, tc.want)
			}
		}
	}
	for _, version := range []int{0, -1} {
		if _, err := parseEnvironmentFile([]byte("# ignored\\\nA=secret-sentinel\n"), version); err == nil || strings.Contains(err.Error(), "secret-sentinel") {
			t.Fatal("unknown version did not refuse without exposing file values")
		}
	}
}

func TestEnvironmentFileContinuationPreservesPrecedingWhitespace(t *testing.T) {
	// env-file.c clears last_value_whitespace in VALUE on the backslash,
	// before VALUE_ESCAPE consumes the newline. Only later whitespace trims.
	// https://github.com/systemd/systemd/blob/v252/src/basic/env-file.c
	// https://github.com/systemd/systemd/blob/v257/src/basic/env-file.c
	for _, version := range []int{252, 254, 257} {
		for _, newline := range []string{"\n", "\r"} {
			for _, tc := range []struct {
				name, suffix, want string
			}{
				{"EOF", "", "A=x \t"},
				{"blank line", newline, "A=x \t"},
				{"later whitespace EOF", " \t", "A=x \t"},
				{"later whitespace newline", " \t" + newline, "A=x \t"},
				{"later text", " y \t" + newline, "A=x \t y"},
			} {
				t.Run(fmt.Sprintf("%d/%q/%s", version, newline, tc.name), func(t *testing.T) {
					input := "A=x \t\\" + newline + tc.suffix
					got, err := parseEnvironmentFile([]byte(input), version)
					if err != nil || !slices.Equal(got, []string{tc.want}) {
						t.Fatalf("input %q: got %q, %v; want %q", input, got, err, tc.want)
					}
				})
			}
		}
	}
}

func TestVariableNames(t *testing.T) {
	for _, name := range []string{"A", "_", "a_B9"} {
		if !validName(name) {
			t.Fatalf("valid name rejected: %s", name)
		}
	}
	for _, name := range []string{"", "1A", "A-B", "A B", "é", "A\x00B"} {
		if validName(name) {
			t.Fatalf("invalid name accepted: %q", name)
		}
	}
}
