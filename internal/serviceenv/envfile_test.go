// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package serviceenv

import (
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
			got, err := parseEnvironmentFile([]byte(tt.input))
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
			_, err := parseEnvironmentFile([]byte(input))
			if err == nil {
				t.Fatal("malformed input accepted")
			}
			if strings.Contains(err.Error(), "secret-sentinel") {
				t.Fatal("error exposed an environment value")
			}
		})
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
