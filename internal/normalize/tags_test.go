// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package normalize

import (
	"strings"
	"testing"
)

func TestDecodeTags(t *testing.T) {
	var tags, ascii strings.Builder
	for r := rune(0x20); r <= 0x7e; r++ {
		tags.WriteRune(0xe0000 + r)
		ascii.WriteRune(r)
	}
	for _, tc := range []struct{ name, input, want string }{
		{"printable range", tags.String(), ascii.String()},
		{"framing", "a\U000e0001\U000e0042\U000e007fc", "aBc"},
		{"other invisibles", "a\u200b\U000e0042\u2060c", "a\u200bB\u2060c"},
		{"unassigned", "\U000e0000\U000e0002\U000e001f\U000e0080", "\U000e0000\U000e0002\U000e001f\U000e0080"},
		{"prose", "ordinary prose", "ordinary prose"},
		{"CJK", "正常な文章", "正常な文章"},
		{"malformed UTF-8", "\xff\U000e0041\xc0", "\xffA\xc0"},
		{"incomplete tag bytes", "\xf3\xa0\x80!", "\xf3\xa0\x80!"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := DecodeTags(tc.input); got != tc.want {
				t.Fatalf("got %q want %q", got, tc.want)
			}
			if len(DecodeTags(tc.input)) > len(tc.input) {
				t.Fatal("decode grew input")
			}
		})
	}
	if got := ForDLP("prefix\U000e0041suffix"); got != "prefixsuffix" {
		t.Fatalf("stripped view changed: %q", got)
	}
	if allocs := testing.AllocsPerRun(100, func() { _ = DecodeTags("ordinary prose") }); allocs != 0 {
		t.Fatalf("untagged allocations: %v", allocs)
	}
}
