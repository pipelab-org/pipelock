// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package decide

import (
	"fmt"
	"slices"
	"strings"
	"testing"
)

// TestLooksLikeHostOperand pins which bare curl/wget operands count as a host.
// A rejected shape is never scanned, so each rejection here must be a word
// curl would not treat as a destination either.
func TestLooksLikeHostOperand(t *testing.T) {
	for _, tc := range []struct {
		word string
		want bool
	}{
		{"api.vendor.example", true},
		{"api.vendor.example/path", true},
		{"api.vendor.example.", true},
		{"169.254.169.254", true},
		{"169.254.169.254:80/latest", true},
		{"169.254.169.254:/latest", true}, // empty port: curl uses the default
		{"169.254.169.254:99999", true},   // out of range, still scanned
		{"[fd00:ec2::254]", true},
		{"[fd00:ec2::254]/latest", true},
		{"[fd00:ec2::254]:80/latest", true},
		{"[fd00:ec2::254]:/latest", true},
		{"a-b.vendor.example", true},

		{"", false},
		{"-o", false},
		{"https://api.vendor.example/", false}, // scheme URLs take the regex path
		{"user@api.vendor.example", false},
		{"api.vendor example", false},
		{"/etc/passwd", false},
		{"localhost", false}, // no dot: ambiguous with a file name
		{"file.txt..bak", false},
		{"[]", false},
		{"[fd00::1", false},
		{"[fd00::1]x", false},
		{"[fd00::1]:8o", false},
		{"api.vendor.example:8o80", false},
		{"api.vendor.example:123456", false},
		{"-bad.vendor.example", false},
		{"bad-.vendor.example", false},
		{"bad_label.vendor.example", false},
		{strings.Repeat("a", 64) + ".vendor.example", false},
	} {
		if got := looksLikeHostOperand(tc.word); got != tc.want {
			t.Errorf("looksLikeHostOperand(%q) = %v, want %v", tc.word, got, tc.want)
		}
	}
}

// TestOperandHost pins the host part used for the literal-IP check after an
// unknown option.
func TestOperandHost(t *testing.T) {
	for _, tc := range []struct{ word, want string }{
		{"169.254.169.254", "169.254.169.254"},
		{"169.254.169.254:80/latest", "169.254.169.254"},
		{"[fd00:ec2::254]:80/latest", "fd00:ec2::254"},
		{"[fd00:ec2::254]/latest", "fd00:ec2::254"},
		{"[fd00::1", "[fd00::1"},
		{"api.vendor.example/x", "api.vendor.example"},
	} {
		if got := operandHost(tc.word); got != tc.want {
			t.Errorf("operandHost(%q) = %q, want %q", tc.word, got, tc.want)
		}
	}
}

// TestSplitShellWordsShapes covers quoting, escapes, comments and operators.
// An unterminated quote or a trailing backslash is unreliable structure, so the
// reader reports it and the caller falls back to explicit scheme URLs only.
func TestSplitShellWordsShapes(t *testing.T) {
	for _, tc := range []struct {
		name  string
		in    string
		want  []string
		valid bool
	}{
		{"single quotes", `curl 'a b'`, []string{"curl", "a b"}, true},
		{"double quote escapes", `echo "a\"b\$c"`, []string{"echo", `a"b$c`}, true},
		{"plain escape", `curl a\ b`, []string{"curl", "a b"}, true},
		{"comment to end of line", "curl x # 169.254.169.254\nls", []string{"curl", "x", "\n", "ls"}, true},
		{"hash inside a word is literal", "curl a#b", []string{"curl", "a#b"}, true},
		{"doubled operators", "a && b || c >> d", []string{"a", "&&", "b", "||", "c", ">>", "d"}, true},
		{"single operators", "a;b|c&d(e)f<g>h", []string{"a", ";", "b", "|", "c", "&", "d", "(", "e", ")", "f", "<", "g", ">", "h"}, true},
		{"unterminated single quote", `curl 'oops`, nil, false},
		{"unterminated double quote", `curl "oops`, nil, false},
		{"trailing backslash", `curl x\`, nil, false},
		{"invalid utf8", "curl \xff", nil, false},
		// bash(1) ANSI-C quoting. The escapes are the bytes the shell runs.
		{"ansi-c hex address", `curl $'\x31\x36\x39.\x32\x35\x34.\x31\x36\x39.\x32\x35\x34'`, []string{"curl", "169.254.169.254"}, true},
		{"ansi-c brace hex address", `curl $'\x{31}\x{36}\x{39}.\x{32}\x{35}\x{34}.\x{31}\x{36}\x{39}.\x{32}\x{35}\x{34}'`, []string{"curl", "169.254.169.254"}, true},
		{"locale quote drops the dollar", `curl $"api.vendor.example"`, []string{"curl", "api.vendor.example"}, true},
		{"dollar quote inside double quotes stays text", `echo "cost $'100'"`, []string{"echo", "cost $'100'"}, true},
		{"unterminated ansi-c quote", `curl $'oops`, nil, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := splitShellWords(tc.in)
			if ok != tc.valid {
				t.Fatalf("ok = %v, want %v (words %q)", ok, tc.valid, got)
			}
			if tc.valid && !slices.Equal(got, tc.want) {
				t.Fatalf("words = %q, want %q", got, tc.want)
			}
		})
	}
}

// TestShellDestinationExtractionOptions covers option handling the decide
// table does not reach: `--`, wget's two-letter flags, short clusters that end
// in a value option, duplicates, and the unreliable-structure fallback.
func TestShellDestinationExtractionOptions(t *testing.T) {
	for _, tc := range []struct {
		command string
		want    []string
	}{
		{"curl -- 169.254.169.254/x", []string{"http://169.254.169.254/x"}},
		{"wget -nv 169.254.169.254/x", []string{"http://169.254.169.254/x"}},
		{"wget -nc api.vendor.example/f", []string{"http://api.vendor.example/f"}},
		{"curl -so out.txt api.vendor.example/f", []string{"http://api.vendor.example/f"}},
		{"curl -so 169.254.169.254 api.vendor.example/f", []string{"http://api.vendor.example/f"}},
		{"curl 169.254.169.254:/x", []string{"http://169.254.169.254:/x"}},
		{"curl https://api.vendor.example/a https://api.vendor.example/a", []string{"https://api.vendor.example/a"}},
		{"curl 'https://api.vendor.example/q", []string{"https://api.vendor.example/q"}},
		// An option word after an unknown option is processed as an option.
		{"curl --not-a-real-option --url=169.254.169.254/latest/meta-data/", []string{"http://169.254.169.254/latest/meta-data/"}},
		{"curl --not-a-real-option --url 169.254.169.254/latest/", []string{"http://169.254.169.254/latest/"}},
		{"curl --not-a-real-option -- 169.254.169.254/x", []string{"http://169.254.169.254/x"}},
		{"curl --not-a-real-option --also-not-real api.vendor.example/x", nil},
		// Real curl booleans are in the table, so a following hostname is an operand.
		{"curl --retry-connrefused --fail-early api.vendor.example/x", []string{"http://api.vendor.example/x"}},
		{"curl --no-progress-meter 169.254.169.254/x", []string{"http://169.254.169.254/x"}},
		// An unknown option might take the value option after it as its own
		// value, which makes the next word the URL: a literal IP stays scanned.
		{"curl --not-a-real-option -o 169.254.169.254", []string{"http://169.254.169.254"}},
		{"curl --not-a-real-option -o out.txt api.vendor.example/f", []string{"http://api.vendor.example/f"}},
		// Destination options: their values name where the request goes.
		{"curl --resolve api.vendor.example:80:169.254.169.254 http://api.vendor.example/latest/", []string{"http://api.vendor.example/latest/", "http://169.254.169.254"}},
		{"curl --resolve=+api.vendor.example:443:10.0.0.5,[fd00:ec2::254] https://api.vendor.example/", []string{"https://api.vendor.example/", "http://10.0.0.5", "http://[fd00:ec2::254]"}},
		{"curl --connect-to api.vendor.example:80:169.254.169.254:80 http://api.vendor.example/", []string{"http://api.vendor.example/", "http://169.254.169.254:80"}},
		{"curl --connect-to api.vendor.example:443::8443 https://api.vendor.example/", []string{"https://api.vendor.example/"}},
		{"curl --connect-to ::[fd00:ec2::254]:80 http://api.vendor.example/", []string{"http://api.vendor.example/", "http://[fd00:ec2::254]:80"}},
		{"curl --socks5 169.254.169.254:1080 https://api.vendor.example/", []string{"https://api.vendor.example/", "http://169.254.169.254:1080"}},
		{"curl -x 169.254.169.254:3128 https://api.vendor.example/", []string{"https://api.vendor.example/", "http://169.254.169.254:3128"}},
		{"curl -x169.254.169.254:3128 https://api.vendor.example/", []string{"https://api.vendor.example/", "http://169.254.169.254:3128"}},
		{"curl -sx 169.254.169.254:3128 https://api.vendor.example/", []string{"https://api.vendor.example/", "http://169.254.169.254:3128"}},
		{"curl --proxy=user:pw@169.254.169.254:3128 https://api.vendor.example/", []string{"https://api.vendor.example/", "http://169.254.169.254:3128", "http://user:pw@169.254.169.254:3128"}},
		// socks5:// is not a scheme the URL regex takes; the destination option does.
		{"curl --preproxy socks5://169.254.169.254:1080 https://api.vendor.example/", []string{"https://api.vendor.example/", "http://169.254.169.254:1080"}},
		{"curl -x proxy.corp.example:3128 https://api.vendor.example/", []string{"https://api.vendor.example/", "http://proxy.corp.example:3128"}},
		// Userinfo is read only inside the authority: the path's "@" is not it.
		{"curl -x 169.254.169.254:3128/@proxy.corp.example https://api.vendor.example/", []string{"https://api.vendor.example/", "http://169.254.169.254:3128"}},
		{"curl -x http://169.254.169.254:3128?x=@proxy.corp.example https://api.vendor.example/", []string{"http://169.254.169.254:3128?x=@proxy.corp.example", "https://api.vendor.example/", "http://169.254.169.254:3128"}},
		// Only a scheme at the start is a scheme: "://" in a path or query is not.
		{"curl --url 169.254.169.254/x?r=http://a.example", []string{"http://a.example", "http://169.254.169.254/x?r=http://a.example"}},
		{"curl 169.254.169.254/x?u=http://a.example", []string{"http://a.example", "http://169.254.169.254/x?u=http://a.example"}},
		{"curl -x 169.254.169.254:3128/?u=http://a.example https://api.vendor.example/", []string{"http://a.example", "https://api.vendor.example/", "http://169.254.169.254:3128"}},
		// Non-web schemes still connect somewhere: their host is scanned.
		{"curl gopher://169.254.169.254:80/_GET", []string{"http://169.254.169.254:80"}},
		{"curl ftp://user:pw@169.254.169.254/pub", []string{"http://169.254.169.254", "http://user:pw@169.254.169.254"}},
		{"curl --url dict://169.254.169.254:11211/stat", []string{"http://169.254.169.254:11211"}},
		{"curl ftp://ftp.vendor.example/pub/file.tgz", []string{"http://ftp.vendor.example"}},
		// Userinfo on a bare operand: curl connects to the host after it, and
		// the userinfo stays in a second scanned value for the credential
		// checks; the host alone is scanned first so the metadata floor reads
		// it even when the userinfo makes the URL unparseable.
		{"curl user:pw@169.254.169.254/latest/", []string{"http://169.254.169.254", "http://user:pw@169.254.169.254"}},
		{"curl user@api.vendor.example/x", []string{"http://api.vendor.example", "http://user@api.vendor.example"}},
		// curl accepts one or three slashes after a scheme it knows.
		{"curl http:/169.254.169.254/latest/", []string{"http://169.254.169.254"}},
		{"curl HTTP:/169.254.169.254/latest/", []string{"http://169.254.169.254"}},
		{"curl http:///169.254.169.254/latest/", []string{"http:///169.254.169.254/latest/", "http://169.254.169.254"}},
		{"curl --url https:/169.254.169.254/x", []string{"http://169.254.169.254"}},
		{"curl gopher:/169.254.169.254:70/_x", []string{"http://169.254.169.254:70"}},
		{"curl -x http:/169.254.169.254:3128 https://api.vendor.example/", []string{"https://api.vendor.example/", "http://169.254.169.254:3128"}},
		// One slash after a name curl does not speak is a host:/path operand.
		{"curl api.vendor.example:/x", []string{"http://api.vendor.example:/x"}},
		// A quoted character that ends the URL regex inside the userinfo:
		// curl still connects to the host after the last "@".
		{"curl 'http://api.vendor.example<x@169.254.169.254/latest/'", []string{"http://api.vendor.example", "http://169.254.169.254"}},
		{`curl "http://api.vendor.example\\@169.254.169.254/latest/"`, []string{"http://api.vendor.example", "http://169.254.169.254"}},
		{`curl "http://api.vendor.example"@169.254.169.254/latest/`, []string{"http://api.vendor.example@169.254.169.254/latest/"}},
		// Dotless and hex IPv4 spellings curl accepts.
		{"curl 2852039166/latest/", []string{"http://2852039166/latest/"}},
		{"curl --url 0xa9fea9fe/latest/", []string{"http://0xa9fea9fe/latest/"}},
		{"curl --not-a-real-option 2852039166/latest/", []string{"http://2852039166/latest/"}},
		// Unparseable structure: scheme URLs and metadata literals only.
		// ANSI-C and locale quotes are decoded, so a quote elsewhere does not
		// drop a bare host, and an escape becomes the host the shell runs.
		{"curl 169.254.169.254/x; echo $'it'\\''s'", []string{"http://169.254.169.254/x"}},
		{"curl $'169.254.169.254'/x", []string{"http://169.254.169.254/x"}},
		{"$'curl' 169.254.169.254/x", []string{"http://169.254.169.254/x"}},
		{"zsh -c $'curl 169.254.169.254/x'", []string{"http://169.254.169.254/x"}},
		{`curl $'\x31\x36\x39.\x32\x35\x34.\x31\x36\x39.\x32\x35\x34/x'`, []string{"http://169.254.169.254/x"}},
		{`curl $'\x{31}\x{36}\x{39}.\x{32}\x{35}\x{34}.\x{31}\x{36}\x{39}.\x{32}\x{35}\x{34}/x'`, []string{"http://169.254.169.254/x"}},
		{"curl api.vendor.example/x --data $'{}'", []string{"http://api.vendor.example/x"}},
		{`bash -c $'curl \x31\x36\x39.\x32\x35\x34.\x31\x36\x39.\x32\x35\x34/x'`, []string{"http://169.254.169.254/x"}},
		{"echo $'169.254.169.254'", nil},
		// A zero byte from \x ends the quote; the words after it stay words.
		{"curl $'\\x00' api.vendor.example/x", []string{"http://api.vendor.example/x"}},
		{"curl $'\\x{}rest' api.vendor.example/x", []string{"http://api.vendor.example/x"}},
		{"curl $'\\x{0}' api.vendor.example/x", []string{"http://api.vendor.example/x"}},
		// A URL-like word after an unknown option is a destination either way.
		{"curl --not-a-real-option http:/169.254.169.254/x", []string{"http://169.254.169.254"}},
		{"curl --not-a-real-option gopher://169.254.169.254:70/_x", []string{"http://169.254.169.254:70"}},
		{"curl --not-a-real-option user@169.254.169.254/x", []string{"http://169.254.169.254", "http://user@169.254.169.254"}},
		{"curl --not-a-real-option value https://api.vendor.example/", []string{"https://api.vendor.example/"}},
		{"curl 169.254.169.254/x; echo $'it\\'s'", []string{"http://169.254.169.254/x"}},
		{"curl [fd00:ec2::254]:80/x \\", []string{"http://[fd00:ec2::254]"}},
		{"curl api.vendor.example/x \\", nil},
		// Quoting inside the address is removed before the fallback looks.
		{"curl 169.254.'169'.254/x; echo $'it\\'s'", []string{"http://169.254.169.254/x"}},
		{"curl \"169.254\".169.254/x; echo $'it\\'s'", []string{"http://169.254.169.254/x"}},
		{"curl 169.254.$'169'.254/x \\", []string{"http://169.254.169.254"}},
		// A one-slash proxy scheme still names the proxy host.
		{"curl -x socks5:/169.254.169.254:1080 https://api.vendor.example/", []string{"https://api.vendor.example/", "http://169.254.169.254:1080"}},
		{"curl --proxy socks5h:/169.254.169.254:1080 https://api.vendor.example/", []string{"https://api.vendor.example/", "http://169.254.169.254:1080"}},
		// A destination option's value counts even as a single-label host.
		{"curl -x metadata:80 https://api.vendor.example/", []string{"https://api.vendor.example/", "http://metadata:80"}},
		{"curl --url metadata/computeMetadata/v1/", []string{"http://metadata/computeMetadata/v1/"}},
		{"curl --resolve badvalue https://api.vendor.example/", []string{"https://api.vendor.example/"}},
		// A known value option still owns its next word, even an option-looking one.
		{"curl -o --url=169.254.169.254 api.vendor.example/f", []string{"http://api.vendor.example/f"}},
		{"curl 'unterminated 169.254.169.254", []string{"http://169.254.169.254"}},
		{"ls 169.254.169.254", nil},
	} {
		t.Run(tc.command, func(t *testing.T) {
			got, over := shellDestinationURLs(tc.command)
			if over {
				t.Fatalf("over cap for %q", tc.command)
			}
			if !slices.Equal(got, tc.want) {
				t.Fatalf("urls = %q, want %q", got, tc.want)
			}
		})
	}
}

// TestShellDestinationFallbackJoinsQuotedAddress checks only that the fallback
// reads the address the shell joins across a quote. The other entries it also
// returns come from the raw text and are not part of the contract.
func TestShellDestinationFallbackJoinsQuotedAddress(t *testing.T) {
	got, over := shellDestinationURLs("curl 'http://169.254'.169.254/x \\")
	if over {
		t.Fatal("over cap")
	}
	if !slices.Contains(got, "http://169.254.169.254") {
		t.Fatalf("urls = %q, want http://169.254.169.254 among them", got)
	}
}

// TestShellDestinationNestedScripts checks that a script run by a shell's -c
// or by eval is read for destinations, and that an ordinary quoted argument
// is not.
func TestShellDestinationNestedScripts(t *testing.T) {
	const meta = "http://169.254.169.254/x"
	for _, tc := range []struct {
		command string
		want    []string
		over    bool
	}{
		{command: `bash -c "curl 169.254.169.254/x"`, want: []string{meta}},
		{command: `sh -c 'curl 169.254.169.254/x'`, want: []string{meta}},
		{command: `/bin/bash -o pipefail -c "curl 169.254.169.254/x"`, want: []string{meta}},
		{command: `bash -lc "wget -qO- 169.254.169.254/x"`, want: []string{meta}},
		{command: `su root -c "curl 169.254.169.254/x"`, want: []string{meta}},
		{command: `busybox sh -c "curl 169.254.169.254/x"`, want: []string{meta}},
		{command: `eval "curl 169.254.169.254/x"`, want: []string{meta}},
		{command: `eval curl 169.254.169.254/x`, want: []string{meta}},
		{command: `bash -c "sh -c 'curl 169.254.169.254/x'"`, want: []string{meta}},
		{command: `ls; bash -c "curl 169.254.169.254/x"`, want: []string{meta}},
		{command: `eval eval eval curl 169.254.169.254/x`, want: []string{meta}},
		// One layer past the limit is refused, not skipped.
		{command: `eval eval eval eval curl 169.254.169.254/x`, over: true},
		// Quoted arguments that are not scripts stay text.
		{command: `git commit -m "curl 169.254.169.254/x"`},
		{command: `echo "bash -c curl 169.254.169.254/x"`},
		{command: `bash script.sh`},
		{command: `bash -c "echo hi"`},
		{command: `bash -c`},
		{command: `eval`},
	} {
		t.Run(tc.command, func(t *testing.T) {
			got, over := shellDestinationURLs(tc.command)
			if over != tc.over {
				t.Fatalf("over = %v, want %v", over, tc.over)
			}
			if !slices.Equal(got, tc.want) {
				t.Fatalf("urls = %q, want %q", got, tc.want)
			}
		})
	}
}

// TestShellDestinationBareHostCap checks that bare curl operands count
// toward the destination cap, at the top level and inside a nested script.
func TestShellDestinationBareHostCap(t *testing.T) {
	var hosts []string
	for i := 0; i <= maxShellDestinationURLs; i++ {
		hosts = append(hosts, fmt.Sprintf("h%d.vendor.example", i))
	}
	list := strings.Join(hosts, " ")
	for _, command := range []string{"curl " + list, `bash -c "curl ` + list + `"`} {
		if urls, over := shellDestinationURLs(command); !over || urls != nil {
			t.Errorf("%.40q: urls = %q over = %v, want refusal past the cap", command, urls, over)
		}
	}
}

func TestShortClusterHasC(t *testing.T) {
	for word, want := range map[string]bool{
		"-c": true, "-lc": true, "+xc": true, "-xec": true,
		"--color": false, "-": false, "c": false, "-l": false, "": false,
	} {
		if got := shortClusterHasC(word); got != want {
			t.Errorf("shortClusterHasC(%q) = %v, want %v", word, got, want)
		}
	}
}

// TestANSIQuotedControlBackslash pins bash 5.3's reading of \c followed by
// a backslash: \c\\ is control-backslash and consumes both backslashes, so
// decoding stays in step with the shell after it.
func TestANSIQuotedControlBackslash(t *testing.T) {
	for command, want := range map[string]string{
		`$'\c\\.'`:          "\x1c.",
		`$'\c\.'`:           "\x1c.",
		`$'\c\\\\.'`:        "\x1c\\.",
		`$'\c\\\x41'`:       "\x1cA",
		`$'\c\''`:           "\x1c'",
		`$'\c?'`:            "\x7f",
		`$'\c\x41'`:         "\x1cx41",
		`$'\c\\\U00000041'`: "\x1cA",
	} {
		words, ok := splitShellWords(command)
		if !ok || len(words) != 1 || words[0] != want {
			t.Errorf("splitShellWords(%s) = %q, %v; want [%q]", command, words, ok, want)
		}
	}
}

// TestANSIQuotedDecode pins $'...' decoding to bash 5.3.20 output: each want
// value was produced by running printf %s on the same input in that bash.
func TestANSIQuotedDecode(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{`$'\a\b\e\E\f\n\r\t\v'`, "\x07\x08\x1b\x1b\x0c\x0a\x0d\x09\x0b"},
		{`$'\\\'\"\?'`, "\x5c\x27\x22\x3f"},
		{`$'\z\8\9'`, "\x5c\x7a\x5c\x38\x5c\x39"},
		{`$'\x41\x4a\x4A'`, "\x41\x4a\x4a"},
		{`$'\x4g'`, "\x04\x67"},
		{`$'\xg'`, "\x5c\x78\x67"},
		{`$'\x'`, "\x5c\x78"},
		{`$'\x{41}'`, "\x41"},
		{`$'\x{1ff}'`, "\xff"},
		{`$'\x{41'`, "\x41"},
		{`$'\x{}rest'`, ""},
		{`$'\x{0}rest'`, ""},
		{`$'\x00rest'`, ""},
		{`$'\x{}a\'b'`, ""},
		{`$'\101\7\77'`, "\x41\x07\x3f"},
		{`$'\777'`, "\xff"},
		{`$'\0rest'`, ""},
		{`$'\000\'x'`, ""},
		{`$'\08'`, ""},
		{`$'\u0041'`, "\x41"},
		{`$'\u00e9'`, "\xc3\xa9"},
		{`$'\u20ac'`, "\xe2\x82\xac"},
		{`$'\U0001F600'`, "\xf0\x9f\x98\x80"},
		{`$'\U00000041'`, "\x41"},
		{`$'\u'`, "\x5c\x75"},
		{`$'\U'`, "\x5c\x55"},
		{`$'\uZZ'`, "\x5c\x75\x5a\x5a"},
		{`$'\u0000rest'`, ""},
		{`$'\ud800'`, "\xed\xa0\x80"},
		{`$'\ca\cA\c@x'`, "\x01\x01"},
		{`$'\c'`, "\x5c\x63"},
		{`$'\c?'`, "\x7f"},
		{`$'\c@rest\'q'`, ""},
		{`$'169.254.169.254'`, "\x31\x36\x39\x2e\x32\x35\x34\x2e\x31\x36\x39\x2e\x32\x35\x34"},
		{`$'\x31\x36\x39.\x32\x35\x34.\x31\x36\x39.\x32\x35\x34'`, "\x31\x36\x39\x2e\x32\x35\x34\x2e\x31\x36\x39\x2e\x32\x35\x34"},
		{`$'\061\066\071.254.169.254'`, "\x31\x36\x39\x2e\x32\x35\x34\x2e\x31\x36\x39\x2e\x32\x35\x34"},
	} {
		words, ok := splitShellWords(tc.in)
		var got string
		if len(words) == 1 {
			got = words[0]
		}
		if !ok || len(words) > 1 || got != tc.want {
			t.Errorf("splitShellWords(%s) = %q, %v; want %q", tc.in, words, ok, tc.want)
		}
	}
}

// TestANSIQuotedUnterminated checks that a $'...' quote that never closes,
// including after a zero byte, leaves the command to the raw-text fallback.
func TestANSIQuotedUnterminated(t *testing.T) {
	for _, command := range []string{`$'abc`, `$'\x00abc`, `$'\x00\`, `$'\x{}x\`, `$'\`, `$'\x`, `$"abc`} {
		if words, ok := splitShellWords(command); ok {
			t.Errorf("splitShellWords(%s) = %q, true; want unreadable", command, words)
		}
	}
}
