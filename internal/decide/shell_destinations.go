// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package decide

import (
	"fmt"
	"net"
	"regexp"
	"strings"
	"unicode/utf8"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

// maxShellDestinationURLs is the most explicit destinations one shell command
// may name. A fetch command names one URL (an installer or a single fetch)
// or a short list; 16 is past that list. A longer list is
// denied without scanning a subset so it cannot fill the 10s hook deadline
// one lookup at a time.
const maxShellDestinationURLs = 16

// schemeURLRe finds an explicit http(s) or ws(s) destination inside one
// already-split shell word. The scheme match is case-insensitive.
var schemeURLRe = regexp.MustCompile(`(?i)(?:https?|wss?)://[^\s<>'"\\]+`)

// leadingSchemeRe is an RFC 3986 scheme and the slashes after it, anchored at
// the start of a value. A "://" later in the value (in a path or query) is not
// a scheme.
var leadingSchemeRe = regexp.MustCompile(`^([A-Za-z][A-Za-z0-9+.-]*):(/+)`)

// curlSchemes are the URL and proxy schemes curl speaks. curl accepts one to three
// slashes after a scheme ("http:/host" and "http:///host" both connect to
// host); a single slash counts as a scheme only for these names, so a
// host:/path operand is not mistaken for one.
var curlSchemes = map[string]bool{
	"dict": true, "file": true, "ftp": true, "ftps": true, "gopher": true,
	"gophers": true, "http": true, "https": true, "imap": true, "imaps": true,
	"ldap": true, "ldaps": true, "mqtt": true, "mqtts": true, "pop3": true,
	"pop3s": true, "rtmp": true, "rtmpe": true, "rtmps": true, "rtmpt": true,
	"rtmpte": true, "rtmpts": true, "rtsp": true, "scp": true, "sftp": true,
	"smb": true, "smbs": true, "smtp": true, "smtps": true, "telnet": true,
	"tftp": true, "ws": true, "wss": true,
	// Proxy schemes (curl(1) --proxy).
	"socks4": true, "socks4a": true, "socks5": true, "socks5h": true,
}

// leadingScheme returns the lowercased scheme, the length of the scheme
// prefix including its slashes, and how many slashes follow the colon.
func leadingScheme(value string) (scheme string, prefixLen, slashes int, ok bool) {
	m := leadingSchemeRe.FindStringSubmatch(value)
	if m == nil {
		return "", 0, 0, false
	}
	scheme, slashes = strings.ToLower(m[1]), len(m[2])
	if slashes == 1 && !curlSchemes[scheme] {
		return "", 0, 0, false
	}
	return scheme, len(m[0]), slashes, true
}

// hasLeadingScheme reports whether value starts with a URL scheme.
func hasLeadingScheme(value string) bool {
	_, _, _, ok := leadingScheme(value)
	return ok
}

// webScheme reports whether value starts with a scheme schemeURLRe already
// takes as a whole URL: http, https, ws or wss followed by exactly "//".
// Other slash counts are scanned through authorityHost instead.
func webScheme(value string) bool {
	scheme, _, slashes, ok := leadingScheme(value)
	if !ok || slashes != 2 {
		return false
	}
	switch scheme {
	case "http", "https", "ws", "wss":
		return true
	}
	return false
}

// authorityHost returns the host[:port] a URL-like value connects to: an
// anchored scheme and its slashes are removed, the authority ends at the
// first "/?#", and any userinfo before the last "@" inside it is dropped
// (curl's URL parser reads it the same way).
func authorityHost(value string) string {
	value = authority(value)
	if at := strings.LastIndexByte(value, '@'); at >= 0 {
		value = value[at+1:]
	}
	return value
}

// authority returns the [userinfo@]host[:port] part of a URL-like value: an
// anchored scheme and its slashes are removed and the authority ends at the
// first "/?#".
func authority(value string) string {
	if _, n, _, ok := leadingScheme(value); ok {
		value = value[n:]
	}
	if i := strings.IndexAny(value, "/?#"); i >= 0 {
		value = value[:i]
	}
	return value
}

// scannedAuthorities are the destinations handed to the scanner for a
// URL-like value: the host alone, so the hook's metadata floor reads it even
// when the userinfo would make the URL unparseable, and then the authority
// with its userinfo kept, so a credential in it still reaches the URL
// credential checks the way it does for an explicit http:// URL. It returns
// nil when there is no host.
func scannedAuthorities(value string) []string {
	host := authorityHost(value)
	if host == "" {
		return nil
	}
	if full := authority(value); full != host {
		return []string{host, full}
	}
	return []string{host}
}

// shellProofWords in internal/mcp/policy is the quote-aware reader the policy
// package already uses, and it is not exported. This splitter is the
// best-effort reader for destination extraction only: it removes quotes and
// simple escapes, decodes $'...' and $"..." the way bash does, and keeps
// operators as their own words. It does not expand variables or
// here-strings. shellDestinationURLsAt reparses -c and eval scripts and the
// bodies of $(...) and backtick substitutions.

func splitShellWords(source string) ([]string, bool) {
	if !utf8.ValidString(source) {
		return nil, false
	}
	var words []string
	var b strings.Builder
	flush := func() {
		if b.Len() == 0 {
			return
		}
		words = append(words, b.String())
		b.Reset()
	}
	for i := 0; i < len(source); {
		c := source[i]
		switch c {
		case ' ', '\t':
			flush()
			i++
			continue
		case '\n':
			flush()
			words = append(words, "\n")
			i++
			continue
		case '$':
			// $'...' (ANSI-C) and $"..." (locale) quoting. Reading them as
			// plain quotes leaves "$" on the word. Decode them so the bytes
			// the shell runs are the bytes the destination scan sees, and so
			// one such quote does not abandon the rest of the command.
			if i+1 < len(source) && (source[i+1] == '\'' || source[i+1] == '"') {
				var next int
				var quoted bool
				if source[i+1] == '\'' {
					next, quoted = consumeANSIQuoted(&b, source, i+2)
				} else {
					next, quoted = consumeDoubleQuoted(&b, source, i+2)
				}
				if !quoted {
					return nil, false
				}
				i = next
				continue
			}
		case '#':
			if b.Len() == 0 {
				for i < len(source) && source[i] != '\n' {
					i++
				}
				continue
			}
		case '\'':
			i++
			closed := false
			for i < len(source) {
				if source[i] == '\'' {
					closed = true
					i++
					break
				}
				b.WriteByte(source[i])
				i++
			}
			if !closed {
				return nil, false
			}
			continue
		case '"':
			next, quoted := consumeDoubleQuoted(&b, source, i+1)
			if !quoted {
				return nil, false
			}
			i = next
			continue
		case '\\':
			if i+1 >= len(source) {
				return nil, false
			}
			if source[i+1] == '\n' {
				// Line continuation (POSIX 2.2.1): the pair is removed and the
				// word continues on the next line.
				i += 2
				continue
			}
			b.WriteByte(source[i+1])
			i += 2
			continue
		}
		if strings.ContainsRune(";|&()<>", rune(c)) {
			flush()
			if i+1 < len(source) && source[i+1] == c && strings.ContainsRune(";|&<>", rune(c)) {
				words = append(words, source[i:i+2])
				i += 2
				continue
			}
			words = append(words, source[i:i+1])
			i++
			continue
		}
		b.WriteByte(c)
		i++
	}
	flush()
	return words, true
}

// consumeDoubleQuoted reads a double-quoted word starting at the first byte
// inside the quotes. Bash $"..." locale quotes use these same rules when the
// string is not translated (bash(1) "Translating Strings").
func consumeDoubleQuoted(b *strings.Builder, source string, i int) (int, bool) {
	for i < len(source) {
		if source[i] == '\\' && i+1 < len(source) {
			n := source[i+1]
			if n == '\n' {
				// Backslash-newline is a line continuation: both bytes go.
				i += 2
				continue
			}
			if n == '$' || n == '`' || n == '"' || n == '\\' {
				b.WriteByte(n)
				i += 2
				continue
			}
		}
		if source[i] == '"' {
			return i + 1, true
		}
		b.WriteByte(source[i])
		i++
	}
	return 0, false
}

// consumeANSIQuoted reads a bash $'...' word starting at the first byte
// inside the quotes. The escapes are the bash(1) "ANSI-C Quoting" list.
// Bash 5.3 also accepts \x{hex} with any number of digits and an optional
// closing brace, and keeps the low eight bits (verified on bash 5.3.20).
// A decoded zero byte ends the quoted text: the shell stores no NUL, and
// bytes after it inside the quotes are dropped. \x{ with no hex digits
// drops the rest of the quoted text the same way.
func consumeANSIQuoted(b *strings.Builder, source string, i int) (int, bool) {
	for i < len(source) {
		c := source[i]
		if c == '\'' {
			return i + 1, true
		}
		if c != '\\' {
			b.WriteByte(c)
			i++
			continue
		}
		if i+1 >= len(source) {
			return 0, false
		}
		n := source[i+1]
		switch n {
		case 'a':
			b.WriteByte(0x07)
			i += 2
		case 'b':
			b.WriteByte(0x08)
			i += 2
		case 'e', 'E':
			b.WriteByte(0x1b)
			i += 2
		case 'f':
			b.WriteByte(0x0c)
			i += 2
		case 'n':
			b.WriteByte('\n')
			i += 2
		case 'r':
			b.WriteByte('\r')
			i += 2
		case 't':
			b.WriteByte('\t')
			i += 2
		case 'v':
			b.WriteByte(0x0b)
			i += 2
		case '\\', '\'', '"', '?':
			b.WriteByte(n)
			i += 2
		case 'c':
			if i+2 >= len(source) || source[i+2] == '\'' {
				b.WriteByte('\\')
				b.WriteByte('c')
				i += 2
				continue
			}
			// bash TOCTRL: ? is DEL; anything else keeps its low five bits.
			ctrl := source[i+2] & 0x1f
			if source[i+2] == '?' {
				ctrl = 0x7f
			}
			i += 3
			// A backslash target lexically escapes the byte after it, the
			// way bash finds the closing quote before decoding: \c\\ is
			// control-backslash with both backslashes consumed, and in \c\'
			// the quote is a literal byte, not the closer.
			escaped := byte(0)
			if source[i-1] == '\\' && i < len(source) && (source[i] == '\\' || source[i] == '\'') {
				if source[i] == '\'' {
					escaped = '\''
				}
				i++
			}
			if ctrl == 0 {
				return skipANSIRest(source, i)
			}
			b.WriteByte(ctrl)
			if escaped != 0 {
				b.WriteByte(escaped)
			}
		case 'x':
			next, ok, closed := appendANSIHex(b, source, i+2)
			if !ok || closed {
				// A zero byte from \x ends the quoted text: appendANSIHex has
				// already skipped past the closing quote.
				return next, ok
			}
			i = next
		case 'u', 'U':
			maxDigits := 4
			if n == 'U' {
				maxDigits = 8
			}
			val, digits, next := readHex(source, i+2, maxDigits)
			if digits == 0 {
				b.WriteByte('\\')
				b.WriteByte(n)
				i += 2
				continue
			}
			i = next
			if val == 0 {
				return skipANSIRest(source, i)
			}
			appendCodepoint(b, val)
		default:
			if n < '0' || n > '7' {
				b.WriteByte('\\')
				b.WriteByte(n)
				i += 2
				continue
			}
			val, next := readOctal(source, i+1)
			i = next
			if val&0xFF == 0 {
				return skipANSIRest(source, i)
			}
			b.WriteByte(byte(val & 0xFF))
		}
	}
	return 0, false
}

// appendANSIHex reads a \x escape whose introduction has already been
// consumed. i is the first byte after "\x". closed reports that the escape
// was a zero byte, which ends the quoted text: next is then past the
// closing quote and the caller must stop reading the quote.
func appendANSIHex(b *strings.Builder, source string, i int) (next int, ok, closed bool) {
	if i < len(source) && source[i] == '{' {
		val, digits, after := readHex(source, i+1, 0)
		i = after
		if digits == 0 {
			next, ok = skipANSIRest(source, i)
			return next, ok, true
		}
		if i < len(source) && source[i] == '}' {
			i++
		}
		if val&0xFF == 0 {
			next, ok = skipANSIRest(source, i)
			return next, ok, true
		}
		b.WriteByte(byte(val & 0xFF))
		return i, true, false
	}
	val, digits, after := readHex(source, i, 2)
	if digits == 0 {
		b.WriteByte('\\')
		b.WriteByte('x')
		return i, true, false
	}
	if val&0xFF == 0 {
		next, ok = skipANSIRest(source, after)
		return next, ok, true
	}
	b.WriteByte(byte(val & 0xFF))
	return after, true, false
}

// skipANSIRest drops the rest of an ANSI-C quote after a zero byte, still
// honoring backslash escapes so \' is not the closer.
func skipANSIRest(source string, i int) (int, bool) {
	for i < len(source) {
		if source[i] == '\\' {
			if i+1 >= len(source) {
				return 0, false
			}
			i += 2
			continue
		}
		if source[i] == '\'' {
			return i + 1, true
		}
		i++
	}
	return 0, false
}

// readHex reads up to limit hex digits, or any number when limit is 0. The
// value keeps only the low eight bits when limit is 0, which is what \x{...}
// stores.
func readHex(source string, i, limit int) (val uint32, digits, next int) {
	for limit <= 0 || digits < limit {
		if i >= len(source) {
			break
		}
		d, ok := hexDigit(source[i])
		if !ok {
			break
		}
		if limit <= 0 {
			val = ((val << 4) | d) & 0xFF
		} else {
			val = (val << 4) | d
		}
		i++
		digits++
	}
	return val, digits, i
}

func readOctal(source string, i int) (val uint32, next int) {
	for n := 0; n < 3 && i < len(source); n++ {
		c := source[i]
		if c < '0' || c > '7' {
			break
		}
		val = (val << 3) | uint32(c-'0')
		i++
	}
	return val, i
}

func hexDigit(c byte) (uint32, bool) {
	switch {
	case c >= '0' && c <= '9':
		return uint32(c - '0'), true
	case c >= 'a' && c <= 'f':
		return uint32(c-'a') + 10, true
	case c >= 'A' && c <= 'F':
		return uint32(c-'A') + 10, true
	default:
		return 0, false
	}
}

// appendCodepoint writes cp the way bash writes a \u or \U escape, including
// a surrogate as its UTF-8 bytes rather than a replacement character.
func appendCodepoint(b *strings.Builder, cp uint32) {
	switch {
	case cp <= 0x7F:
		b.WriteByte(byte(cp))
	case cp <= 0x7FF:
		b.WriteByte(0xC0 | byte(cp>>6))
		b.WriteByte(0x80 | byte(cp&0x3F))
	case cp <= 0xFFFF:
		b.WriteByte(0xE0 | byte(cp>>12))
		b.WriteByte(0x80 | byte((cp>>6)&0x3F))
		b.WriteByte(0x80 | byte(cp&0x3F))
	default:
		b.WriteByte(0xF0 | byte((cp>>18)&0x07))
		b.WriteByte(0x80 | byte((cp>>12)&0x3F))
		b.WriteByte(0x80 | byte((cp>>6)&0x3F))
		b.WriteByte(0x80 | byte(cp&0x3F))
	}
}

// maxNestedShellDepth bounds how many script layers (bash -c "sh -c '...'")
// are reparsed. Each layer is a quoted word inside the one above, so real
// commands rarely pass two.
const maxNestedShellDepth = 4

// scriptRunners are programs whose -c option (alone or in a short-option
// cluster such as -lc or -xc) takes a whole shell script as its value.
// commandBase strips any directory, so /bin/sh and /usr/bin/env bash work.
var scriptRunners = map[string]bool{
	"ash": true, "bash": true, "busybox": true, "csh": true, "dash": true,
	"fish": true, "ksh": true, "mksh": true, "rbash": true, "runuser": true,
	"sh": true, "su": true, "tcsh": true, "yash": true, "zsh": true,
}

func shellDestinationURLs(command string) (urls []string, over bool) {
	return shellDestinationURLsAt(command, nil, make(map[string]struct{}), 0)
}

func shellDestinationURLsAt(command string, urls []string, seen map[string]struct{}, depth int) ([]string, bool) {
	var over bool
	words, ok := splitShellWords(command)
	if !ok {
		// The structure is not reliable (an unclosed quote, a trailing
		// backslash). Still take explicit scheme URLs from the raw text,
		// and any cloud-metadata address literal anywhere in it, without
		// guessing other bare hosts.
		// Quote characters and backslashes are removed for a second look,
		// so 169.254.'169'.254 still reads as the address the shell joins.
		texts := []string{command, rawQuoteStripper.Replace(command)}
		urls, over = appendSchemeURLs(urls, seen, texts)
		if over {
			return nil, true
		}
		for _, host := range append(rawMetadataLiterals(texts[0]), rawMetadataLiterals(texts[1])...) {
			if urls, over = addDestination(urls, seen, "http://"+host); over {
				return nil, true
			}
		}
		// The substitution reader follows here-documents and comments the
		// word splitter does not, so a quote inside one does not hide them.
		return reparseScripts(commandSubstitutions(command), urls, seen, depth)
	}
	urls, over = appendSchemeURLs(urls, seen, words)
	if over {
		return nil, true
	}
	if urls, over = appendCurlWgetHosts(urls, seen, words); over {
		return nil, true
	}
	// A script passed to a shell's -c or to eval is one quoted word here,
	// so a bare host inside it never reached the curl/wget scan above.
	// Reparse those scripts. Only recognised script-execution forms are
	// reparsed; an ordinary quoted argument (a commit message, an echo) is
	// left alone. Past the depth limit, deny rather than stop looking.
	// Command substitutions run their body even inside double quotes
	// ("$(curl ...)") or as an assignment value, where the body is part of
	// one word. Backticks are never split from their first word at all.
	return reparseScripts(append(nestedScripts(words), commandSubstitutions(command)...), urls, seen, depth)
}

// reparseScripts scans each nested script one level down. Past the depth
// limit it denies rather than stops looking.
func reparseScripts(scripts, urls []string, seen map[string]struct{}, depth int) ([]string, bool) {
	var over bool
	for _, script := range scripts {
		if depth+1 >= maxNestedShellDepth {
			return nil, true
		}
		if urls, over = shellDestinationURLsAt(script, urls, seen, depth+1); over {
			return nil, true
		}
	}
	return urls, false
}

// commandSubstitutions returns the body of each $(...) and backtick
// substitution bash would execute in source: those outside quotes, inside
// double quotes and inside here-documents, but not text inside single
// quotes, $'...' or comments. A nested substitution stays in its parent's
// body for the next reparse.
//
// Where the reading is uncertain it scans more text, never less: a quote
// that never closes is read as unquoted, a body left open runs to the end,
// and a case pattern's ) inside a $(...) body does not end it. Quoted
// here-document bodies are scanned too: << inside ${...} or arithmetic
// can look like a quoted here-document that would hide the lines after it.
func commandSubstitutions(source string) []string {
	s := substitutionScanner{src: source, collect: true}
	s.scan(0, false, false)
	return s.bodies
}

type substitutionScanner struct {
	src     string
	bodies  []string
	collect bool
}

type pendingHereDoc struct {
	delim string
	strip bool
}

// shellWordBreaks are the bytes after which a new shell word starts.
const shellWordBreaks = " \t\n;|&()<>"

// parenFrame is one open parenthesis inside a $(...) body: the
// double-quote state outside it, and the case statements open inside it.
// pattern is true where a case pattern is being read, so its ) closes the
// pattern rather than the parenthesis.
type parenFrame struct {
	outerDouble bool
	cases       int
	pattern     bool
	// head is true between case and its in. The first word there is the
	// subject, which may itself be esac or in; headWords counts them.
	head      bool
	headWords int
}

// scan walks s.src from i. With untilParen it returns the index of the )
// that closes a $( whose body starts at i, or len(s.src) when none does.
// In hereText mode the text is a here-document body, where only \, ` and
// $( are special.
//
// case is read as the keyword only in command position. When a word case
// was passed over for that reason alone, the end is also found with case
// read at any word start, and the later of the two ends is kept: command
// position is tracked approximately, and a body is never cut shorter than
// the permissive reading.
func (s *substitutionScanner) scan(i int, untilParen, hereText bool) int {
	end, rejected := s.scanBody(i, untilParen, hereText, false)
	if untilParen && rejected {
		end = max(end, s.scanBodyQuiet(i))
	}
	return end
}

// scanBodyQuiet finds a $( body's end with case read at any word start,
// without collecting bodies.
func (s *substitutionScanner) scanBodyQuiet(i int) int {
	inner := substitutionScanner{src: s.src}
	end, _ := inner.scanBody(i, true, false, true)
	return end
}

func (s *substitutionScanner) scanBody(i int, untilParen, hereText, anyCase bool) (end int, rejectedCase bool) {
	src := s.src
	inDouble := false
	frames := []parenFrame{{}}
	// lastPattern is the last ) read as a case pattern's close at the top
	// level. When no ) closes the body, the body ends there instead: case
	// is matched at any word start, so a word "case" that is only an
	// argument would otherwise run the body to the end of the text.
	lastPattern := -1
	var pending []pendingHereDoc
	// atWordStart is true when no byte of a new shell word has been read:
	// at the start and after an unescaped, unquoted blank or operator. An
	// escaped blank, a quote or a substitution's closing ) does not start
	// a word, so a # after them is not a comment. cmdPos is true where a
	// command may start, which is where esac can close a case arm.
	atWordStart, cmdPos := true, true
	for ; i < len(src); i++ {
		c := src[i]
		wordStart, atCmd := atWordStart, cmdPos
		atWordStart = !inDouble && !hereText && strings.IndexByte(shellWordBreaks, c) >= 0
		if !inDouble && !hereText && c != ' ' && c != '\t' {
			cmdPos = strings.IndexByte(";&|\n(", c) >= 0
		}
		top := &frames[len(frames)-1]
		if wordStart && top.head && strings.IndexByte(" \t\n", c) < 0 {
			// Counted before the switch so a subject starting with $(, a
			// quote or a backslash counts too. The first in after the
			// subject ends the head.
			if top.headWords > 0 && shellKeywordAt(src, i, "in") {
				top.head, top.pattern = false, true
			}
			top.headWords++
		}
		switch {
		case c == '\\':
			i++
		case c == '`':
			body, next := backtickBody(src, i+1, inDouble)
			s.add(body)
			i = next - 1
		case c == '$' && i+1 < len(src) && src[i+1] == '(':
			if untilParen {
				// Track it as a parenthesis; the body is read on its own
				// when the enclosing body is reparsed.
				frames = append(frames, parenFrame{outerDouble: inDouble})
				inDouble = false
				atWordStart, cmdPos = true, true
				i++
				continue
			}
			inner := substitutionScanner{src: src}
			end := inner.scan(i+2, true, false)
			s.add(src[i+2 : end])
			i = end
		case hereText:
		case c == '"':
			inDouble = !inDouble
		case inDouble:
		case c == '\'':
			// A quote that never closes is read as unquoted.
			if end := strings.IndexByte(src[i+1:], '\''); end >= 0 {
				i += end + 1
			}
		case c == '$' && i+1 < len(src) && src[i+1] == '\'':
			if end, ok := ansiQuoteEnd(src, i+2); ok {
				i = end
			}
		case c == '#' && wordStart:
			for i+1 < len(src) && src[i+1] != '\n' {
				i++
			}
		case c == '<' && strings.HasPrefix(src[i:], "<<") && !strings.HasPrefix(src[i:], "<<<"):
			doc, next := readHereDocWord(src, i+2)
			if doc.delim != "" {
				// Read by hereDocBodies at the next unquoted newline.
				pending = append(pending, doc)
			}
			i = next - 1
		case c == '\n' && len(pending) > 0:
			i = s.hereDocBodies(i+1, pending) - 1
			pending = nil
		case !untilParen:
		case c == '(':
			frames = append(frames, parenFrame{})
		case c == ')' && top.cases > 0 && top.pattern:
			top.pattern = false
			cmdPos = true
			if len(frames) == 1 {
				lastPattern = i
			}
		case c == ')':
			if len(frames) == 1 {
				return i, rejectedCase
			}
			inDouble = top.outerDouble
			frames = frames[:len(frames)-1]
			// The () of a function definition is followed by its body,
			// which may be a case statement.
			cmdPos = src[i-1] == '('
		case c == ';' && i+1 < len(src) && (src[i+1] == ';' || src[i+1] == '&'):
			// ;; ;& and ;;& end a case arm; a pattern follows.
			if top.cases > 0 {
				top.pattern = true
			}
		case wordStart && atCmd && reservedPrefixAt(src, i) > 0:
			// then, do, else and the like keep the next word in command
			// position, so a case after them is still the keyword.
			i += reservedPrefixAt(src, i) - 1
			cmdPos = true
		case wordStart && shellKeywordAt(src, i, "case"):
			if atCmd || anyCase {
				top.cases++
				top.head, top.headWords, top.pattern = true, 0, false
			} else {
				rejectedCase = true
			}
		case wordStart && top.cases > 0 && !top.head && (top.pattern || atCmd) && shellKeywordAt(src, i, "esac"):
			top.cases--
			top.pattern = false
		}
	}
	if lastPattern >= 0 {
		return lastPattern, rejectedCase
	}
	return len(src), rejectedCase
}

func (s *substitutionScanner) add(body string) {
	if s.collect {
		s.bodies = append(s.bodies, body)
	}
}

// hereDocBodies reads the bodies of the pending here-documents, one after
// another, starting at i, the byte after the newline that ends the command
// line. It returns the index after the last delimiter line. A body with no
// closing delimiter runs to the end of the text.
func (s *substitutionScanner) hereDocBodies(i int, pending []pendingHereDoc) int {
	src := s.src
	for _, doc := range pending {
		start := i
		end := len(src)
		for i < len(src) {
			lineEnd := strings.IndexByte(src[i:], '\n')
			next := len(src)
			if lineEnd >= 0 {
				lineEnd += i
				next = lineEnd + 1
			} else {
				lineEnd = len(src)
			}
			line := src[i:lineEnd]
			if doc.strip {
				line = strings.TrimLeft(line, "\t")
			}
			if line == doc.delim {
				end = i
				i = next
				break
			}
			i = next
		}
		if s.collect {
			inner := substitutionScanner{src: src[start:end], collect: true}
			inner.scan(0, false, true)
			s.bodies = append(s.bodies, inner.bodies...)
		}
	}
	return i
}

// readHereDocWord reads the delimiter after << (and an optional -). The
// delimiter is the word with its quotes removed (bash(1) "Here Documents").
// Quoting would make the body literal, but it is scanned anyway; see
// commandSubstitutions.
func readHereDocWord(src string, i int) (doc pendingHereDoc, next int) {
	if i < len(src) && src[i] == '-' {
		doc.strip = true
		i++
	}
	for i < len(src) && (src[i] == ' ' || src[i] == '\t') {
		i++
	}
	var b strings.Builder
	for i < len(src) && strings.IndexByte(shellWordBreaks, src[i]) < 0 {
		switch c := src[i]; c {
		case '\'', '"':
			end := strings.IndexByte(src[i+1:], c)
			if end < 0 {
				return pendingHereDoc{}, len(src)
			}
			b.WriteString(src[i+1 : i+1+end])
			i += end + 2
		case '\\':
			if i+1 < len(src) {
				b.WriteByte(src[i+1])
			}
			i += 2
		default:
			b.WriteByte(c)
			i++
		}
	}
	doc.delim = b.String()
	return doc, min(i, len(src))
}

// ansiQuoteEnd returns the index of the quote closing a $'...' body that
// starts at i.
func ansiQuoteEnd(src string, i int) (int, bool) {
	for ; i < len(src); i++ {
		switch src[i] {
		case '\\':
			i++
		case '\'':
			return i, true
		}
	}
	return 0, false
}

// commandPrefixWords are the reserved words after which a command, and so
// a case keyword, may follow (bash(1) "Reserved Words").
var commandPrefixWords = []string{"then", "do", "else", "elif", "if", "while", "until", "!", "{", "time", "coproc"}

// reservedPrefixAt returns the length of the commandPrefixWords entry that
// starts at i as a whole word, or 0.
func reservedPrefixAt(src string, i int) int {
	for _, w := range commandPrefixWords {
		if shellKeywordAt(src, i, w) {
			return len(w)
		}
	}
	return 0
}

func shellKeywordAt(src string, i int, keyword string) bool {
	end := i + len(keyword)
	return strings.HasPrefix(src[i:], keyword) &&
		(end == len(src) || strings.IndexByte(shellWordBreaks, src[end]) >= 0)
}

// backtickBody reads a backtick substitution from the first byte after the
// opening backtick. Inside it a backslash is removed only before $, ` or \
// (bash(1) "Command Substitution"), which is how nested backticks are written.
// Inside double quotes bash also removes it before ", as a differential run
// against bash 5.3.20 shows: "`bash -c \"curl ...\"`" runs bash -c "curl ...".
func backtickBody(source string, i int, inDouble bool) (body string, next int) {
	escapable := "$`\\"
	if inDouble {
		escapable += `"`
	}
	var b strings.Builder
	for ; i < len(source); i++ {
		c := source[i]
		if c == '`' {
			return b.String(), i + 1
		}
		if c == '\\' && i+1 < len(source) && strings.IndexByte(escapable, source[i+1]) >= 0 {
			i++
			c = source[i]
		}
		b.WriteByte(c)
	}
	return b.String(), i
}

// nestedScripts returns the script text each recognised script-execution
// form in words runs: the value of a -c option cluster after a shell or su,
// and the arguments of eval joined the way eval joins them.
func nestedScripts(words []string) []string {
	var scripts []string
	for i := 0; i < len(words); i++ {
		base := commandBase(words[i])
		switch {
		case base == "eval":
			j := i + 1
			for j < len(words) && !isShellOperator(words[j]) {
				j++
			}
			if j > i+1 {
				scripts = append(scripts, strings.Join(words[i+1:j], " "))
			}
			i = j - 1
		case scriptRunners[base]:
			// Look past other options and operands (su USER -c, bash -o
			// pipefail -c) for the first short-option cluster holding c.
			for j := i + 1; j < len(words) && !isShellOperator(words[j]); j++ {
				if shortClusterHasC(words[j]) {
					if j+1 < len(words) && !isShellOperator(words[j+1]) {
						scripts = append(scripts, words[j+1])
					}
					break
				}
			}
		}
	}
	return scripts
}

// shortClusterHasC reports whether word is a single-dash (or plus) short
// option cluster containing c. Reading any such cluster as -c over-marks
// at worst, which only scans more text.
func shortClusterHasC(word string) bool {
	if len(word) < 2 || strings.HasPrefix(word, "--") || (word[0] != '-' && word[0] != '+') {
		return false
	}
	return strings.ContainsRune(word[1:], 'c')
}

func appendSchemeURLs(urls []string, seen map[string]struct{}, words []string) ([]string, bool) {
	for _, word := range words {
		for _, loc := range schemeURLRe.FindAllStringIndex(word, -1) {
			match := word[loc[0]:loc[1]]
			var over bool
			urls, over = addDestination(urls, seen, strings.TrimRight(match, ".,);"))
			if over {
				return nil, true
			}
			// The regex stops at a quote, backslash or angle bracket that
			// quoting kept inside the word, which can end the match inside
			// the userinfo: 'http://a.example<x@169.254.169.254/' connects
			// to 169.254.169.254. Scan the authority curl would read too.
			full := word[loc[0]:]
			if i := strings.IndexAny(full, " \t\n"); i >= 0 {
				full = full[:i]
			}
			if h := authorityHost(full); h != "" && h != authorityHost(match) {
				if urls, over = addDestination(urls, seen, "http://"+h); over {
					return nil, true
				}
			}
		}
	}
	return urls, false
}

func addDestination(urls []string, seen map[string]struct{}, raw string) ([]string, bool) {
	if raw == "" {
		return urls, false
	}
	if _, ok := seen[raw]; ok {
		return urls, false
	}
	if len(urls) == maxShellDestinationURLs {
		return nil, true
	}
	seen[raw] = struct{}{}
	return append(urls, raw), false
}

// appendCurlWgetHosts adds http:// in front of a curl or wget positional
// operand that is a single host[:port][/path] word. Option values are not
// operands. An option this table does not know makes the following word
// ineligible, because it might be that option's value.
func appendCurlWgetHosts(urls []string, seen map[string]struct{}, words []string) ([]string, bool) {
	tool := ""
	optionsDone := false
	skipBare := false
	ambiguous := false
	destNext := "" // curl destination option whose value is the next word
	add := func(word string) bool {
		var over bool
		urls, over = addDestination(urls, seen, "http://"+word)
		return over
	}
	addValue := func(opt, value string) bool {
		for _, dest := range curlDestinationTargets(opt, value) {
			if add(dest) {
				return true
			}
		}
		return false
	}
	for _, word := range words {
		if isShellOperator(word) {
			tool = ""
			optionsDone = false
			skipBare, ambiguous, destNext = false, false, ""
			continue
		}
		if tool == "" {
			if base := commandBase(word); base == "curl" || base == "wget" {
				tool = base
				optionsDone = false
				skipBare, ambiguous, destNext = false, false, ""
			}
			continue
		}
		if destNext != "" {
			opt := destNext
			destNext = ""
			if addValue(opt, word) {
				return nil, true
			}
			continue
		}
		carry := false
		if skipBare {
			wasAmbiguous := ambiguous
			skipBare, ambiguous = false, false
			// After an option this table does not know, an option word is the
			// next option, not that option's value: let option handling below
			// see it (so --url=... and -- still work). Otherwise the word may
			// be the value or the URL. A literal IP is scanned either way (a
			// file named like an address is not worth the miss); a hostname is
			// left alone to avoid treating values as hosts.
			// A word with a scheme or userinfo is a destination whichever
			// way the unknown option reads it: the scheme and userinfo
			// branches below add only hosts curl would connect to.
			urlLike := wasAmbiguous && !isOptionWord(word) && (hasLeadingScheme(word) || strings.Contains(word, "@"))
			if !urlLike && (!wasAmbiguous || !isOptionWord(word)) {
				if wasAmbiguous && looksLikeHostOperand(word) && scanner.ParseIPLiteral(operandHost(word)) != nil && add(word) {
					return nil, true
				}
				continue
			}
			carry = !urlLike
		}
		if !optionsDone && isOptionWord(word) {
			if tool == "curl" {
				if opt, value, attached, ok := curlDestinationOption(word); ok {
					if !attached {
						destNext = opt
						continue
					}
					if addValue(opt, value) {
						return nil, true
					}
					continue
				}
			}
			skipBare, ambiguous, optionsDone = consumeFetchOption(tool, word)
			// The unknown option before this one might take this word as
			// its value, which makes the next word the URL: keep the
			// literal-IP check alive for it.
			if carry && skipBare {
				ambiguous = true
			}
			continue
		}
		if hasLeadingScheme(word) {
			// http(s) and ws(s) URLs are taken whole by the URL regex. Any
			// other scheme curl or wget speaks (gopher, ftp, dict, ...)
			// still connects somewhere: scan that host.
			if !webScheme(word) {
				for _, a := range scannedAuthorities(word) {
					if add(a) {
						return nil, true
					}
				}
			}
			continue
		}
		if strings.Contains(word, "@") {
			// user[:pass]@host[:port][/path]: curl connects to the host after
			// the userinfo, so scan that host.
			if looksLikeHostOperand(authorityHost(word)) {
				for _, a := range scannedAuthorities(word) {
					if add(a) {
						return nil, true
					}
				}
			}
			continue
		}
		if !looksLikeHostOperand(word) {
			continue
		}
		if add(word) {
			return nil, true
		}
	}
	return urls, false
}

// rawQuoteStripper removes shell quoting characters from raw text the word
// splitter could not read. ANSI-C and locale quote openers go first so their
// "$" does not stay behind as a separator.
var rawQuoteStripper = strings.NewReplacer("$'", "", "$\"", "", "'", "", "\"", "", "\\", "")

// rawMetadataLiterals returns every cloud-metadata address literal in text,
// in any spelling ParseIPLiteral accepts, bracketed when IPv6. It is the
// fallback when the command cannot be split into words.
func rawMetadataLiterals(text string) []string {
	var out []string
	seen := make(map[string]struct{})
	fields := strings.FieldsFunc(text, func(r rune) bool { return !ipLiteralRune(r) })
	for _, field := range fields {
		candidates := []string{field, strings.Trim(field, "[]")}
		if h, _, err := net.SplitHostPort(field); err == nil {
			candidates = append(candidates, h)
		}
		for _, c := range candidates {
			ip := scanner.ParseIPLiteral(c)
			if ip == nil || !scanner.IsCloudMetadataIP(ip) {
				continue
			}
			host := bracketHost(ip.String())
			if _, dup := seen[host]; !dup {
				seen[host] = struct{}{}
				out = append(out, host)
			}
			break
		}
	}
	return out
}

// ipLiteralRune reports whether r can appear in an IP literal in any spelling
// ParseIPLiteral accepts: decimal, octal or hex IPv4 parts, IPv6 with
// brackets, a port separator or a zone.
func ipLiteralRune(r rune) bool {
	switch {
	case r >= '0' && r <= '9', r >= 'a' && r <= 'f', r >= 'A' && r <= 'F':
		return true
	}
	return strings.ContainsRune("xX.:[]%", r)
}

// curlDestinationLongOpts are curl options whose value names a network
// destination the request will reach: the URL itself, a proxy, or an address
// that overrides where a host connects (curl(1): --url, --proxy, --preproxy,
// --proxy1.0, --socks4, --socks4a, --socks5, --socks5-hostname, --resolve,
// --connect-to). Their values are scanned instead of skipped.
var curlDestinationLongOpts = optSet(
	"url", "proxy", "preproxy", "proxy1.0", "socks4", "socks4a", "socks5", "socks5-hostname", "resolve", "connect-to",
)

// curlDestinationOption reports whether word is a curl destination option.
// It returns the canonical option name and, when the value is attached to the
// word (--opt=value, -xvalue), that value.
func curlDestinationOption(word string) (opt, value string, attached, ok bool) {
	if rest, isLong := strings.CutPrefix(word, "--"); isLong {
		name, v, hasValue := strings.Cut(rest, "=")
		if _, known := curlDestinationLongOpts[name]; !known {
			return "", "", false, false
		}
		return name, v, hasValue, true
	}
	// Short form: -x is --proxy. It may end a cluster of booleans (-sSx, value
	// next) or carry its value glued (-xhost:3128, -sxhost:3128).
	cluster := word[1:]
	for i := 0; i < len(cluster); i++ {
		letter := cluster[i : i+1]
		if letter == "x" {
			if i+1 == len(cluster) {
				return "proxy", "", false, true
			}
			return "proxy", cluster[i+1:], true, true
		}
		if takes, known := fetchOption("curl", letter); !known || takes {
			return "", "", false, false
		}
	}
	return "", "", false, false
}

// curlDestinationTargets returns the host[:port] targets named by a curl
// destination option value, bracketing IPv6 literals.
func curlDestinationTargets(opt, value string) []string {
	switch opt {
	case "url":
		// The value is the URL by definition, so a single-label host counts
		// too. Only a scheme at the start makes it a scheme URL: http(s) and
		// ws(s) URLs are taken whole by the URL regex, and any other scheme
		// still names a host to scan.
		if value == "" {
			return nil
		}
		if hasLeadingScheme(value) {
			if webScheme(value) {
				return nil
			}
			return scannedAuthorities(value)
		}
		return []string{value}
	case "resolve":
		// [+]HOST:PORT:ADDRESS[,ADDRESS]...
		value = strings.TrimPrefix(value, "+")
		rest, ok := cutHostPortPrefix(value)
		if !ok {
			return nil
		}
		var out []string
		for _, addr := range strings.Split(rest, ",") {
			if t := bracketHost(addr); t != "" {
				out = append(out, t)
			}
		}
		return out
	case "connect-to":
		// HOST1:PORT1:HOST2:PORT2; an empty HOST2 keeps the original host.
		rest, ok := cutHostPortPrefix(value)
		if !ok {
			return nil
		}
		host2, port2 := rest, ""
		if strings.HasPrefix(rest, "[") {
			if end := strings.IndexByte(rest, ']'); end > 0 {
				host2, port2 = rest[:end+1], strings.TrimPrefix(rest[end+1:], ":")
			}
		} else if i := strings.LastIndexByte(rest, ':'); i >= 0 {
			host2, port2 = rest[:i], rest[i+1:]
		}
		t := bracketHost(host2)
		if t == "" {
			return nil
		}
		if port2 != "" {
			t += ":" + port2
		}
		return []string{t}
	default:
		// Proxy forms: [scheme://][user:pass@]host[:port][/...]. Cut the
		// authority at the first "/?#" before looking for userinfo, the way
		// curl's URL parser does, so "host/@other" names host, not other.
		// The value is a destination by definition: any non-empty host is
		// emitted (single labels included) and the scan decides; a value
		// that is not a valid host fails there instead of being skipped.
		// Userinfo stays in the scanned value for the credential checks.
		return scannedAuthorities(value)
	}
}

// cutHostPortPrefix splits "HOST:PORT:rest" (HOST may be a bracketed IPv6
// literal or *) and returns the remainder after the second colon.
func cutHostPortPrefix(value string) (rest string, ok bool) {
	start := 0
	if strings.HasPrefix(value, "[") {
		end := strings.IndexByte(value, ']')
		if end < 0 {
			return "", false
		}
		start = end + 1
	}
	first := strings.IndexByte(value[start:], ':')
	if first < 0 {
		return "", false
	}
	first += start
	second := strings.IndexByte(value[first+1:], ':')
	if second < 0 {
		return "", false
	}
	second += first + 1
	return value[second+1:], true
}

// bracketHost returns host ready for a host[:port] operand: IPv6 literals in
// brackets, other non-empty hosts unchanged.
func bracketHost(host string) string {
	host = strings.TrimSpace(host)
	if host == "" {
		return ""
	}
	if strings.HasPrefix(host, "[") {
		return host
	}
	if strings.Contains(host, ":") {
		return "[" + host + "]"
	}
	return host
}

// operandHost returns the host part of a bare host[:port][/path] operand,
// without brackets or port, for the literal-IP check.
func operandHost(word string) string {
	host := word
	if i := strings.IndexByte(host, '/'); i >= 0 {
		host = host[:i]
	}
	if strings.HasPrefix(host, "[") {
		if end := strings.IndexByte(host, ']'); end > 0 {
			return host[1:end]
		}
		return host
	}
	if h, _, err := net.SplitHostPort(host); err == nil {
		return h
	}
	return host
}

func isShellOperator(word string) bool {
	switch word {
	case ";", "|", "||", "&", "&&", "(", ")", "<", ">", ">>", "\n":
		return true
	default:
		return false
	}
}

func commandBase(word string) string {
	word = strings.TrimSuffix(word, "/")
	if i := strings.LastIndex(word, "/"); i >= 0 {
		return word[i+1:]
	}
	return word
}

func isOptionWord(word string) bool {
	return word == "--" || (strings.HasPrefix(word, "-") && len(word) > 1)
}

// consumeFetchOption reports whether the next word may be that option's value
// (and therefore not a plain URL operand), whether that is only a guess because
// the option is not in the table (ambiguous), and whether options have ended
// (`--`).
func consumeFetchOption(tool, word string) (skipNextBare, ambiguous, optionsDone bool) {
	if word == "--" {
		return false, false, true
	}
	if strings.HasPrefix(word, "--") {
		name, _, attached := strings.Cut(word[2:], "=")
		takes, known := fetchOption(tool, name)
		if !known {
			return !attached, !attached, false
		}
		return takes && !attached, false, false
	}
	if tool == "wget" && (word == "-nv" || word == "-nc") {
		return false, false, false
	}
	cluster := word[1:]
	for i := 0; i < len(cluster); i++ {
		takes, known := fetchOption(tool, cluster[i:i+1])
		if !known {
			return true, true, false
		}
		if takes {
			return i+1 == len(cluster), false, false
		}
	}
	return false, false, false
}

func fetchOption(tool, name string) (takesValue, known bool) {
	switch tool {
	case "curl":
		if _, ok := curlValueOpts[name]; ok {
			return true, true
		}
		if _, ok := curlFlagOpts[name]; ok {
			return false, true
		}
	case "wget":
		if _, ok := wgetValueOpts[name]; ok {
			return true, true
		}
		if _, ok := wgetFlagOpts[name]; ok {
			return false, true
		}
	}
	return false, false
}

func looksLikeHostOperand(word string) bool {
	if word == "" || strings.HasPrefix(word, "-") || hasLeadingScheme(word) || strings.Contains(word, "@") || strings.ContainsAny(word, " \t") {
		return false
	}
	host := word
	if i := strings.IndexByte(word, '/'); i >= 0 {
		host = word[:i]
	}
	if host == "" {
		return false
	}
	if strings.HasPrefix(host, "[") {
		end := strings.IndexByte(host, ']')
		if end <= 1 {
			return false
		}
		if end == len(host)-1 {
			return true
		}
		return host[end+1] == ':' && validPort(host[end+2:])
	}
	if i := strings.LastIndexByte(host, ':'); i >= 0 {
		if !validPort(host[i+1:]) {
			return false
		}
		host = host[:i]
	}
	host = strings.TrimSuffix(host, ".")
	// curl accepts every IPv4 spelling the URL standard does, including one
	// dotless number (2852039166) and hex or octal parts.
	if scanner.ParseIPLiteral(host) != nil {
		return true
	}
	if !strings.Contains(host, ".") || strings.Contains(host, "..") {
		return false
	}
	for _, label := range strings.Split(host, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, c := range label {
			if (c < 'a' || c > 'z') && (c < 'A' || c > 'Z') && (c < '0' || c > '9') && c != '-' {
				return false
			}
		}
	}
	return true
}

// validPort accepts the port of a bare host operand. An empty port is valid:
// curl reads "host:/path" as the scheme's default port, so it is a real
// destination. Out-of-range digits are accepted too; the scan then decides.
func validPort(port string) bool {
	if port == "" {
		return true
	}
	if len(port) > 5 {
		return false
	}
	for _, c := range port {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

func optSet(names ...string) map[string]struct{} {
	set := make(map[string]struct{}, len(names))
	for _, name := range names {
		set[name] = struct{}{}
	}
	return set
}

// Short names are single letters. Long names omit the leading dashes.
// The lists are the options from curl --help and wget --help that take a
// value, plus the long forms used for the same jobs (--url, --data-raw).
var (
	// curlValueOpts and curlFlagOpts are every option `curl --help all` lists
	// (curl 8.23.0): options shown with an <argument> take a value; the rest are
	// booleans. An option missing from both is treated as possibly taking one.
	curlValueOpts = optSet(
		"A", "C", "D", "E", "F", "H", "K", "P", "Q", "T", "U", "X", "Y", "b", "c", "d", "e", "h", "m", "o", "r", "t", "u",
		"w", "x", "y", "z", "abstract-unix-socket", "alt-svc", "aws-sigv4", "cacert", "capath", "cert", "cert-type",
		"ciphers", "config", "connect-timeout", "connect-to", "continue-at", "cookie", "cookie-jar", "create-file-mode",
		"crlfile", "curves", "data", "data-ascii", "data-binary", "data-raw", "data-urlencode", "delegation",
		"dns-interface", "dns-ipv4-addr", "dns-ipv6-addr", "dns-servers", "doh-url", "dump-header", "ech", "egd-file",
		"engine", "etag-compare", "etag-save", "expect100-timeout", "form", "form-string", "ftp-account",
		"ftp-alternative-to-user", "ftp-method", "ftp-port", "ftp-ssl-ccc-mode", "happy-eyeballs-timeout-ms",
		"haproxy-clientip", "header", "help", "hostpubmd5", "hostpubsha256", "hsts", "interface", "ip-tos", "ipfs-gateway",
		"json", "keepalive-cnt", "keepalive-time", "key", "key-type", "knownhosts", "krb", "libcurl", "limit-rate",
		"local-port", "login-options", "mail-auth", "mail-from", "mail-rcpt", "max-filesize", "max-redirs", "max-time",
		"netrc-file", "noproxy", "oauth2-bearer", "output", "output-dir", "parallel-max", "parallel-max-host", "pass",
		"pinnedpubkey", "preproxy", "proto", "proto-default", "proto-redir", "proxy", "proxy-cacert", "proxy-capath",
		"proxy-cert", "proxy-cert-type", "proxy-ciphers", "proxy-crlfile", "proxy-header", "proxy-key", "proxy-key-type",
		"proxy-pass", "proxy-pinnedpubkey", "proxy-service-name", "proxy-tls13-ciphers", "proxy-tlsauthtype",
		"proxy-tlspassword", "proxy-tlsuser", "proxy-user", "proxy1.0", "pubkey", "quote", "random-file", "range", "rate",
		"referer", "request", "request-target", "resolve", "retry", "retry-delay", "retry-max-time", "sasl-authzid",
		"service-name", "sigalgs", "socks4", "socks4a", "socks5", "socks5-gssapi-service", "socks5-hostname",
		"speed-limit", "speed-time", "ssl-sessions", "stderr", "telnet-option", "tftp-blksize", "time-cond", "tls-max",
		"tls13-ciphers", "tlsauthtype", "tlspassword", "tlsuser", "trace", "trace-ascii", "trace-config", "unix-socket",
		"upload-file", "upload-flags", "url", "url-query", "user", "user-agent", "variable", "vlan-priority", "write-out",
	)
	curlFlagOpts = optSet(
		"#", "0", "1", "2", "3", "4", "6", ":", "B", "G", "I", "J", "L", "M", "N", "O", "R", "S", "V", "Z", "a", "f", "g",
		"i", "j", "k", "l", "n", "p", "q", "s", "v", "anyauth", "append", "basic", "ca-native", "cert-status",
		"compressed", "compressed-ssh", "create-dirs", "crlf", "digest", "disable", "disable-eprt", "disable-epsv",
		"disallow-username-in-url", "doh-cert-status", "doh-insecure", "dump-ca-embed", "fail", "fail-early",
		"fail-with-body", "false-start", "follow", "form-escape", "ftp-create-dirs", "ftp-pasv", "ftp-pret",
		"ftp-skip-pasv-ip", "ftp-ssl-ccc", "ftp-ssl-control", "get", "globoff", "haproxy-protocol", "head", "http0.9",
		"http1.0", "http1.1", "http2", "http2-prior-knowledge", "http3", "http3-only", "ignore-content-length", "insecure",
		"ipv4", "ipv6", "junk-session-cookies", "list-only", "location", "location-trusted", "mail-rcpt-allowfails",
		"manual", "metalink", "mptcp", "negotiate", "netrc", "netrc-optional", "next", "no-alpn", "no-buffer",
		"no-clobber", "no-keepalive", "no-npn", "no-progress-meter", "no-sessionid", "ntlm", "ntlm-wb", "out-null",
		"parallel", "parallel-immediate", "path-as-is", "post301", "post302", "post303", "progress-bar", "proxy-anyauth",
		"proxy-basic", "proxy-ca-native", "proxy-digest", "proxy-http2", "proxy-http3", "proxy-insecure",
		"proxy-negotiate", "proxy-ntlm", "proxy-ssl-allow-beast", "proxy-ssl-auto-client-cert", "proxy-tlsv1",
		"proxytunnel", "raw", "remote-header-name", "remote-name", "remote-name-all", "remote-time", "remove-on-error",
		"retry-all-errors", "retry-connrefused", "sasl-ir", "show-error", "show-headers", "silent", "skip-existing",
		"socks5-basic", "socks5-gssapi", "socks5-gssapi-nec", "ssl", "ssl-allow-beast", "ssl-auto-client-cert",
		"ssl-no-revoke", "ssl-reqd", "ssl-revoke-best-effort", "sslv2", "sslv3", "styled-output",
		"suppress-connect-headers", "tcp-fastopen", "tcp-nodelay", "tftp-no-options", "tls-earlydata", "tlsv1", "tlsv1.0",
		"tlsv1.1", "tlsv1.2", "tlsv1.3", "tr-encoding", "trace-ids", "trace-time", "use-ascii", "verbose", "version",
		"xattr",
	)
	wgetValueOpts = optSet(
		"e", "o", "a", "i", "B", "t", "O", "T", "w", "Q", "P",
		"execute", "output-file", "append-output", "input-file", "base", "tries", "output-document", "timeout", "wait", "quota",
		"user", "password", "bind-address", "limit-rate", "referer", "user-agent", "header", "post-data", "post-file", "rejected-log",
		"config", "report-speed", "retry-on-http-error", "waitretry", "progress", "start-pos", "dns-timeout", "connect-timeout",
		"read-timeout", "restrict-file-names", "prefer-family", "local-encoding", "remote-encoding", "use-askpass", "directory-prefix",
	)
	wgetFlagOpts = optSet(
		"V", "h", "b", "d", "q", "v", "F", "N", "S", "c", "4", "6",
		"version", "help", "background", "debug", "quiet", "verbose", "no-verbose", "force-html", "no-clobber", "continue",
		"timestamping", "server-response", "spider", "no-proxy", "no-dns-cache", "ignore-case", "inet4-only", "inet6-only",
		"no-config", "show-progress", "no-iri",
	)
)

// shellURLCapEvidence is the refusal used when a command names too many
// destinations to scan inside the hook deadline.
func shellURLCapEvidence() Evidence {
	return Evidence{
		Scanner:              scanner.DecideStructuralLabel,
		Pattern:              fmt.Sprintf("shell command names more than %d URLs or nests scripts %d deep", maxShellDestinationURLs, maxNestedShellDepth),
		Severity:             config.SeverityHigh,
		Detail:               "refusing to scan a subset of shell destinations",
		Action:               config.ActionBlock,
		inspectionIncomplete: true,
	}
}
