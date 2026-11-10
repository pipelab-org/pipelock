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

// shellProofWords in internal/mcp/policy is the quote-aware reader the policy
// package already uses, and it is not exported. This splitter is the
// best-effort reader for destination extraction only: it removes quotes and
// simple escapes and keeps operators as their own words. It does not expand
// variables or re-parse a quoted script.

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
			i++
			closed := false
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

func shellDestinationURLs(command string) (urls []string, over bool) {
	words, ok := splitShellWords(command)
	if !ok {
		// The structure is not reliable. Still take explicit scheme URLs
		// from the raw text, and do not guess a bare host.
		words = []string{command}
		return appendSchemeURLs(nil, map[string]struct{}{}, words)
	}
	seen := make(map[string]struct{})
	urls, over = appendSchemeURLs(nil, seen, words)
	if over {
		return nil, true
	}
	return appendCurlWgetHosts(urls, seen, words)
}

func appendSchemeURLs(urls []string, seen map[string]struct{}, words []string) ([]string, bool) {
	for _, word := range words {
		for _, match := range schemeURLRe.FindAllString(word, -1) {
			var over bool
			urls, over = addDestination(urls, seen, strings.TrimRight(match, ".,);"))
			if over {
				return nil, true
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
	urlNext := false
	add := func(word string) bool {
		var over bool
		urls, over = addDestination(urls, seen, "http://"+word)
		return over
	}
	for _, word := range words {
		if isShellOperator(word) {
			tool = ""
			optionsDone = false
			skipBare, ambiguous, urlNext = false, false, false
			continue
		}
		if tool == "" {
			if base := commandBase(word); base == "curl" || base == "wget" {
				tool = base
				optionsDone = false
				skipBare, ambiguous, urlNext = false, false, false
			}
			continue
		}
		if urlNext {
			// curl's --url value is the destination itself.
			urlNext = false
			if looksLikeHostOperand(word) && add(word) {
				return nil, true
			}
			continue
		}
		if skipBare {
			skipBare = false
			// After an option this table does not know, the word may be that
			// option's value or the URL. A literal IP is scanned either way
			// (a file named like an address is not worth the miss); a
			// hostname is left alone to avoid treating values as hosts.
			if ambiguous && looksLikeHostOperand(word) && scanner.ParseIPLiteral(operandHost(word)) != nil && add(word) {
				return nil, true
			}
			ambiguous = false
			continue
		}
		if !optionsDone && isOptionWord(word) {
			if tool == "curl" {
				if word == "--url" {
					urlNext = true
					continue
				}
				if value, ok := strings.CutPrefix(word, "--url="); ok {
					if looksLikeHostOperand(value) && add(value) {
						return nil, true
					}
					continue
				}
			}
			skipBare, ambiguous, optionsDone = consumeFetchOption(tool, word)
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
	if word == "" || strings.HasPrefix(word, "-") || strings.Contains(word, "://") || strings.Contains(word, "@") || strings.ContainsAny(word, " \t") {
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
	curlValueOpts = optSet(
		"E", "K", "C", "b", "c", "d", "D", "F", "P", "H", "h", "m", "o", "x", "U", "Q", "r", "e", "X", "Y", "y", "t", "z", "T", "u", "A", "w",
		"cert", "config", "continue-at", "cookie", "cookie-jar", "data", "dump-header", "form", "ftp-port", "header", "help", "max-time",
		"output", "proxy", "proxy-user", "quote", "range", "referer", "request", "speed-limit", "speed-time", "telnet-option", "time-cond",
		"upload-file", "user", "user-agent", "write-out", "url", "data-raw", "data-binary", "data-ascii", "data-urlencode", "form-string",
		"connect-timeout", "retry", "retry-delay", "retry-max-time", "max-redirs", "limit-rate", "output-dir", "resolve", "connect-to",
		"proxy-header", "cacert", "capath", "key", "proto", "proto-default", "proto-redir",
	)
	curlFlagOpts = optSet(
		"a", "q", "f", "G", "g", "I", "0", "k", "4", "6", "j", "l", "L", "M", "n", "N", "O", "Z", "#", "p", "J", "R", "S", "i", "s", "2", "3", "1", "B", "v", "V",
		"append", "disable", "fail", "get", "globoff", "head", "http1.0", "insecure", "ipv4", "ipv6", "junk-session-cookies", "list-only",
		"location", "manual", "netrc", "next", "no-buffer", "parallel", "progress-bar", "proxytunnel", "remote-header-name", "remote-name",
		"remote-time", "show-error", "show-headers", "silent", "sslv2", "sslv3", "tlsv1", "use-ascii", "verbose", "version", "compressed",
		"path-as-is", "fail-with-body", "location-trusted", "http1.1", "http2", "tlsv1.2", "tlsv1.3", "create-dirs",
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
		Pattern:              fmt.Sprintf("shell command names more than %d URLs", maxShellDestinationURLs),
		Severity:             config.SeverityHigh,
		Detail:               "refusing to scan a subset of shell destinations",
		Action:               config.ActionBlock,
		inspectionIncomplete: true,
	}
}
