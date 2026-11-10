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

// leadingSchemeRe is an RFC 3986 scheme anchored at the start of a value. A
// "://" later in the value (in a path or query) is not a scheme.
var leadingSchemeRe = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9+.-]*://`)

// webScheme reports whether value starts with a scheme schemeURLRe already
// takes as a whole URL (http, https, ws, wss).
func webScheme(value string) bool {
	m := leadingSchemeRe.FindString(value)
	switch strings.ToLower(strings.TrimSuffix(m, "://")) {
	case "http", "https", "ws", "wss":
		return true
	}
	return false
}

// authorityHost returns the host[:port] a URL-like value connects to: an
// anchored scheme is removed, the authority ends at the first "/?#", and any
// userinfo before the last "@" inside it is dropped (curl's URL parser reads
// it the same way).
func authorityHost(value string) string {
	value = strings.TrimPrefix(value, leadingSchemeRe.FindString(value))
	if i := strings.IndexAny(value, "/?#"); i >= 0 {
		value = value[:i]
	}
	if at := strings.LastIndexByte(value, '@'); at >= 0 {
		value = value[at+1:]
	}
	return value
}

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
			if !wasAmbiguous || !isOptionWord(word) {
				if wasAmbiguous && looksLikeHostOperand(word) && scanner.ParseIPLiteral(operandHost(word)) != nil && add(word) {
					return nil, true
				}
				continue
			}
			carry = true
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
		if leadingSchemeRe.MatchString(word) {
			// http(s) and ws(s) URLs are taken whole by the URL regex. Any
			// other scheme curl or wget speaks (gopher, ftp, dict, ...)
			// still connects somewhere: scan that host.
			if !webScheme(word) {
				if h := authorityHost(word); h != "" && add(h) {
					return nil, true
				}
			}
			continue
		}
		if strings.Contains(word, "@") {
			// user[:pass]@host[:port][/path]: curl connects to the host after
			// the userinfo, so scan that host.
			if h := authorityHost(word); looksLikeHostOperand(h) && add(h) {
				return nil, true
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
		if leadingSchemeRe.MatchString(value) {
			if webScheme(value) {
				return nil
			}
			if h := authorityHost(value); h != "" {
				return []string{h}
			}
			return nil
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
		if value = authorityHost(value); value == "" {
			return nil
		}
		return []string{value}
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
	if word == "" || strings.HasPrefix(word, "-") || leadingSchemeRe.MatchString(word) || strings.Contains(word, "@") || strings.ContainsAny(word, " \t") {
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
		Pattern:              fmt.Sprintf("shell command names more than %d URLs", maxShellDestinationURLs),
		Severity:             config.SeverityHigh,
		Detail:               "refusing to scan a subset of shell destinations",
		Action:               config.ActionBlock,
		inspectionIncomplete: true,
	}
}
