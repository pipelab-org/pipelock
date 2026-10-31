// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package policy

import (
	"path"
	"regexp"
	"slices"
	"strings"
)

type longOptionSpec struct {
	names       []string
	values      []string
	shortValues string
	forceShort  bool
	// prefixes maps every non-empty prefix of a name to the names it may
	// abbreviate, in names order, and an exact name to itself alone. It is
	// derived from names, so its size is fixed by the tables below.
	prefixes map[string][]string
}

// optionSpec uses a trailing ! for Git's documented --[no-] options.
func optionSpec(names, values, shortValues string, forceShort bool) longOptionSpec {
	var expanded []string
	for _, name := range strings.Fields(names) {
		if base, ok := strings.CutSuffix(name, "!"); ok {
			expanded = append(expanded, base, "no-"+base)
		} else {
			expanded = append(expanded, name)
		}
	}
	spec := longOptionSpec{names: expanded, values: strings.Fields(values), shortValues: shortValues, forceShort: forceShort}
	spec.prefixes = make(map[string][]string)
	for _, name := range expanded {
		for end := 1; end <= len(name); end++ {
			prefix := name[:end]
			if _, done := spec.prefixes[prefix]; !done {
				// Clipped so an append by a caller copies instead of sharing.
				spec.prefixes[prefix] = slices.Clip(scanLongOption(prefix, expanded))
			}
		}
	}
	return spec
}

// The option sets are from GNU coreutils 9.12 rm/chmod/chown/cp/base64 --help,
// Git 2.56.0 reset/clean/push/rm -h (including the documented negated forms),
// util-linux 2.42.4 wipefs --help, Ncat 7.992 --help and GNU Wget 1.25.0 --help.
// Sources: https://www.gnu.org/software/coreutils/manual/coreutils.html
// (rm, chmod, chown, cp, base64 invocation), https://git-scm.com/docs/gitcli#_abbreviated_options
// and the git-reset, git-clean, git-push, git-rm manuals at git-scm.com/docs,
// the wipefs(8) manual, https://nmap.org/book/ncat-man.html and the Wget manual.
// Keep the complete sets for these commands: benign options participate in
// ambiguity too. Git reads --help only as an exact word before parsing (Git
// 2.56.0 runs git reset --h as --hard), so the Git sets omit it. Wget's set is only its upload options because no other Wget
// long option is a prefix of one of them, so any prefix of one is that option
// or an ambiguity Wget rejects. Netcat spellings use Ncat's set; other netcat
// implementations either have no long options or resolve these prefixes the
// same way. Other commands retain their submitted spelling.
var commandLongOptions = map[string]longOptionSpec{
	"rm":     optionSpec("force interactive one-file-system no-preserve-root preserve-root recursive dir verbose help version", "", "", false),
	"chmod":  optionSpec("changes silent quiet verbose dereference no-dereference no-preserve-root preserve-root reference recursive help version", "reference", "", false),
	"chown":  optionSpec("changes silent quiet verbose dereference no-dereference from no-preserve-root preserve-root reference recursive help version", "from reference", "", false),
	"cp":     optionSpec("archive attributes-only backup copy-contents debug dereference force interactive keep-directory-symlink link no-clobber no-dereference no-preserve no-target-directory one-file-system parents preserve recursive reflink remove-destination sparse strip-trailing-slashes suffix symbolic-link target-directory update verbose context help version", "no-preserve sparse suffix target-directory", "St", false),
	"base64": optionSpec("decode ignore-garbage wrap help version", "wrap", "w", false),
	"wipefs": optionSpec("all backup force noheadings json no-act offset output parsable quiet types lock help version", "offset output types", "oOt", false),
	"ncat":   ncatOptions,
	"nc":     ncatOptions,
	"netcat": ncatOptions,
	"wget":   optionSpec("post-data post-file body-data body-file", "post-data post-file body-data body-file", "", false),
	"reset":  optionSpec("quiet! no-refresh refresh mixed soft hard merge keep recurse-submodules! patch! auto-advance! unified inter-hunk-context intent-to-add! pathspec-from-file! pathspec-file-nul!", "unified inter-hunk-context pathspec-from-file", "U", false),
	"clean":  optionSpec("quiet! dry-run! force! interactive! exclude", "exclude", "e", true),
	"push":   optionSpec("verbose! quiet! repo! all! branches! mirror! delete! tags! dry-run! porcelain! force! force-with-lease! force-if-includes! recurse-submodules! thin! receive-pack! exec! set-upstream! progress! prune! no-verify verify follow-tags! signed! atomic! push-option! ipv4 ipv6", "repo recurse-submodules receive-pack exec push-option", "o", true),
	"git-rm": optionSpec("dry-run! quiet! cached! force! ignore-unmatch! sparse! pathspec-from-file! pathspec-file-nul!", "pathspec-from-file", "", false),
}

var ncatOptions = optionSpec("allow allowfile append-output broker chat crlf delay deny denyfile exec help hex-dump idle-timeout keep-open listen lua-exec max-conns nodns no-shutdown output proxy proxy-auth proxy-dns proxy-type recv-only sctp send-only sh-exec source source-port ssl ssl-alpn ssl-cert ssl-ciphers ssl-servername ssl-trustfile ssl-verify telnet udp unixsock verbose version vsock wait",
	"delay exec hex-dump idle-timeout lua-exec max-conns output proxy proxy-auth proxy-dns proxy-type sh-exec source source-port wait", "cdeimopswx", false)

// gitValueOptions are git(1)'s global options that take the next word as their
// value; Git 2.56.0 accepts each in the separate form.
var gitValueOptions = []string{"-C", "-c", "--git-dir", "--work-tree", "--namespace", "--config-env", "--attr-source"}

// gitCommandKey maps a covered Git subcommand to its option set.
func gitCommandKey(name string) (string, bool) {
	switch name {
	case "reset", "clean", "push":
		return name, true
	case "rm":
		return "git-rm", true
	}
	return "", false
}

// commandName is the utility a word runs. It is lowercased because a
// case-insensitive file system runs /BIN/RM as rm.
func commandName(word string) string {
	return strings.ToLower(path.Base(word))
}

// utilityKey resolves a command word to its option set, including the
// git-<command> builtin names Git runs as that subcommand.
func utilityKey(name string) string {
	if sub, ok := strings.CutPrefix(name, "git-"); ok {
		if key, ok := gitCommandKey(sub); ok {
			return key
		}
	}
	return name
}

// normalizeCommandOptions adds the documented long-option interpretation to
// the normalized views; the literal view remains available to custom rules.
// GNU getopt_long and Git parse-options accept unique prefixes. Both reject
// ambiguous prefixes; policy conservatively presents every candidate instead
// of choosing one. The output is linear in input size: see optionExpander.
func normalizeCommandOptions(tokens []string) []string {
	out, _ := normalizeLineOptions(tokens, false, nil)
	return out
}

// normalizeLineOptions is normalizeCommandOptions, also reporting whether the
// tokens run a Git subcommand that is not a builtin (see gitBuiltins). Such a
// subcommand may run an alias or external program whose definition the tokens
// do not show, possibly assembled from text elsewhere on the line, such as an
// earlier export. Every long option word in the tokens then also presents the
// readings gitDestructiveReadings returns, so it receives the verdict of the
// strictest covered builtin it may spell or abbreviate. A personal alias used
// with such a prefix (git l --for=..., where l runs ls-files) is therefore
// matched, as is any such word elsewhere on its line; an alias run with no
// option word on the line is not.
//
// gitTool reads the tokens as the dedicated git tool's arguments (see
// gitToolName): Git's own argument list, as if preceded by the word git. That
// tool runs no shell, so its subcommand is the whole argument word: one that
// carries more than a builtin name, such as status; with its separator, is
// not that builtin.
//
// A builtin subcommand keeps its own reading only where proof grants it (see
// gitProof). With a nil proof, as for normalizeCommandOptions, the tokens' own
// reading decides.
func normalizeLineOptions(tokens []string, gitTool bool, proof *gitProof) ([]string, bool) {
	out, unknown, judged := normalizeOptions(tokens, false, gitTool)
	unknown = unknown || proof != nil && !proof.grants(judged)
	if unknown {
		out, _, _ = normalizeOptions(tokens, true, gitTool)
	}
	return out, unknown
}

// normalizeOptions presents option interpretations and reports whether the
// tokens run a non-builtin Git subcommand. judged lists, in order, the builtin
// subcommand of each other Git command it reads. strict presents every long
// option word's destructive Git readings, once each per call. gitTool is as
// for normalizeLineOptions.
func normalizeOptions(tokens []string, strict, gitTool bool) (out []string, unknownGit bool, judged []string) {
	hasLongOption := slices.ContainsFunc(tokens, func(token string) bool { return strings.Contains(token, "--") })
	if !hasLongOption {
		return tokens, false, nil
	}
	var activeKey string
	var candidateKeys []string
	remember := func(key string) bool {
		_, ok := commandLongOptions[key]
		if ok && !slices.Contains(candidateKeys, key) {
			candidateKeys = append(candidateKeys, key)
		}
		return ok
	}
	activate := func(key string) bool {
		if !remember(key) {
			return false
		}
		activeKey = key
		return true
	}
	// operands are covered utilities named among the current command's operands.
	// The active utility may then be a wrapper option's value, so the next word is
	// read as a value only when every one of them agrees.
	var operands []string
	takesValue := func(word, key string) bool {
		s := commandLongOptions[key]
		return optionTakesValue(word, s) || shortOptionNeedsValue(word, s.shortValues)
	}
	expander := optionExpander{ambiguous: map[string]bool{}, extra: map[string]bool{}}
	// Each command seeks its utility past wrappers (sudo, env, nice),
	// assignments and their options; a shell separator starts the next command.
	// stopped marks the end of options in a utility, or an uncovered Git
	// subcommand while seeking.
	var active, stopped, skipValue bool
	git := gitTool
	// unknown marks a Git command whose subcommand is not a builtin. gitConfig
	// marks a -c or --config-env value read before the subcommand: quote removal
	// can leave a separator from inside that value, such as an alias
	// definition's shell text, so a separator met while still seeking the
	// subcommand leaves it unknown. A command substitution or subshell met while
	// seeking, such as git -C "$(pwd)", suspends the seek until its parentheses
	// close (depth); if they never close, the subcommand is unknown.
	var unknown, gitConfig, resumeConfig bool
	depth := 0
	presented := make(map[string]bool)
	for _, token := range tokens {
		// A redirection target is a word too: flattened substitutions (>`rm ...`)
		// and process substitutions (<(rm ...)) leave commands there.
		op := ""
		if token != "" && strings.IndexByte("0123456789&<>", token[0]) >= 0 {
			// Every redirectOperatorRe match starts with one of these bytes.
			op = redirectOperatorRe.FindString(token)
		}
		parts := []string{op}
		changed := false
		// Retain shell operators while resetting option scope on both sides. The
		// caller already resolves shell spelling and splits quoted command views.
		start := len(op)
		for i := start; i <= len(token); i++ {
			if i < len(token) && !strings.ContainsRune(";|&()\n", rune(token[i])) {
				continue
			}
			if word := token[start:i]; word != "" {
				name := commandName(word)
				gitKey, _ := gitCommandKey(name)
				// Builtin names match exactly (see gitBuiltins).
				subKey, subCommand := gitCommandKey(word)
				// A shell alias definition (alias.<name>=!<command>) runs its first
				// word as a utility; the definition's options follow this word
				// once quote removal splits it.
				if _, command, found := strings.Cut(word, "=!"); found {
					remember(utilityKey(commandName(command)))
				}
				expand := false
				switch {
				case skipValue:
					skipValue = false
				case !active:
					switch {
					case git && subCommand:
						active, git, stopped = activate(subKey), false, false
						if gitTool && word != token {
							unknownGit = true
						} else {
							judged = append(judged, word)
						}
					case unknown && strings.HasPrefix(word, "-"):
						// The options may belong to whatever the alias runs.
						expand = true
					case stopped:
					case name == "git":
						git = true
					case git && slices.Contains(gitValueOptions, word):
						skipValue = true
						gitConfig = gitConfig || word == "-c" || word == "--config-env"
					case git && strings.HasPrefix(word, "--config-env="):
						gitConfig = true
					case strings.HasPrefix(word, "--coreutils-prog="):
						// The coreutils multi-call binary runs the named program.
						active = activate(commandName(strings.TrimPrefix(word, "--coreutils-prog=")))
					case strings.HasPrefix(word, "-"):
						// Wrapper and global options precede the utility. Quote stripping
						// can make a separator inside an operand look like shell syntax,
						// so earlier utilities' interpretations still apply.
						expand = true
					case git:
						// An unrelated Git subcommand must not adopt a later operand as
						// its command.
						stopped = true
						unknown = !gitBuiltins[word] || gitTool && word != token
						unknownGit = unknownGit || unknown
						if !unknown {
							judged = append(judged, word)
						}
					default:
						// Bare subcommands still support the MCP git tool.
						active = activate(utilityKey(name))
					}
				case word == "--" && !stopped:
					stopped = true
				case !strings.HasPrefix(word, "-"):
					// A wrapper option's value can name a covered utility (sudo -u push
					// git reset), and a wrapper's own -- can end its options rather
					// than the utility's (sudo -u push -- git reset). A covered name
					// among the operands adds its interpretation without replacing
					// the active utility's, and resumes option reading.
					named := false
					for _, key := range []string{utilityKey(name), gitKey} {
						if remember(key) {
							named = true
							if key != activeKey && !slices.Contains(operands, key) {
								operands = append(operands, key)
							}
						}
					}
					stopped = stopped && !named
				case stopped:
				default:
					expand = true
					skipValue = takesValue(word, activeKey) &&
						!slices.ContainsFunc(operands, func(key string) bool { return !takesValue(word, key) })
				}
				if expand {
					key := ""
					if active {
						key = activeKey
					}
					expanded := expander.expand(word, key, candidateKeys)
					parts = append(parts, strings.Join(expanded, " "))
					changed = changed || len(expanded) != 1 || expanded[0] != word
				} else {
					parts = append(parts, word)
				}
				if strict {
					// An assigned option (V=--hard) can reach the command as $V.
					readings := gitDestructiveReadings(word)
					if _, value, found := strings.Cut(word, "="); found {
						readings = append(readings, gitDestructiveReadings(value)...)
					}
					for _, reading := range readings {
						if !presented[reading] {
							presented[reading] = true
							parts = append(parts, " "+reading+" ")
							changed = true
						}
					}
				}
			}
			if i < len(token) {
				seeking, resume := git && !active && !stopped, false
				switch c := token[i]; {
				case depth > 0 && c == '(':
					depth++
				case depth > 0 && c == ')':
					depth--
					resume = depth == 0
				case seeking && c == '(' && (!gitConfig || i > 0 && token[i-1] == '$'):
					depth, resumeConfig = 1, gitConfig
				case seeking && gitConfig:
					unknownGit = true
				}
				parts = append(parts, token[i:i+1])
				active, git, stopped, skipValue = false, false, false, false
				unknown, gitConfig = false, false
				if resume {
					git, gitConfig = true, resumeConfig
				}
				operands = operands[:0]
				clear(expander.extra)
			}
			start = i + 1
		}
		if changed {
			out = append(out, strings.Fields(strings.Join(parts, ""))...)
		} else {
			out = append(out, token)
		}
	}
	return out, unknownGit || depth > 0, judged
}

// redirectOperatorRe matches the operator that starts a redirection word; the
// rest of the word is its target.
var redirectOperatorRe = regexp.MustCompile(`^(?:[0-9]+|&)?(?:>>|>\||>|<<<|<<-?|<>|<)&?`)

// optionExpander presents the documented interpretations of long-option words.
// The running utility's unique interpretation replaces the word in place and
// keeps its value. Other candidate utilities' interpretations, and every
// candidate of an ambiguous prefix (which the utility itself rejects), follow
// the word as bare names: once per command for other utilities, once per
// input for ambiguous candidates. Repeating a word therefore cannot multiply
// the tokens every rule is matched against.
type optionExpander struct {
	ambiguous map[string]bool // presented anywhere in the input
	extra     map[string]bool // presented in the current command
}

func (e optionExpander) expand(word, activeKey string, candidateKeys []string) []string {
	out := []string{word}
	present := func(seen map[string]bool, token string) {
		if !seen[token] && !slices.Contains(out, token) {
			seen[token] = true
			out = append(out, token)
		}
	}
	interpret := func(key string, inPlace bool) {
		spec := commandLongOptions[key]
		names, value, hasValue := matchLongOption(word, spec)
		seen := e.extra
		if len(names) > 1 {
			seen = e.ambiguous
		}
		for _, name := range names {
			switch {
			case len(names) == 1 && inPlace && hasValue:
				out[0] = "--" + name + "=" + value
			case len(names) == 1 && inPlace:
				out[0] = "--" + name
			default:
				present(seen, "--"+name)
			}
			if spec.forceShort && name == "force" {
				// The shipped Git clean rule recognizes the short synonym, and
				// push's no-argument force option must remain visible with = too.
				present(seen, "-f")
			}
		}
	}
	if activeKey != "" {
		interpret(activeKey, true)
	}
	for _, key := range candidateKeys {
		if key != activeKey {
			interpret(key, false)
		}
	}
	return out
}

// matchLongOption returns the names in spec that word may abbreviate, and the
// value it carries after =. An exact name wins over longer options.
func matchLongOption(word string, spec longOptionSpec) (names []string, value string, hasValue bool) {
	if !strings.HasPrefix(word, "--") {
		return nil, "", false
	}
	name, value, hasValue := strings.Cut(word[2:], "=")
	if name == "" {
		return nil, "", false
	}
	if spec.prefixes != nil {
		// Callers only read names, so the shared table slice is returned.
		return spec.prefixes[name], value, hasValue
	}
	return scanLongOption(name, spec.names), value, hasValue
}

// scanLongOption returns the names that name may abbreviate; an exact name
// wins over longer options.
func scanLongOption(name string, names []string) []string {
	if slices.Contains(names, name) {
		return []string{name}
	}
	var out []string
	for _, candidate := range names {
		if strings.HasPrefix(candidate, name) {
			out = append(out, candidate)
		}
	}
	return out
}

// optionTakesValue reports whether the utility reads the next word as the
// value of word, for any option word may abbreviate.
func optionTakesValue(word string, spec longOptionSpec) bool {
	names, _, hasValue := matchLongOption(word, spec)
	return !hasValue && slices.ContainsFunc(names, func(name string) bool { return slices.Contains(spec.values, name) })
}

// A value-taking short option consumes the rest of its cluster, or the next
// word when it ends the cluster (Git's parse-options short-option contract).
func shortOptionNeedsValue(word, valueOptions string) bool {
	if !strings.HasPrefix(word, "-") || strings.HasPrefix(word, "--") {
		return false
	}
	for i := 1; i < len(word); i++ {
		if strings.ContainsRune(valueOptions, rune(word[i])) {
			return i == len(word)-1
		}
	}
	return false
}
