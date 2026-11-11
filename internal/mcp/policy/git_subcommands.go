// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package policy

import (
	"bytes"
	"encoding/json"
	"regexp"
	"slices"
	"strings"

	"github.com/luckyPipewrench/pipelock/internal/mcp/jsonrpc"
)

// gitBuiltins is the output of `git --list-cmds=builtins` from Git 2.56.0, the
// version the Git option tables in long_options.go follow. Git runs a builtin
// before it looks up an alias, so a configured alias cannot replace one
// (git-config(1), alias.*: "aliases that hide existing commands are ignored").
// Builtin names match exactly: Git 2.56.0 reads git RESET as an alias name.
// Every other subcommand word may run an alias from any configuration source,
// including files and environment the command line does not show, or an
// external git-<name> program.
var gitBuiltins = func() map[string]bool {
	set := make(map[string]bool)
	for _, name := range strings.Fields(`add am annotate apply archive backfill
		bisect blame branch bugreport bundle cat-file check-attr check-ignore
		check-mailmap check-ref-format checkout checkout--worker checkout-index
		cherry cherry-pick clean clone column commit commit-graph commit-tree
		config count-objects credential credential-cache
		credential-cache--daemon credential-store describe diagnose diff
		diff-files diff-index diff-pairs diff-tree difftool fast-export
		fast-import fetch fetch-pack fmt-merge-msg for-each-ref for-each-repo
		format-patch format-rev fsck fsck-objects fsmonitor--daemon gc
		get-tar-commit-id grep hash-object help history hook index-pack init
		init-db interpret-trailers last-modified log ls-files ls-remote ls-tree
		mailinfo mailsplit maintenance merge merge-base merge-file merge-index
		merge-ours merge-recursive merge-recursive-ours merge-recursive-theirs
		merge-subtree merge-tree mktag mktree multi-pack-index mv name-rev notes
		pack-objects pack-redundant pack-refs patch-id pickaxe prune
		prune-packed pull push range-diff read-tree rebase receive-pack reflog
		refs remote remote-ext remote-fd repack replace replay repo rerere reset
		restore rev-list rev-parse revert rm send-pack shortlog show show-branch
		show-index show-ref sparse-checkout stage stash status stripspace
		submodule--helper switch symbolic-ref tag unpack-file unpack-objects
		update-index update-ref update-server-info upload-archive
		upload-archive--writer upload-pack url-parse var verify-commit
		verify-pack verify-tag version whatchanged worktree write-tree`) {
		set[name] = true
	}
	return set
}()

// gitToolName matches the dedicated git tool, whose arguments are Git's own
// argument list without the word git. It is the git alternative of the default
// Destructive Git Operation rule's tool pattern, with the namespace prefixes
// every shipped rule accepts (builtinToolNameAliasPrefix); the rule's other
// alternatives are shell tools. TestGitToolNameFromRules derives it from the
// default rules.
var gitToolName = regexp.MustCompile(`(?i)^(?:` + builtinToolNameAliasPrefix + `)?git$`)

// argCarrier is one submitted argument value with the shape the request gave
// it: a JSON array of strings is one argument list whose elements are literal
// arguments, and any other string is a scalar whose word boundaries depend on
// how the tool reads it.
type argCarrier struct {
	values []string
	array  bool
}

// jsonArgCarriers returns the carriers of raw in the order ArgValues extracts
// their strings, or nil when that order does not reproduce values exactly, so
// a shape is used only for the values it describes.
func jsonArgCarriers(raw json.RawMessage, values []string) []argCarrier {
	if len(raw) == 0 {
		return nil
	}
	var parsed any
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	if dec.Decode(&parsed) != nil {
		return nil
	}
	var carriers []argCarrier
	var visit func(v any, depth int)
	visit = func(v any, depth int) {
		if depth > maxArgCarrierDepth {
			return
		}
		switch val := v.(type) {
		case string:
			carriers = append(carriers, argCarrier{values: []string{val}})
		case []any:
			elements := make([]string, 0, len(val))
			for _, item := range val {
				s, ok := item.(string)
				if !ok {
					elements = nil
					break
				}
				elements = append(elements, s)
			}
			if elements != nil && len(elements) == len(val) && len(val) > 0 {
				carriers = append(carriers, argCarrier{values: elements, array: true})
				return
			}
			for _, item := range val {
				visit(item, depth+1)
			}
		case map[string]any:
			for _, k := range jsonrpc.SortedKeys(val) {
				visit(val[k], depth+1)
			}
		}
	}
	visit(parsed, 0)
	var flat []string
	for _, c := range carriers {
		flat = append(flat, c.values...)
	}
	if !slices.Equal(flat, values) {
		return nil
	}
	return carriers
}

// maxArgCarrierDepth bounds jsonArgCarriers' walk. Deeper strings are left out,
// so the shape no longer reproduces the values and is not used.
const maxArgCarrierDepth = 64

// gitProof is the reading that may grant a Git subcommand the builtin
// exception. proved lists, in order, the builtin subcommand of each Git
// command whose executable, global options and subcommand were all read from
// the request as submitted. unproved reports a Git command, or a carrier of
// the git tool's arguments, whose subcommand could not be read that way.
type gitProof struct {
	proved   []string
	unproved bool
	// Keep executable uncertainty separate so added strict readings cannot
	// erase incomplete checks in the interpretation set that preceded them.
	variableExecutable bool
}

// grants reports whether the proof covers judged, the builtin subcommands a
// normalized view found, in order. Normalization drops invisible characters,
// folds lookalike letters, removes shell quoting and decodes escapes, so a
// word it reads as a builtin may reach Git as another name, which runs an
// alias or a git-<name> program. A normalized view keeps the builtin reading
// only for the Git commands this proof read the same way.
func (p gitProof) grants(judged []string) bool {
	return !p.unproved && !p.variableExecutable && slices.Equal(p.proved, judged)
}

// gitWord is one word of a carrier. literal marks an array element, which is
// one argument exactly as written. ambiguous marks a word from a value that
// may be either a literal argument or text a tool splits into words, when
// those readings give the word different boundaries.
type gitWord struct {
	text               string
	literal, ambiguous bool
	// Quoted parentheses are operand text, but quoting still withholds
	// proof of an executable or subcommand's original spelling.
	quotedParens bool
	// nestedScript marks a word of a shell -c/-lc command string. Separators
	// there belong to the nested shell, not to the outer command.
	nestedScript bool
}

// proveGitBuiltins reads args for gitProof. carriers is the shape of args
// when the request recorded it (see jsonArgCarriers), else nil.
//
// Only a bounded literal prefix is proved; expansions are never evaluated.
// In a scalar, raw words split on space and tab (gitScalarWords preserves
// quoted parentheses), and every word from the executable to the
// subcommand must be plain (see plainShellWord): quoting, escapes, expansion,
// substitution, globbing, line continuation and non-ASCII text leave the
// command unproved. Array elements are literal arguments; they are never
// decoded or split. After the executable, git(1)'s global options are read
// with their values as whole arguments; any other option word leaves the
// command unproved rather than skipping to a later word. The next argument is
// the subcommand, even when it is itself named git, and it is proved only when
// it exactly equals a name in gitBuiltins.
//
// The git tool's arguments (gitTool) are read as one argument list. A request
// that splits them over more than one value records no order or grammar for
// joining them, so it proves nothing. A scalar's words are its arguments when
// its prefix is plain: shell parsing, whitespace splitting and quote-aware
// splitting all give a plain prefix the same words, and a tool that instead
// passes the whole string as one argument gives Git no option at all.
//
// Without a recorded shape, a value may be either kind. One value is read as
// a scalar, for the same reason. With several, a word in the prefix from a
// value of more than one word is ambiguous, so it proves nothing.
func proveGitBuiltins(args []string, carriers []argCarrier, gitTool bool) gitProof {
	var proof gitProof
	if carriers == nil {
		var words []gitWord
		for _, arg := range args {
			fields, complete := gitScalarWords(arg, gitTool)
			proof.unproved = proof.unproved || !complete
			ambiguous := len(args) > 1 && len(splitPlainFields(arg)) > 1
			for _, field := range fields {
				field.ambiguous = ambiguous
				words = append(words, field)
			}
		}
		proof.read(words, gitTool, gitTool)
		return proof
	}
	if gitTool && len(carriers) != 1 {
		proof.unproved = true
		return proof
	}
	for _, carrier := range carriers {
		var words []gitWord
		for _, value := range carrier.values {
			if carrier.array {
				words = append(words, gitWord{text: value, literal: true})
				continue
			}
			fields, complete := gitScalarWords(value, gitTool)
			proof.unproved = proof.unproved || !complete
			words = append(words, fields...)
		}
		proof.read(words, gitTool, gitTool)
	}
	return proof
}

// splitPlainFields splits a scalar on the shell's default field separators,
// space and tab.
func splitPlainFields(s string) []string {
	return strings.FieldsFunc(s, func(r rune) bool { return r == ' ' || r == '\t' })
}

// gitScalarWords keeps the original spelling for prefix proof. The shared
// bash(1) reader identifies literal operands, whose parentheses cannot start
// commands. Real parentheses, expansions and escapes retain the conservative
// reading. Unclosed quotes cannot grant proof. Dedicated Git tool scalars
// have no shell grammar in the first place.
func gitScalarWords(source string, noShell bool) ([]gitWord, bool) {
	var out []gitWord
	if !noShell {
		if words, ok := shellProofWords(source); ok && !slices.ContainsFunc(words, func(w shellProofWord) bool {
			return !w.literal || w.operator && strings.ContainsAny(w.value, "()<>{}")
		}) {
			scripts := nestedShellScriptWords(words)
			for i, w := range words {
				for _, field := range splitPlainFields(source[w.start:w.end]) {
					out = append(out, gitWord{
						text:         field,
						quotedParens: w.literal && !w.operator,
						nestedScript: scripts[i],
					})
				}
			}
			return out, true
		}
	}
	for _, field := range splitPlainFields(source) {
		out = append(out, gitWord{text: field})
	}
	if noShell {
		return out, true
	}
	_, complete := readShellPathWords(source)
	return out, complete
}

// read adds the Git commands in one carrier's words. A command starts at the
// first word and after each shell separator outside a literal word. Within a
// command, words before git are skipped, as the normalized views skip
// wrappers, assignments and options, until a covered utility other than Git
// (see commandLongOptions) starts the command instead. inGit seeds the first
// command as the git tool's arguments; noShell keeps separators inside the
// git tool's words, where no shell reads them.
//
// A scalar word that is not plain (see plainShellWord) before the executable
// may expand to another executable, such as $CMD git fetch, where Git would
// read git as an alias and fetch as its argument. Git met after such a word in
// the same command is unproved. A shell's command string in an argument list,
// such as bash -c's, is not read: the shell's environment, startup files and
// aliases can redefine git there, so its Git commands stay unproved. A
// separator inside that string is the nested shell's own syntax, and a Git
// builtin after one does not join the proof.
func (p *gitProof) read(words []gitWord, inGit, noShell bool) {
	const (
		seeking = iota
		global  // after the executable, before the subcommand
		value   // a global option's value is next
		done    // the command's subcommand is read, or it is not Git
	)
	state := seeking
	if inGit {
		state = global
	}
	// expanded marks a scalar word in the current command, before its
	// executable, that is not plain.
	expanded := false
	// nestedSep marks a separator already seen in the current nested script.
	nestedSep := false
	// executable marks that the current command's executable word is next:
	// POSIX simple commands (Shell Command Language 2.9.1) begin with
	// optional NAME=value assignments, then the command name. A command name
	// the shell expands, such as $X, may run Git with any subcommand, so the
	// proof cannot vouch for the command's options.
	executable := !inGit
	word := func(w gitWord) {
		if executable && (w.literal || !shellAssignment.MatchString(w.text)) {
			executable = false
			if !w.literal && !strings.HasPrefix(w.text, "#") && !plainShellWord(w.text) {
				p.variableExecutable = true
			}
		}
		switch state {
		case seeking:
			name := commandName(w.text)
			switch {
			case !w.literal && strings.HasPrefix(w.text, "#"):
				// The shell reads the rest of this command as a comment.
				state = done
			case !w.literal && name != "git" && viewsReadGit(w.text):
				// A rule view reads this word as Git, but its spelling is not
				// git, so the proof cannot say which Git command a later word
				// belongs to.
				p.unproved, state = true, done
			case name == "git":
				state = global
				if expanded || !w.literal && !plainShellWord(w.text) {
					p.unproved, state = true, done
				}
			case !strings.HasPrefix(w.text, "-"):
				if _, covered := commandLongOptions[utilityKey(name)]; covered {
					state = done
				}
			}
			if !w.literal && !plainShellWord(w.text) {
				expanded = true
			}
			if (strings.HasPrefix(w.text, "-") || strings.Contains(w.text, "=")) && strings.Contains(w.text, "git-") {
				// An option or assignment value naming git-<name>, such as
				// exec -agit-push, env --argv0=git-push or zsh's ARGV0, may
				// become Git's argv[0], from which Git runs builtin <name>
				// whatever subcommand word follows.
				expanded = true
			}
		case global, value:
			switch {
			case w.ambiguous || !w.literal && !plainShellWord(w.text):
				p.unproved, state = true, done
			case state == value:
				state = global
			case slices.Contains(gitValueOptions, w.text):
				state = value
			case strings.HasPrefix(w.text, "-"):
				if !gitGlobalOption(w.text) {
					p.unproved, state = true, done
				}
			case gitBuiltins[w.text]:
				// A builtin after a separator inside bash -c's script is the
				// nested shell's command. Granting it would let an option
				// abbreviation such as --har keep the builtin reading.
				if w.nestedScript && nestedSep {
					p.unproved, state = true, done
					break
				}
				p.proved = append(p.proved, w.text)
				state = done
			default:
				p.unproved, state = true, done
			}
		}
	}
	for _, w := range words {
		if !w.nestedScript {
			nestedSep = false
		}
		if w.literal || noShell {
			word(w)
			continue
		}
		start := 0
		// The pass at i == len(w.text) flushes the last piece; the loop ends there.
		for i := 0; ; i++ {
			if i < len(w.text) && w.quotedParens && (w.text[i] == '(' || w.text[i] == ')') {
				continue
			}
			if i < len(w.text) && !strings.ContainsRune(gitProofSeparators, rune(w.text[i])) {
				continue
			}
			if piece := w.text[start:i]; piece != "" {
				word(gitWord{text: piece, ambiguous: w.ambiguous, nestedScript: w.nestedScript})
			}
			if i == len(w.text) {
				break
			}
			if w.nestedScript {
				nestedSep = true
			}
			if state == seeking && w.text[i] == '`' {
				// A backquote is the older spelling of $(, whose $ marks the
				// prefix as expanded: the substitution's output may become
				// the executable of the command it appears in.
				expanded = true
			}
			if expanded && (strings.ContainsRune("()`", rune(w.text[i])) || i > 0 && w.text[i-1] == '\\') {
				// A substitution or escaped separator need not end the outer
				// command. Its uncertain prefix must not grant a later Git
				// word a builtin reading.
				p.unproved = true
			}
			if state == global || state == value {
				p.unproved = true
			}
			state, expanded, executable = seeking, false, true
			start = i + 1
		}
	}
	if state == global || state == value {
		p.unproved = true
	}
}

// viewsReadGit reports whether any rule view reads word as the git
// executable, under the same normalizations the views use (argViewNorms).
func viewsReadGit(word string) bool {
	for _, n := range argViewNorms {
		tokens, _ := n.tokens([]string{word})
		if slices.ContainsFunc(tokens, func(t string) bool { return commandName(t) == "git" }) {
			return true
		}
	}
	return false
}

// shellAssignment matches a variable assignment word: a name of letters,
// digits and underscores not starting with a digit (POSIX XBD 3.216), then =.
var shellAssignment = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*=`)

// gitProofSeparators end a command in a shell command string: the separators
// the normalized views split on, and backquote, which starts a command
// substitution.
const gitProofSeparators = ";|&()\n`"

// nestedShellNames are shells whose -c argument is a command string. The
// names match the shells Encoded Command Execution already names, plus the
// restricted and Almquist spellings of the same programs.
var nestedShellNames = map[string]bool{
	"ash": true, "bash": true, "dash": true, "ksh": true,
	"mksh": true, "rbash": true, "sh": true, "zsh": true,
}

// shellShortFlags are bash(1)'s single-letter invocation and set options
// (bash --help: -ilrsD, -c, -O, and -abefhkmnptuvxBCEHPT / -o). A cluster
// made of these letters that includes c starts the nested command string;
// any other suffix on that cluster is treated as script text too.
const shellShortFlags = "abcefhiklmnoprstuvxBCDEHOPT"

// nestedShellScriptWords marks each shell word that is a nested shell's
// command string. Operators split commands. A -c inside one command marks
// that command's script only.
func nestedShellScriptWords(words []shellProofWord) []bool {
	mark := make([]bool, len(words))
	start := 0
	for i, w := range words {
		if !w.operator {
			continue
		}
		markNestedShellScripts(words[start:i], mark[start:i])
		start = i + 1
	}
	markNestedShellScripts(words[start:], mark[start:])
	return mark
}

// markNestedShellScripts marks the words of one command that may be a nested
// shell's command string. Once -c appears among a shell's options, every
// later word of the command is marked. Picking the single script word would
// need each shell's exact option grammar (-o and -O take a value, clustered
// or not, and long options differ by shell); a miscount would leave the real
// script unmarked and its Git commands proved. Marking positional arguments
// too only makes their Git reading stricter, so the error direction is safe.
func markNestedShellScripts(words []shellProofWord, mark []bool) {
	for i, w := range words {
		if !nestedShellNames[commandName(w.value)] {
			continue
		}
		sawCommand := false
		for j := i + 1; j < len(words); j++ {
			if sawCommand {
				mark[j] = true
				continue
			}
			attached, ok := shellCommandString(words[j].value)
			if !ok {
				continue
			}
			sawCommand = true
			if attached {
				mark[j] = true
			}
		}
	}
}

// shellCommandString reports whether word is a short-option cluster that
// includes -c (-c, -lc, -ce, -oc). attached means the cluster also carries
// text after its flags, which is marked as script text too.
func shellCommandString(word string) (attached, ok bool) {
	if len(word) < 2 || word[0] != '-' || word[1] == '-' {
		return false, false
	}
	body := word[1:]
	i := 0
	for i < len(body) && strings.ContainsRune(shellShortFlags, rune(body[i])) {
		i++
	}
	if !strings.ContainsRune(body[:i], 'c') {
		return false, false
	}
	return i < len(body), true
}

// plainShellWord reports whether a word in a scalar has the same text after
// shell parsing as before it, so its boundaries do not depend on how the tool
// reads the scalar: ASCII letters, digits and characters with no shell or
// splitting meaning. A tilde stays one word when the shell expands it.
func plainShellWord(word string) bool {
	for i := 0; i < len(word); i++ {
		c := word[i]
		switch {
		case 'a' <= c && c <= 'z', 'A' <= c && c <= 'Z', '0' <= c && c <= '9':
		case strings.IndexByte("-_./:@%+,=~", c) >= 0:
		default:
			return false
		}
	}
	return word != ""
}

// gitGlobalOption reports whether word is one of git(1)'s global options for
// Git 2.56.0 that is followed by a subcommand: a flag, or an option with its
// value attached by =. The options taking a separate value are
// gitValueOptions. Options that print and exit without a subcommand, such as
// --version and --exec-path without a value, are not included.
func gitGlobalOption(word string) bool {
	switch word {
	case "-p", "--paginate", "-P", "--no-pager", "--bare", "--no-replace-objects",
		"--no-lazy-fetch", "--no-optional-locks", "--no-advice", "--literal-pathspecs",
		"--glob-pathspecs", "--noglob-pathspecs", "--icase-pathspecs":
		return true
	}
	for _, prefix := range []string{"--git-dir=", "--work-tree=", "--namespace=", "--config-env=", "--attr-source=", "--exec-path="} {
		if strings.HasPrefix(word, prefix) {
			return true
		}
	}
	return false
}

// gitDestructiveOptions are the long options in the covered Git subcommands'
// option tables (commandLongOptions) that a built-in rule blocks on their own:
// reset --hard and push --force under Destructive Git Operation, git rm
// --force under Destructive File Delete, and the checkout, switch, and branch
// forms that discard a work tree or reset a ref. Clean's force option is
// blocked only together with -d, which has no long form.
// TestGitDestructiveOptionsFromRules derives this list from DefaultToolPolicyRules.
var gitDestructiveOptions = []struct{ command, option string }{
	{"reset", "hard"},
	{"push", "force"},
	{"rm", "force"},
	{"checkout", "force"},
	{"switch", "force-create"},
	{"switch", "discard-changes"},
	{"switch", "force"},
	{"branch", "force"},
}

// gitDestructiveReadings returns "<subcommand> --<option>" for each destructive
// option that word spells in full or abbreviates, ambiguous prefixes included,
// as Git would read it if the subcommand ran that builtin. Option names match
// case-sensitively, as Git's parse-options does; a value after = is ignored.
func gitDestructiveReadings(word string) []string {
	name, _, _ := strings.Cut(strings.TrimPrefix(word, "--"), "=")
	if !strings.HasPrefix(word, "--") || name == "" {
		return nil
	}
	var readings []string
	for _, d := range gitDestructiveOptions {
		if strings.HasPrefix(d.option, name) {
			readings = append(readings, d.command+" --"+d.option)
		}
	}
	return readings
}
