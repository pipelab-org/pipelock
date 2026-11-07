// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package policy

import (
	"encoding/json"
	"regexp"
	"slices"
	"strings"
	"unicode/utf8"
)

// CheckShellCommand checks a known shell program. Only the shipped command
// patterns in shellDataProofRules can use the literal-data proof, and only
// Destructive Git Operation the dry-run proof; every other rule and every
// unproved program keeps the ordinary whole-script matching views.
func (pc *Config) CheckShellCommand(command string, rawArgs json.RawMessage) Verdict {
	args := []string{command}
	return pc.checkToolCallWithArgs("bash", args, rawArgs, toolCallOptions{
		checkInput: true, proofArgs: args, proofShape: rawArgs, shell: proveShellRules(command),
	})
}

type shellProofWord struct {
	value                          string
	start, end                     int
	literal, fullyQuoted, operator bool
}

type shellRuleProof struct {
	data, clean []argView
}

func (p *shellRuleProof) views(rule *CompiledRule) ([]argView, bool) {
	if p == nil || rule.ArgPattern == nil || rule.ArgKey != nil || rule.ArgSource != "" {
		return nil, false
	}
	pattern := rule.ArgPattern.String()
	if !slices.ContainsFunc(shellDataProofRules, func(name string) bool { return pattern == shippedShellPatterns[name] }) {
		return nil, false
	}
	if p.data != nil {
		return p.data, true
	}
	if pattern == shippedShellPatterns["Destructive Git Operation"] && p.clean != nil {
		return p.clean, true
	}
	return nil, false
}

// shellDataProofRules are the shipped rules that describe running a command.
// When the whole script is proved to be read-only utilities given literal data,
// a match inside that data is text, not a command. Rules about which file a
// command touches, such as credential reads, are deliberately absent: there the
// data is the target.
var shellDataProofRules = []string{
	"Destructive Git Operation", "Reverse Shell", "Destructive File Delete", "Recursive Permission Change",
}

var shippedShellPatterns = func() map[string]string {
	patterns := make(map[string]string)
	for _, rule := range DefaultToolPolicyRules() {
		if slices.Contains(shellDataProofRules, rule.Name) {
			patterns[rule.Name] = rule.ArgPattern
		}
	}
	return patterns
}()

var (
	shellResolutionVariable = regexp.MustCompile(`(?:^|[^a-zA-Z0-9_])(?:PATH|BASH_ENV|ENV)(?:$|[^a-zA-Z0-9_])`)
	shellCleanOccurrence    = regexp.MustCompile(shellCommandStart + `git[ \t]+clean\b`)
	// Output conversions from bash(1) printf and printf(3). %n assigns a
	// variable, including with width/length modifiers, so is never inert.
	shellPrintfOutput = regexp.MustCompile(`^(?:[^%]|%%|%[-+ #0']*(?:[0-9]+|\*)?(?:\.(?:[0-9]+|\*))?[hlLjzt]*[cCsSdiouxXeEfFgGaAbqQ])*$`)
)

func proveShellRules(source string) *shellRuleProof {
	words, ok := shellProofWords(source)
	if !ok || len(words) == 0 {
		return nil
	}
	p := &shellRuleProof{}
	cleanText, cleanProved := shellCleanPreviews(source, words)
	if cleanProved {
		p.clean = buildArgViews([]string{cleanText}, false, nil, true)
	}
	if text, proved := shellLiteralData(source, words, cleanProved); proved {
		p.data = buildArgViews([]string{text}, false, nil, true)
	}
	return p
}

// shellProofWords is a deliberately partial reader of bash(1) Quoting, Shell
// Expansions and Shell Grammar. It never executes or resolves expansions.
// Unquoted brace/glob/tilde syntax and any expansion withhold literal proof.
// Operators are retained, so only the allowlisted top-level lists below can
// grant a data proof. Braces/parentheses can surround a literal preview in a
// function, but cannot grant a data proof.
func shellProofWords(source string) ([]shellProofWord, bool) {
	// bash(1), DEFINITIONS: a blank is space or tab; newline is a
	// metacharacter, not a blank. Other C0 controls and DEL are not modeled
	// here, even inside quotes. Refuse the whole source (also invalid UTF-8)
	// so neither preview nor data proofs can replace whole-script matching.
	if !utf8.ValidString(source) {
		return nil, false
	}
	for _, c := range source {
		if c < ' ' && c != '\t' && c != '\n' || c == '\x7f' {
			return nil, false
		}
	}
	var words []shellProofWord
	for i := 0; i < len(source); {
		c := source[i]
		if strings.ContainsRune(" \t", rune(c)) {
			i++
			continue
		}
		if strings.ContainsRune(";|&()<>\n", rune(c)) || (c == '{' || c == '}') && (i+1 == len(source) || strings.ContainsRune(" \t\n;", rune(source[i+1]))) {
			end := i + 1
			if end < len(source) && source[end] == c && strings.ContainsRune(";|&<>", rune(c)) {
				end++
			}
			words = append(words, shellProofWord{value: source[i:end], start: i, end: end, literal: true, operator: true})
			i = end
			continue
		}
		// Comments need a full shell grammar to establish their extent in
		// substitutions and here-documents. They withhold these exceptions.
		if c == '#' {
			return nil, false
		}
		w := shellProofWord{start: i, literal: true}
		var value strings.Builder
		var quote byte
		quoted, unquoted := false, false
		for i < len(source) {
			c = source[i]
			if quote == 0 && strings.ContainsRune(" \t\n;|&()<>", rune(c)) {
				break
			}
			if c == '\\' && quote != '\'' {
				// Escapes remain conservative (including ANSI-C quoting).
				return nil, false
			}
			if c == '\'' || c == '"' {
				if quote == 0 {
					quote = c
					quoted = true
					i++
					continue
				}
				if quote == c {
					quote = 0
					i++
					continue
				}
			}
			if quote != '\'' && (c == '$' || c == '`') {
				w.literal = false
			}
			if quote == 0 {
				unquoted = true
				if strings.ContainsRune("*?{}~", rune(c)) {
					w.literal = false
				}
			}
			value.WriteByte(c)
			i++
		}
		if quote != 0 {
			return nil, false
		}
		w.value, w.end, w.fullyQuoted = value.String(), i, quoted && !unquoted
		if unquoted && strings.Contains(w.value, "[") && strings.Contains(w.value, "]") {
			w.literal = false
		}
		words = append(words, w)
	}
	return words, true
}

// shellCleanPreviews changes only the clean word of proved previews; matching
// still reads the entire script and retains all other command/argument text.
func shellCleanPreviews(source string, words []shellProofWord) (string, bool) {
	// Reuse the policy word normalizer (normalizeArgTokensRead) for every
	// visible override check. The proof reader first refuses expansions and
	// unsupported escapes, so normalization cannot turn uncertainty into proof.
	normalized := make([]string, len(words))
	for i, w := range words {
		if !w.literal {
			return "", false
		}
		_, normalized[i] = normalizeArgTokensUnexpanded([]string{source[w.start:w.end]}, func(s string) string { return s }, nil)
		if shellResolutionVariable.MatchString(normalized[i]) {
			return "", false
		}
	}
	for i := range words {
		switch normalized[i] {
		// A standalone "." is treated like source wherever it appears: after
		// reserved words (then, do, else, !, time, ...) it is still a command
		// word, and a sourced file can redefine git or PATH. Refusing every
		// position errs toward the existing whole-script match.
		case "enable", "hash", "alias", "unalias", "source", ".", "eval", "exec", "command_not_found_handle", "trap", "unset", "let":
			return "", false
		case "git":
			// Any function body form, not only the brace spelling.
			if i+1 < len(words) && normalized[i+1] == "(" || i > 0 && normalized[i-1] == "function" {
				return "", false
			}
		case "printf":
			for j := i + 1; j < len(words) && !words[j].operator; j++ {
				// bash accepts the variable name attached (-vNAME) as well as separate.
				if strings.HasPrefix(normalized[j], "-v") || !shellPrintfOutput.MatchString(normalized[j]) && strings.Contains(normalized[j], "%") {
					return "", false
				}
			}
		case "cd", "pushd", "popd":
			if strings.Contains(strings.Join(normalized, " "), "CDPATH") {
				return "", false
			}
			// Inherited-environment executable substitution is outside
			// command-text policy: ordinary bare git after cd is allowed too.
			// Literal directory changes alone therefore do not revoke this
			// proof. Dynamic targets and cd - remain conservative.
			for j := i + 1; j < len(words) && !words[j].operator; j++ {
				if normalized[j] == "-" {
					return "", false
				}
			}
		}
	}
	var spans []shellProofWord
	for i := 0; i+1 < len(words); i++ {
		if words[i].operator || words[i].value != "git" || words[i+1].value != "clean" {
			continue
		}
		end := i + 2
		values := []string{"git", "clean"}
		for end < len(words) && !words[end].operator {
			values = append(values, words[end].value)
			end++
		}
		if !shellDryClean(values) {
			return "", false
		}
		spans = append(spans, words[i+1])
	}
	// A quoted program, nonliteral spelling, or extra non-dry occurrence must
	// not be hidden by a preview elsewhere in the script.
	if len(spans) == 0 || len(spans) != len(shellCleanOccurrence.FindAllStringIndex(source, -1)) {
		return "", false
	}
	return shellMaskWords(source, spans), true
}

// shellDryClean follows git-clean(1): -n/--dry-run only lists, even with -f.
// The existing Git option table supplies long names, abbreviations and values.
// --no-dry-run anywhere revokes proof; -e consumes its pattern and -- ends
// option parsing. Every operand's literal status is checked by the caller.
func shellDryClean(words []string) bool {
	if len(words) < 3 || words[0] != "git" || words[1] != "clean" {
		return false
	}
	dry := false
	for i := 2; i < len(words); i++ {
		word := words[i]
		if word == "--" {
			break
		}
		if strings.HasPrefix(word, "--") {
			names, _, hasValue := matchLongOption(word, commandLongOptions["clean"])
			if len(names) != 1 {
				return false
			}
			switch names[0] {
			case "dry-run":
				if hasValue {
					return false
				}
				dry = true
			case "no-dry-run":
				return false
			case "exclude":
				if !hasValue {
					i++
					if i == len(words) {
						return false
					}
				}
			}
			continue
		}
		if !strings.HasPrefix(word, "-") {
			continue
		}
		for j := 1; j < len(word); j++ {
			switch word[j] {
			case 'n':
				dry = true
			case 'e':
				if j == len(word)-1 {
					i++
					if i == len(words) {
						return false
					}
				}
				j = len(word)
			case 'f', 'd', 'x', 'X', 'i', 'q':
			default:
				return false
			}
		}
	}
	return dry
}

func shellMaskWords(source string, spans []shellProofWord) string {
	masked := []byte(source)
	for _, w := range spans {
		for i := w.start; i < w.end; i++ {
			masked[i] = ' '
		}
	}
	return string(masked)
}

// This is the whole-script read-only gate: bash(1) Shell Grammar, Redirection
// and Shell Builtin Commands. Only literal simple commands joined by lists
// qualify. No pipeline, redirection, compound command or state change qualifies.
func shellLiteralData(source string, words []shellProofWord, cleanProved bool) (string, bool) {
	var statements [][]shellProofWord
	start := 0
	directoryChanged := false
	for i, w := range words {
		if !w.literal || shellAssignment.MatchString(source[w.start:w.end]) {
			return "", false
		}
		if w.operator {
			switch w.value {
			case ";", "\n", "&&", "||":
				if i > start {
					statements = append(statements, words[start:i])
				}
				start = i + 1
			default:
				return "", false
			}
		}
	}
	if start < len(words) {
		statements = append(statements, words[start:])
	}
	for _, st := range statements {
		if !shellReadOnlyCommand(st) {
			return "", false
		}
		directoryChanged = directoryChanged || st[0].value == "cd"
	}
	var spans []shellProofWord
	for _, st := range statements {
		name := st[0].value
		if name == "git" {
			if !cleanProved {
				return "", false
			}
			// The whole-script gate already proved this is a literal preview.
			spans = append(spans, st[1])
		}
		if directoryChanged && name != "echo" && name != "printf" {
			continue
		}
		if !shellDataUtility(st, name) {
			continue
		}
		for _, w := range st[1:] {
			if w.fullyQuoted {
				spans = append(spans, w)
			}
		}
	}
	if len(spans) == 0 {
		return "", false
	}
	return shellMaskWords(source, spans), true
}

// Ordinary filters follow their section-1/coreutils manuals. This fixed set
// and the option restrictions are the read-only gate, not a shell evaluator.
func shellReadOnlyCommand(words []shellProofWord) bool {
	name := words[0].value
	switch name {
	case "echo", "printf", "grep", "egrep", "fgrep", "rg", "sed":
		return shellDataUtility(words, name)
	case "cat", "ls", "head", "tail", "wc", "true", "false", "cut", "tr", "basename", "dirname", "pwd", "cd":
		return true
	case "test", "[":
		for _, w := range words[1:] {
			if w.value == "-v" || w.value == "-R" {
				return false
			}
		}
		return true
	case "sort", "uniq", "date":
		return len(words) == 1
	case "git":
		values := make([]string, len(words))
		for i, w := range words {
			values[i] = w.value
		}
		return shellDryClean(values)
	}
	return false
}

func shellDataUtility(words []shellProofWord, name string) bool {
	if len(words) == 0 || words[0].value != name {
		return false
	}
	switch name {
	case "echo", "grep", "egrep", "fgrep":
		return true
	case "printf":
		for _, w := range words {
			// -v NAME and the attached -vNAME both assign instead of printing.
			if strings.HasPrefix(w.value, "-v") {
				return false
			}
		}
		format := 1
		if len(words) > format && words[format].value == "--" {
			format++
		}
		return len(words) <= format || shellPrintfOutput.MatchString(words[format].value)
	case "rg":
		for _, w := range words {
			if strings.HasPrefix(w.value, "--pre") || strings.HasPrefix(w.value, "--hostname-bin") {
				return false
			}
		}
		return true
	case "sed":
		if len(words) != 4 || words[1].value != "-n" || strings.HasPrefix(words[3].value, "-") {
			return false
		}
		pattern := words[2].value
		return len(pattern) >= 3 && strings.HasPrefix(pattern, "/") && strings.HasSuffix(pattern, "/p") && !strings.ContainsAny(pattern[1:len(pattern)-2], "/\\\n")
	}
	return false
}
