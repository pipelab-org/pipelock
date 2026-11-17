// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package policy

import (
	"slices"
	"strings"
)

// This file reads the assignments a command text makes to its own variables.
//
// The reader does not follow the order a shell would run the text in. Loops,
// functions, conditionals, traps and eval all run text later or not at all,
// quotes are gone by the time this runs so quoted text cannot be told from
// commands, and a reader that guesses which assignment a use sees is wrong
// in one of them. Instead a use reads every value its name is assigned
// anywhere in the text: the command that contains the use is written once
// per value, so the deny rules see each command the text could run. That
// costs an extra match on a value the shell would not have used, and needs
// no model of control flow.
//
// Three bounds keep that safe:
//
//   - Work (shellBounds.work): every byte read, written or built is charged
//     to one bound, linear in the input. Text that cannot be read within it
//     is refused, and the caller blocks.
//   - Copies (shellBounds.copies): the rules that run after this reader cost
//     time for every byte, so the extra copies have a smaller budget. Past
//     it a use is read with its first value only and the reading is marked
//     partial, which the caller reports as an incomplete check.
//   - Passes: text still changing after maxShellConstructionPasses is
//     refused.
//
// It reads NAME=VALUE and NAME+=VALUE text only. Values a program produces at
// run time (read, a for list, command output other than a literal echo or
// printf, arrays, ${name:offset} and the other operator forms) are outside
// it, and so is a value built by appends a script repeats or skips;
// docs/bypass-resistance.md lists those limits.

// assignSpan is one shell assignment. The value is s[valueStart:valueEnd].
//
// "x=rm;$x" hides the command name. "IFS=,;CMD=r,m;$CMD" assigns "," and
// "r,m".
type assignSpan struct {
	name                 string
	opStart              int
	valueStart, valueEnd int
	appends              bool
	// selfRef is set for "+=" and for a value that names its own variable.
	selfRef bool
	// chained is set when the assignment is ended by another assignment on
	// the same line and not by a separator.
	chained bool
	// soft is set when the assignment survives because the command has no
	// literal command word: a redirection, or a parameter expansion where a
	// command name would be. A separator did not end it.
	soft bool
	// maybeKept is set when only a special builtin keeps the assignment: sh
	// keeps it and bash drops it, so uses also read the name as unset.
	maybeKept bool
}

func isShellSpaceByte(c byte) bool {
	return c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\f'
}

// shellAssignmentAt reports whether a name followed by "=" or "+=" starts at
// s[i].
func shellAssignmentAt(s string, i int) bool {
	start := i
	for i < len(s) && isShellNameByte(s[i]) {
		i++
	}
	if i == start || i == len(s) {
		return false
	}
	return s[i] == '=' || (s[i] == '+' && i+1 < len(s) && s[i+1] == '=')
}

// assignSpansIn returns the assignments in s, in one scan. An assignment is
// a name, "=" or "+=", a value with no whitespace or shell metacharacter in
// it, and then a separator: ";", "&", "&&", "|", "||", "<", ">", a newline,
// or the end of the text. Another assignment after spaces ends it too. The
// value may be empty, so IFS= is an assignment. A comment after whitespace
// is not part of the value. NAME=value followed by a command word is that
// command's environment, not an assignment the rest of the text reads, and
// is skipped. A redirection is not a command word: NAME=value >/path still
// assigns. export, declare, typeset, local and readonly assign even when
// another operand follows.
//
// A name that follows "$" is a parameter reference, not an assignment:
// awk's `$1=$2=""` and the text `$a=$b=` assign nothing. A ")" that closes
// a subshell or a function body is not part of the value.
//
// With wanted set, only assignments to those names and to IFS are returned;
// a long list of assignments nothing reads then costs no memory.
func assignSpansIn(s string, wanted map[string]struct{}) []assignSpan {
	var out []assignSpan
	cur := assignCursor{s: s}
	for i := 0; i < len(s); {
		if !isShellNameByte(s[i]) {
			i++
			continue
		}
		nameStart := i
		for i < len(s) && isShellNameByte(s[i]) {
			i++
		}
		opStart := i
		appends := i+1 < len(s) && s[i] == '+' && s[i+1] == '='
		if appends {
			i += 2
		} else if i < len(s) && s[i] == '=' {
			i++
		} else {
			continue
		}
		valueStart := i
		opens, closes := 0, 0
		for i < len(s) && !endsAssignValue(s, i) {
			switch s[i] {
			case '(':
				opens++
			case ')':
				closes++
			}
			i++
		}
		valueEnd := i
		chained := false
		soft := false
		maybeKept := false
		// A comment runs to the end of its line.
		j := i
		for j < len(s) && (s[j] == ' ' || s[j] == '\t') {
			j++
		}
		if j > i && j < len(s) && s[j] == '#' {
			for j < len(s) && s[j] != '\n' {
				j++
			}
		} else {
			j = i
		}
		// The separator: the next ";", "&" or "|", the end of the text, or
		// failing those the last newline in the whitespace after the value.
		newline := -1
		for j < len(s) && isShellSpaceByte(s[j]) {
			if s[j] == '\n' {
				newline = j
			}
			j++
		}
		switch {
		case j == len(s):
		case s[j] == ';':
			j++
		case s[j] == '&' || s[j] == '|':
			if j+1 < len(s) && s[j+1] == s[j] {
				j++
			}
			j++
		case newline >= 0:
			j = newline + 1
		case shellAssignmentAt(s, j):
			// "A=r B=m;" and "export A=r B=m" assign both names. The scan
			// resumes at the next assignment.
			chained = true
			// "C=x D=y :" is kept by sh and dropped by bash for both names.
			maybeKept = cur.persists(nameStart) && keptOnlyBySpecialBuiltin(s, cur.cmdLo, cur.cmdHi)
		default:
			// "A=r >/tmp/x" and "export A=r dummy" still assign. "A=r cmd"
			// does not: the value is that command's environment. "A=r $u"
			// does: an expansion is not a command word until it runs.
			if !cur.persists(nameStart) {
				continue
			}
			soft = true
			maybeKept = cur.cmdOK && keptOnlyBySpecialBuiltin(s, cur.cmdLo, cur.cmdHi)
		}
		i = j
		if nameStart > 0 && s[nameStart-1] == '$' {
			continue
		}
		name := s[nameStart:opStart]
		if wanted != nil && name != "IFS" {
			if _, ok := wanted[name]; !ok {
				continue
			}
		}
		for valueEnd > valueStart && s[valueEnd-1] == ')' && opens < closes {
			valueEnd--
			closes--
		}
		out = append(out, assignSpan{
			name:       name,
			opStart:    opStart,
			valueStart: valueStart,
			valueEnd:   valueEnd,
			appends:    appends,
			chained:    chained,
			soft:       soft,
			maybeKept:  maybeKept,
		})
	}
	return out
}

// endsAssignValue reports whether s[i] ends an assignment value. A
// backslash keeps a "<" or ">" in the value; the shell removes that
// backslash later, with the other escapes.
func endsAssignValue(s string, i int) bool {
	if isShellSpaceByte(s[i]) || s[i] == ';' || s[i] == '&' || s[i] == '|' {
		return true
	}
	return (s[i] == '<' || s[i] == '>') && (i == 0 || s[i-1] != '\\')
}

// assignCursor remembers the simple command it already classified. The
// cursor only moves forward, so classifying every assignment is one pass.
type assignCursor struct {
	s            string
	cmdLo, cmdHi int
	cmdOK        bool
	valid        bool
}

func (c *assignCursor) persists(nameStart int) bool {
	if c.valid && nameStart >= c.cmdLo && nameStart < c.cmdHi {
		return c.cmdOK
	}
	pos := 0
	if c.valid && nameStart >= c.cmdHi {
		pos = skipCommandSep(c.s, c.cmdHi)
	}
	for {
		end := nextSimpleCommandEnd(c.s, pos)
		if nameStart < end || end >= len(c.s) {
			c.cmdLo = pos
			c.cmdHi = end
			c.cmdOK = end > pos && commandAssignsPersist(c.s, pos, end)
			c.valid = true
			return c.cmdOK
		}
		next := skipCommandSep(c.s, end)
		if next <= pos {
			c.cmdLo = pos
			c.cmdHi = len(c.s)
			c.cmdOK = false
			c.valid = true
			return false
		}
		pos = next
	}
}

// commandAssignsPersist reports whether a simple command's assignments
// survive it. A redirection is not a command, so "A=r >/path" assigns.
// A parameter expansion is not a command word either: "A=r $u" assigns
// when u is empty, and the text is read that way when u has a value too.
// export, declare, typeset, local and readonly assign even with another
// operand. "A=r cmd" does not: the value belongs to cmd.
// Once a redirection precedes any command word, keep the assignment even
// if another word follows. Quotes are already gone: a spaced target and
// a later command word cannot be distinguished. Reading an extra value is
// safer than missing the assignment in A=r >"output file" or A=r > >(true).
func commandAssignsPersist(s string, start, end int) bool {
	return commandAssignsPersistIn(s, start, end, keptByBuiltin)
}

// commandAssignsPersistIn is commandAssignsPersist with the command words that
// keep an assignment chosen by keeps.
func commandAssignsPersistIn(s string, start, end int, keeps func(string) bool) bool {
	if commandWordIsAssigningBuiltin(s, start, end, keeps) {
		return true
	}
	sawRedirect, sawExpansion, foreign := classifyCommand(s, start, end)
	return sawRedirect || (!foreign && sawExpansion)
}

// keptOnlyBySpecialBuiltin reports whether the command word is a special
// builtin, which sh keeps the prefix assignments of and bash drops, even when
// a redirection comes first ("C=x >/dev/null :").
func keptOnlyBySpecialBuiltin(s string, start, end int) bool {
	return commandWordIsAssigningBuiltin(s, start, end, shellSpecialBuiltin) &&
		!commandWordIsAssigningBuiltin(s, start, end, shellAssigningBuiltin)
}

func keptByBuiltin(w string) bool {
	return shellAssigningBuiltin(w) || shellSpecialBuiltin(w)
}

func commandWordIsAssigningBuiltin(s string, start, end int, keeps func(string) bool) bool {
	i := skipConditionPrefix(s, start, end)
	afterWrapper := false
	for i < end {
		i = skipShellBlank(s, i, end)
		if i >= end || commandBoundary(s, i) {
			return false
		}
		if redirectionAt(s, i) {
			i = skipRedirection(s, i, end)
			continue
		}
		if processSubstAt(s, i) || s[i] == '(' {
			return false
		}
		if shellReservedByte(s, i, end) {
			if s[i] == '!' {
				afterWrapper = true
			}
			i++
			continue
		}
		w0 := i
		i = skipPlainWord(s, i, end)
		if i == w0 {
			return false
		}
		word := s[w0:i]
		switch {
		case shellWrapperWord(word):
			afterWrapper = true
		case shellAssignmentWord(word):
		case keeps(word):
			return true
		case afterWrapper && word[0] == '-':
		default:
			return false
		}
	}
	return false
}

// classifyCommand reports whether the command redirects, whether it has a
// parameter expansion where a command word would be, and whether it has a
// literal command word. A process substitution is a literal word: the
// assignment in front of it does not survive. "$name" and "${name}" are not.
func classifyCommand(s string, start, end int) (sawRedirect, sawExpansion, foreign bool) {
	i := skipConditionPrefix(s, start, end)
	for i < end {
		i = skipShellBlank(s, i, end)
		if i >= end || commandBoundary(s, i) || s[i] == '#' {
			return sawRedirect, sawExpansion, false
		}
		if redirectionAt(s, i) {
			sawRedirect = true
			i = skipRedirection(s, i, end)
			continue
		}
		if processSubstAt(s, i) || s[i] == '(' {
			return sawRedirect, sawExpansion, true
		}
		if shellReservedByte(s, i, end) {
			i++
			continue
		}
		if s[i] == '$' || s[i] == '`' {
			sawExpansion = true
			i = skipExpansionWord(s, i, end)
			continue
		}
		w0 := i
		i = skipPlainWord(s, i, end)
		if i == w0 {
			return sawRedirect, sawExpansion, true
		}
		word := s[w0:i]
		if shellWrapperWord(word) || shellAssigningBuiltin(word) || shellAssignmentWord(word) {
			continue
		}
		return sawRedirect, sawExpansion, true
	}
	return sawRedirect, sawExpansion, false
}

// skipExpansionWord consumes one $name or ${...} starting at s[i].
func skipExpansionWord(s string, i, end int) int {
	if i >= end {
		return i
	}
	i++
	if i < end && s[i] == '{' {
		i++
		for i < end && s[i] != '}' && !commandBoundary(s, i) {
			i++
		}
		if i < end && s[i] == '}' {
			i++
		}
		return i
	}
	for i < end && !plainWordEnd(s[i]) {
		i++
	}
	return i
}

func shellWrapperWord(w string) bool {
	switch w {
	case "command", "builtin", "time", "then", "do", "else", "elif":
		return true
	default:
		return false
	}
}

// Conditions start a command; the same word after an assignment does not.
func skipConditionPrefix(s string, start, end int) int {
	for start < end {
		i := skipShellBlank(s, start, end)
		j := skipPlainWord(s, i, end)
		switch s[i:j] {
		case "if", "while", "until", "then", "do", "else", "elif":
			start = j
		default:
			return start
		}
	}
	return start
}

func shellAssigningBuiltin(w string) bool {
	switch w {
	case "export", "declare", "typeset", "local", "readonly":
		return true
	default:
		return false
	}
}

// shellConditionalAt reports, for each offset in at (ascending), whether an
// assignment starting there may not run: it is inside a group, subshell,
// condition, loop, case or function body, or follows "&&", "||" or "|" in
// its own statement. "$(", "${", "<(" and ">(" are expansions, not groups.
func shellConditionalAt(s string, at []int) map[int]bool {
	out := make(map[int]bool, len(at))
	depth, gated := 0, false
	var groups []bool // true for a group that counts toward depth
	// cmdPos: the next word is a command word, where reserved words count.
	// "echo fi" does not close an if.
	cmdPos := true
	next := 0
	for i := 0; i < len(s) && next < len(at); i++ {
		for next < len(at) && at[next] == i {
			out[at[next]] = depth > 0 || gated || shellStatementForks(s, i)
			next++
		}
		switch c := s[i]; c {
		case '&', '|':
			if i+1 < len(s) && s[i+1] == c {
				gated = true
				i++
			} else {
				// A single "&" ends a statement; what follows "|" runs in a
				// subshell. The assignment before either is caught by
				// shellStatementForks.
				gated = c == '|'
			}
			cmdPos = true
		case ';', '\n':
			gated = false
			cmdPos = true
		case '(', '{':
			counts := i == 0 || (s[i-1] != '$' && s[i-1] != '<' && s[i-1] != '>')
			groups = append(groups, counts)
			if counts {
				depth++
			}
			cmdPos = true
		case ')', '}':
			if n := len(groups); n > 0 {
				if groups[n-1] {
					depth--
				}
				groups = groups[:n-1]
			}
		case '\'', '"':
			// Quoted text is data: skip to the closing quote. An unclosed
			// quote runs to the end. An assignment the skip passes over is
			// read as conditional.
			to := len(s) - 1
			if k := strings.IndexByte(s[i+1:], c); k >= 0 {
				to = i + 1 + k
			}
			next = markSkipped(out, at, next, to)
			i = to
			cmdPos = false
		case '#':
			if i == 0 || isShellSpaceByte(s[i-1]) || strings.IndexByte(";&|(<>", s[i-1]) >= 0 {
				to := len(s) - 1
				if k := strings.IndexByte(s[i:], '\n'); k >= 0 {
					to = i + k - 1
				}
				next = markSkipped(out, at, next, to)
				i = to
			}
		case '!':
			// Pipeline negation only as a word of its own in command
			// position: "echo !fi" is an argument, and its fi closes nothing.
			cmdPos = cmdPos && (i+1 >= len(s) || isShellSpaceByte(s[i+1]) || s[i+1] == '(' || s[i+1] == '{')
		case ' ', '\t':
		default:
			if !isShellNameByte(c) || (i > 0 && isShellNameByte(s[i-1])) {
				cmdPos = false
				continue
			}
			j := i
			for j < len(s) && isShellNameByte(s[j]) {
				j++
			}
			assign := j < len(s) && (s[j] == '=' || s[j] == '+' && j+1 < len(s) && s[j+1] == '=')
			if cmdPos && !assign {
				// Reserved words count only as command words: "echo if" opens
				// nothing and "echo fi" closes nothing.
				switch s[i:j] {
				case "if", "while", "until", "for", "case", "select":
					depth++
				case "fi", "done", "esac":
					depth = max(depth-1, 0)
				}
			}
			switch s[i:j] {
			case "if", "while", "until", "then", "do", "else", "elif", "time", "!":
				cmdPos = !assign
			default:
				cmdPos = assign && cmdPos
			}
			if next < len(at) && at[next] < j {
				i = at[next] - 1
				continue
			}
			i = j - 1
		}
	}
	return out
}

// markSkipped marks every pending offset up to and including to as
// conditional and returns the index of the first one after it.
func markSkipped(out map[int]bool, at []int, next, to int) int {
	for next < len(at) && at[next] <= to {
		out[at[next]] = true
		next++
	}
	return next
}

// shellStatementForks reports whether the statement holding offset i ends in
// a pipe or "&" before its ";", newline, "&&" or "||": its assignments then
// run in a subshell or in the background.
func shellStatementForks(s string, i int) bool {
	for ; i < len(s); i++ {
		switch c := s[i]; c {
		case ';', '\n':
			return false
		case '\'', '"', '`', '\\', '(', '#':
			// Quoting, a substitution or a comment can hide the end of the
			// statement: read the assignment as conditional.
			return true
		case '&', '|':
			if i+1 < len(s) && s[i+1] == c {
				return false
			}
			if c == '&' && (s[i-1] == '>' || s[i-1] == '<' || i+1 < len(s) && s[i+1] == '>') {
				continue
			}
			return true
		}
	}
	return false
}

// shellUnsetsName reports whether the text unsets name with the unset
// builtin anywhere.
func shellUnsetsName(s, name string) bool {
	for i := 0; ; {
		k := strings.Index(s[i:], "unset")
		if k < 0 {
			return false
		}
		k += i
		i = k + len("unset")
		if k > 0 && isShellNameByte(s[k-1]) {
			continue
		}
		rest := s[i:]
		end := strings.IndexAny(rest, ";&|\n")
		if end < 0 {
			end = len(rest)
		}
		for _, w := range strings.Fields(rest[:end]) {
			// unset "$v" names a variable we cannot read: assume any.
			if strings.ContainsAny(w, "$`") || strings.Trim(w, `"'\`) == name {
				return true
			}
		}
	}
}

// shellSpecialBuiltin names the POSIX special builtins. In sh, "A=r :" keeps
// A after the command; bash keeps it only in POSIX mode. A command can run
// under either, so the assignment is read as kept.
func shellSpecialBuiltin(w string) bool {
	switch w {
	case ":", ".", "eval", "exec", "exit", "return", "set", "shift", "times", "trap", "unset":
		return true
	default:
		return false
	}
}

func shellAssignmentWord(w string) bool {
	i := 0
	for i < len(w) && isShellNameByte(w[i]) {
		i++
	}
	if i == 0 || i == len(w) {
		return false
	}
	if w[i] == '=' {
		return true
	}
	return w[i] == '+' && i+1 < len(w) && w[i+1] == '='
}

func shellReservedByte(s string, i, end int) bool {
	if i >= end {
		return false
	}
	switch s[i] {
	case '{', '}', '!':
		return i+1 >= end || plainWordEnd(s[i+1])
	default:
		return false
	}
}

func skipShellBlank(s string, i, end int) int {
	for i < end && (s[i] == ' ' || s[i] == '\t' || s[i] == '\r' || s[i] == '\f') {
		i++
	}
	return i
}

func skipPlainWord(s string, i, end int) int {
	start := i
	for i < end && !plainWordEnd(s[i]) {
		i++
	}
	if i == start && i < end {
		return i + 1
	}
	return i
}

func plainWordEnd(c byte) bool {
	return c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\f' ||
		c == ';' || c == '|' || c == '&' || c == '<' || c == '>' ||
		c == '(' || c == ')' || c == '{' || c == '}'
}

// commandBoundary is a separator between simple commands. "(" and ")" bound
// a subshell or a function body. The "(" of a process substitution does not:
// that substitution is a word of the current command. "&" and "|" after a
// redirection ("&>", ">&", ">|") are part of the redirection.
func commandBoundary(s string, i int) bool {
	if i >= len(s) {
		return true
	}
	switch s[i] {
	case ';', '\n', ')':
		return true
	case '(':
		return !processSubstAt(s, i-1)
	case '{':
		// A group starts a new command even after a named coprocess or
		// a function declaration. ${name} and {fd}>path are words instead.
		return shellReservedByte(s, i, len(s))
	case '|':
		return i == 0 || (s[i-1] != '>' && s[i-1] != '<')
	case '&':
		if i > 0 && (s[i-1] == '>' || s[i-1] == '<') {
			return false
		}
		return i+1 >= len(s) || s[i+1] != '>'
	default:
		return false
	}
}

func processSubstAt(s string, i int) bool {
	return i >= 0 && i+1 < len(s) && (s[i] == '<' || s[i] == '>') && s[i+1] == '('
}

func nextSimpleCommandEnd(s string, pos int) int {
	for pos < len(s) {
		if commandBoundary(s, pos) {
			return pos
		}
		pos++
	}
	return len(s)
}

func skipCommandSep(s string, i int) int {
	if i >= len(s) {
		return i
	}
	switch s[i] {
	case ';', '\n', '(', ')':
		return i + 1
	case '&', '|':
		if i+1 < len(s) && s[i+1] == s[i] {
			return i + 2
		}
		return i + 1
	default:
		return i + 1
	}
}

func redirectionAt(s string, i int) bool {
	if i >= len(s) {
		return false
	}
	if s[i] == '&' && i+1 < len(s) && s[i+1] == '>' {
		return true
	}
	if s[i] == '{' && braceRedirect(s, i) {
		return true
	}
	j := i
	if s[j] >= '0' && s[j] <= '9' {
		for j < len(s) && s[j] >= '0' && s[j] <= '9' {
			j++
		}
		return j < len(s) && (s[j] == '<' || s[j] == '>') && !processSubstAt(s, j)
	}
	return (s[i] == '<' || s[i] == '>') && !processSubstAt(s, i)
}

func braceRedirect(s string, i int) bool {
	j := i + 1
	if j >= len(s) || !isBraceNameStart(s[j]) {
		return false
	}
	j++
	for j < len(s) && isShellNameByte(s[j]) {
		j++
	}
	if j >= len(s) || s[j] != '}' {
		return false
	}
	j++
	return j < len(s) && (s[j] == '<' || s[j] == '>') && !processSubstAt(s, j)
}

func isBraceNameStart(c byte) bool {
	return c == '_' || (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z')
}

func skipRedirection(s string, i, end int) int {
	if i >= end {
		return i
	}
	start := i
	if s[i] == '{' && braceRedirect(s, i) {
		i++
		for i < end && s[i] != '}' {
			i++
		}
		if i < end && s[i] == '}' {
			i++
		}
	}
	if i < end && s[i] == '&' && i+1 < end && s[i+1] == '>' {
		i++
	}
	for i < end && s[i] >= '0' && s[i] <= '9' {
		i++
	}
	op := i
	for i < end {
		c := s[i]
		switch {
		case c == '<' || c == '>':
			i++
		case c == '-' && i > op && (s[i-1] == '<' || s[i-1] == '>' || s[i-1] == '&'):
			i++
		case c == '&' && i > op && (s[i-1] == '<' || s[i-1] == '>'):
			i++
		case c == '|' && i > op && s[i-1] == '>' && (i+1 >= end || s[i+1] != '|'):
			i++
		default:
			c = 0
		}
		if c == 0 {
			break
		}
	}
	if i == start {
		return min(end, start+1)
	}
	// <&- and >&- close a descriptor. <<- still takes a delimiter.
	if i > op && s[i-1] == '-' {
		for k := op; k < i; k++ {
			if s[k] == '&' {
				return i
			}
		}
	}
	if i < end && !isShellSpaceByte(s[i]) && !commandBoundary(s, i) && !redirectionAt(s, i) {
		return skipPlainWord(s, i, end)
	}
	k := i
	for k < end && (s[k] == ' ' || s[k] == '\t') {
		k++
	}
	if k >= end || commandBoundary(s, k) || redirectionAt(s, k) || shellAssignmentAt(s, k) {
		return i
	}
	return skipPlainWord(s, k, end)
}

// shellUse is one $name, ${name} or ${!name in the text.
type shellUse struct {
	pos, end int
	name     string
	indirect bool
}

func shellUsesIn(s string) []shellUse {
	var out []shellUse
	for i := 0; i < len(s); {
		if s[i] != '$' {
			i++
			continue
		}
		name, consumed, indirect, ok := readShellExpansion(s, i)
		if !ok {
			i++
			continue
		}
		out = append(out, shellUse{pos: i, end: i + consumed, name: name, indirect: indirect})
		i += consumed
	}
	return out
}

// bracedShellRefs rewrites each bare $name in v as ${name}. A value is
// written next to other text, and "$a" followed by "m" would name a
// different variable.
func bracedShellRefs(v string) string {
	if !strings.Contains(v, "$") {
		return v
	}
	var b strings.Builder
	prev := 0
	for _, u := range shellUsesIn(v) {
		if u.indirect || v[u.pos+1] == '{' {
			continue
		}
		b.WriteString(v[prev:u.pos])
		b.WriteString("${")
		b.WriteString(u.name)
		b.WriteString("}")
		prev = u.end
	}
	if prev == 0 {
		return v
	}
	b.WriteString(v[prev:])
	return b.String()
}

// valueTemplate is one assignment's value text. refs are the $name and
// ${name} uses in it that name assigned variables; stamp is the sum of
// their value counts when the template was last expanded.
type valueTemplate struct {
	text  string
	refs  []shellUse
	stamp int
}

// distinctStrings is an ordered set. Most names hold one or two values, so
// it scans a short list and only builds a map for a long one.
type distinctStrings struct {
	list []string
	set  map[string]struct{}
}

const distinctStringsScan = 8

func (d *distinctStrings) has(v string) bool {
	if d.set != nil {
		_, ok := d.set[v]
		return ok
	}
	return slices.Contains(d.list, v)
}

// add reports whether v was new.
func (d *distinctStrings) add(v string) bool {
	if d.has(v) {
		return false
	}
	d.list = append(d.list, v)
	if d.set != nil {
		d.set[v] = struct{}{}
	} else if len(d.list) > distinctStringsScan {
		d.set = make(map[string]struct{}, 2*len(d.list))
		for _, e := range d.list {
			d.set[e] = struct{}{}
		}
	}
	return true
}

// assignedName collects what one variable is assigned across the text.
type assignedName struct {
	name string
	// plain holds the distinct value texts of assignments that do not name
	// the variable itself. selfBase is unset followed by plain, built when
	// a self-reference first needs it.
	plain    distinctStrings
	selfBase []string
	// templates are plain plus, for each assignment that names the variable
	// itself, that value with the self-reference filled in.
	templates []valueTemplate
	texts     distinctStrings
	// values is every string the variable can hold: the templates with the
	// variables they name replaced, to a fixed point. widest is the length
	// of the longest.
	values distinctStrings
	widest int
	// chain is the value built by the assignments read so far, in order.
	chain string
	// pos is the name's place in the order the text first assigns names.
	// deps are the names its templates reference; the rest is the state of
	// the search in components.
	pos        int
	deps       []*assignedName
	markedBy   *assignedName
	index, low int
	onStack    bool
}

// shellValueCost is charged for each value or template built, on top of its
// length: a short string still costs an allocation and a set entry.
const shellValueCost = 64

// shellSlot is a span of the text that one pass replaces. Slots that share a
// key take the same value in one copy of a command.
type shellSlot struct {
	pos, end int
	key      shellSlotKey
	prefix   string
	alts     []string
	// widest is the length of the longest of alts.
	widest int
	// mayUnset is set when the name can still be unset at this use.
	mayUnset bool
}

type shellSlotKey struct {
	name     string
	indirect bool
}

// maxShellSlotChoices caps the variables with more than one value that one
// command or value is read in combination for. Each at least doubles the
// copies, so more than this never fits the copy budget.
const maxShellSlotChoices = 30

// shellBounds is the limit one resolveShellConstruction call works under.
type shellBounds struct {
	// work is the bytes of reading and writing left for the whole call. It
	// starts at maxShellConstructionLen. Every pass spends its input
	// length, every byte it writes and every byte of every value it builds,
	// so neither the output, the values held nor the time taken can pass
	// that bound however the text is arranged.
	work int
	// copies is the bytes left for reading a command or a value more than
	// once. A use of a name with several values needs one copy per value,
	// and the rules after this reader cost time for every byte they are
	// given, so the copies are held to a budget of their own
	// (shellCopyBudget). A command or value whose copies do not fit is read
	// once, with the first value of each name, and partial is set: the
	// caller reports an incomplete check instead of a clean one.
	copies  int
	partial bool
}

// shellCopyBudget is the bytes of extra copies one call may write for an
// input of n bytes.
func shellCopyBudget(n int) int {
	return max(8<<10, n)
}

// fitsCopies reports whether count readings of at most width bytes each fit
// the copy budget beyond the first reading, and reserves nothing: the
// writer charges what it writes.
func (sb *shellBounds) fitsCopies(count, width int) bool {
	if count <= 1 {
		return true
	}
	return width == 0 || count-1 <= sb.copies/width
}

// spendCopies charges n bytes written beyond a first reading.
func (sb *shellBounds) spendCopies(n int) {
	sb.copies = max(sb.copies-n, 0)
}

func (sb *shellBounds) spend(n int) bool {
	if n > sb.work {
		return false
	}
	sb.work -= n
	return true
}

// shellValues computes the values of the assigned names in one text.
type shellValues struct {
	*shellBounds
	names    map[string]*assignedName
	order    []*assignedName
	ifsChars distinctStrings
}

func (sv *shellValues) addTemplate(n *assignedName, text string) bool {
	text = bracedShellRefs(text)
	if !n.texts.add(text) {
		return true
	}
	if !sv.spend(shellValueCost) {
		return false
	}
	t := valueTemplate{text: text, stamp: -1}
	for _, u := range shellUsesIn(text) {
		if _, assigned := sv.names[u.name]; assigned && !u.indirect && u.name != n.name {
			t.refs = append(t.refs, u)
		}
	}
	n.templates = append(n.templates, t)
	return true
}

// addValue records v, and v with each assigned IFS character removed.
// Reading a value without the IFS character is the safe over-approximation:
// an unquoted expansion would word-split, and the assembled command name is
// what policy has to see. The value as written stays too, because the IFS
// assignment might not run.
func (sv *shellValues) addValue(n *assignedName, v string) (added, fits bool) {
	add := func(v string) bool {
		if !n.values.add(v) {
			return true
		}
		added = true
		n.widest = max(n.widest, len(v))
		return sv.spend(shellValueCost)
	}
	if !add(v) {
		return false, false
	}
	if n.name == "IFS" {
		return added, true
	}
	for _, c := range sv.ifsChars.list {
		if !strings.Contains(v, c) {
			continue
		}
		if !sv.spend(len(v)) || !add(strings.ReplaceAll(v, c, "")) {
			return false, false
		}
	}
	return added, true
}

// unsetShellValue is what a name with no value reads as.
var unsetShellValue = []string{""}

// expand adds to n every value template t yields from the current values of
// the names it references. With unset false a template that references a
// name with no value yet is skipped; with unset true that name reads as
// empty, which is what the shell reads before any assignment runs.
func (sv *shellValues) expand(n *assignedName, t *valueTemplate, unset bool) (added, fits bool) {
	if len(t.refs) == 0 {
		if t.stamp == 0 {
			return false, true
		}
		t.stamp = 0
		return sv.addValue(n, t.text)
	}
	stamp := 0
	if unset {
		stamp = 1
	}
	for _, r := range t.refs {
		held := len(sv.names[r.name].values.list)
		if held == 0 && !unset {
			return false, true
		}
		stamp += held
	}
	if stamp == t.stamp {
		return false, true
	}
	slots := make([]shellSlot, len(t.refs))
	for i, r := range t.refs {
		m := sv.names[r.name]
		alts := m.values.list
		if len(alts) == 0 {
			alts = unsetShellValue
		}
		slots[i] = shellSlot{pos: r.pos, end: r.end, key: shellSlotKey{name: r.name}, alts: alts, widest: m.widest}
	}
	t.stamp = stamp
	choices := newShellChoices(slots)
	if !sv.fitsCopies(choices.count, choices.width(len(t.text))) {
		choices = shellChoices{slots: slots, count: 1}
		sv.partial = true
	}
	var b strings.Builder
	first := true
	fits = choices.each(func(pick func(int) string) bool {
		b.Reset()
		prev := 0
		for i, sl := range slots {
			b.WriteString(t.text[prev:sl.pos])
			b.WriteString(pick(i))
			prev = sl.end
			if b.Len() > sv.work {
				return false
			}
		}
		b.WriteString(t.text[prev:])
		if !sv.spend(b.Len()) {
			return false
		}
		if !first {
			sv.spendCopies(b.Len())
		}
		first = false
		a, ok := sv.addValue(n, b.String())
		added = added || a
		return ok
	})
	return added, fits
}

// maxShellCycleRounds caps how many times values are passed around a group
// of names that reference each other.
const maxShellCycleRounds = 8

// components groups the names into sets that reference each other, directly
// or through other names, and returns the sets with every set after the
// sets it references. A name outside any cycle is a set of one.
func (sv *shellValues) components() [][]*assignedName {
	for _, n := range sv.order {
		for ti := range n.templates {
			for _, r := range n.templates[ti].refs {
				m := sv.names[r.name]
				if m.markedBy != n {
					m.markedBy = n
					n.deps = append(n.deps, m)
				}
			}
		}
	}
	// Tarjan's strongly connected components, with an explicit stack: a
	// long chain of assignments must not become a deep recursion.
	type frame struct {
		n    *assignedName
		next int
	}
	var (
		out   [][]*assignedName
		stack []*assignedName
		call  []frame
		index int
	)
	visit := func(n *assignedName) {
		index++
		n.index, n.low, n.onStack = index, index, true
		stack = append(stack, n)
		call = append(call, frame{n: n})
	}
	for _, root := range sv.order {
		if root.index != 0 {
			continue
		}
		visit(root)
		for len(call) > 0 {
			top := len(call) - 1
			n := call[top].n
			if call[top].next < len(n.deps) {
				m := n.deps[call[top].next]
				call[top].next++
				if m.index == 0 {
					visit(m)
				} else if m.onStack {
					n.low = min(n.low, m.index)
				}
				continue
			}
			call = call[:top]
			if top > 0 {
				parent := call[top-1].n
				parent.low = min(parent.low, n.low)
			}
			if n.low != n.index {
				continue
			}
			var comp []*assignedName
			for {
				m := stack[len(stack)-1]
				stack = stack[:len(stack)-1]
				m.onStack = false
				comp = append(comp, m)
				if m == n {
					break
				}
			}
			out = append(out, comp)
		}
	}
	return out
}

// resolve gives every name its values. A name that references no cycle is
// expanded once, after the names it references, so a chain of any depth is
// exact. Names that reference each other are expanded in rounds, in the
// order the text assigns them: a value copied around the group (a swap, a
// saved and restored value) settles within the group's size, and a value
// that grows each time around (OLD=$PATH; PATH=$OLD:/x) is followed once
// around and then left, like any other value a script extends repeatedly.
// A group too large to pass a value all the way around within the round cap
// marks the reading partial. When a group has no value to start from, a
// missing one reads as unset, which is what the shell reads before any
// assignment has run.
func (sv *shellValues) resolve() bool {
	for _, comp := range sv.components() {
		if len(comp) == 1 {
			n := comp[0]
			for ti := range n.templates {
				if _, ok := sv.expand(n, &n.templates[ti], false); !ok {
					return false
				}
			}
			continue
		}
		slices.SortFunc(comp, func(a, b *assignedName) int { return a.pos - b.pos })
		unset := false
		for rounds := min(len(comp), maxShellCycleRounds); rounds > 0; {
			changed := false
			for _, n := range comp {
				for ti := range n.templates {
					added, ok := sv.expand(n, &n.templates[ti], unset)
					if !ok {
						return false
					}
					changed = changed || added
				}
			}
			if changed {
				rounds--
				// A group larger than the round cap can stop before a
				// value has been all the way around it. A group within the
				// cap has had a full lap; what still changes then is a value
				// that grows each time around, which is followed once.
				if rounds == 0 && len(comp) > maxShellCycleRounds {
					sv.partial = true
				}
				continue
			}
			if unset || !slices.ContainsFunc(comp, func(n *assignedName) bool { return len(n.values.list) == 0 }) {
				break
			}
			unset = true
		}
	}
	return true
}

// shellConstructionPass substitutes the assignments in s.
//
//   - $name and ${name} read every value assigned to name anywhere in s,
//     with the variables those values name already replaced. With IFS
//     assigned a single character, they also read each value with that
//     character removed, so CMD=r,m under IFS=, is read as rm.
//   - ${!name reads "${" followed by each value, so v=IFS;${!v} becomes
//     ${IFS}.
//   - NAME+=x and NAME=${NAME}x extend a value. The self-reference reads
//     the value built by the assignments written before it, every plain
//     value of the name, and unset, so PATH=$PATH:/x is finite. Appends
//     that a script skips on some runs, more than one deep, are not
//     followed.
//
// A command (the text between ";", "&&", "||", "&" and newlines) that uses a
// name with several values is written once per combination, each copy
// followed by the command's own separator, while the copies fit the copy
// budget; past it the command is written once with the first value of each
// name and sb.partial is set. A name with no assignment is left as written.
// A use is read as unset only when it comes before the name's first
// assignment.
//
// fits is false when the work left in sb runs out.
func shellConstructionPass(s string, sb *shellBounds) (out string, changed, fits bool) {
	uses := shellUsesIn(s)
	if len(uses) == 0 {
		return s, false, true
	}
	used := make(map[string]struct{})
	for _, u := range uses {
		used[u.name] = struct{}{}
	}
	spans := assignSpansIn(s, used)
	if len(spans) == 0 {
		return s, false, true
	}

	// selfUse[i] is the index of the assignment whose own value holds
	// uses[i] as a self-reference, or -1.
	selfUse := make([]int, len(uses))
	ui := 0
	for si := range spans {
		a := &spans[si]
		a.selfRef = a.appends
		for ; ui < len(uses) && uses[ui].pos < a.valueStart; ui++ {
			selfUse[ui] = -1
		}
		for ; ui < len(uses) && uses[ui].end <= a.valueEnd; ui++ {
			selfUse[ui] = -1
			if uses[ui].name == a.name && !uses[ui].indirect {
				selfUse[ui] = si
				a.selfRef = true
			}
		}
	}
	for ; ui < len(uses); ui++ {
		selfUse[ui] = -1
	}

	sv := &shellValues{shellBounds: sb, names: make(map[string]*assignedName)}
	firstAssign := make(map[string]int)
	for si := range spans {
		a := &spans[si]
		if _, isUsed := used[a.name]; !isUsed {
			if a.name == "IFS" && !a.selfRef && a.valueEnd-a.valueStart == 1 {
				sv.ifsChars.add(s[a.valueStart:a.valueEnd])
			}
			continue
		}
		n := sv.names[a.name]
		if n == nil {
			n = &assignedName{name: a.name, pos: len(sv.order)}
			sv.names[a.name] = n
			sv.order = append(sv.order, n)
			firstAssign[a.name] = a.opStart
		}
		if a.maybeKept {
			n.plain.add("")
		}
		if a.selfRef {
			continue
		}
		v := bracedShellRefs(s[a.valueStart:a.valueEnd])
		if !n.plain.add(v) {
			continue
		}
		if a.name == "IFS" && len(v) == 1 {
			sv.ifsChars.add(v)
		}
	}
	if len(sv.names) == 0 {
		return s, false, true
	}
	// A name can still be unset where it is used: the use comes before its
	// first assignment ("$Z$A$B -rf /x; Z=echo" runs rm), that assignment may
	// not run (it follows "&&", "||", a condition, a loop, a group or a
	// function), or the name is unset again. The command is then written
	// once more with those names empty: one extra copy, not another value
	// that multiplies with every other name's values.
	firsts := make([]int, 0, len(firstAssign))
	for _, at := range firstAssign {
		firsts = append(firsts, at)
	}
	slices.Sort(firsts)
	conditional := shellConditionalAt(s, firsts)
	mayUnset := make([]bool, len(uses))
	for i, u := range uses {
		if selfUse[i] >= 0 || sv.names[u.name] == nil {
			continue
		}
		first := firstAssign[u.name]
		mayUnset[i] = u.pos < first || conditional[first] || shellUnsetsName(s, u.name)
	}
	for _, n := range sv.order {
		for _, v := range n.plain.list {
			if !sv.addTemplate(n, v) {
				return s, false, false
			}
		}
	}

	// Walk the assignments in order to give each self-reference the value
	// built so far, and make a template of each value it can then hold.
	ui = 0
	for si := range spans {
		a := &spans[si]
		n := sv.names[a.name]
		if n == nil {
			continue
		}
		raw := s[a.valueStart:a.valueEnd]
		if !a.selfRef {
			n.chain = bracedShellRefs(raw)
			continue
		}
		// unset and every plain value, shared by the name's self-references;
		// the value built so far goes in front unless it is one of them.
		if n.selfBase == nil {
			n.selfBase = make([]string, 0, len(n.plain.list)+1)
			n.selfBase = append(n.selfBase, "")
			for _, v := range n.plain.list {
				if v != "" {
					n.selfBase = append(n.selfBase, v)
				}
			}
		}
		alts := n.selfBase
		if n.chain != "" && !n.plain.has(n.chain) {
			if !sb.spend(16 * (len(alts) + 1)) {
				return s, false, false
			}
			alts = make([]string, 0, len(n.selfBase)+1)
			alts = append(alts, n.chain)
			alts = append(alts, n.selfBase...)
		}
		for ui < len(uses) && uses[ui].pos < a.valueStart {
			ui++
		}
		first := ui
		for ui < len(uses) && uses[ui].end <= a.valueEnd {
			ui++
		}
		// The alternative that is the value built so far yields the value
		// the next self-reference builds on.
		next := ""
		for _, alt := range alts {
			size := len(raw)
			if a.appends {
				size += len(alt)
			}
			for i := first; i < ui; i++ {
				if selfUse[i] == si {
					size += len(alt) - (uses[i].end - uses[i].pos)
				}
			}
			if !sb.spend(size) {
				return s, false, false
			}
			var b strings.Builder
			b.Grow(size)
			if a.appends {
				b.WriteString(alt)
			}
			prev := a.valueStart
			for i := first; i < ui; i++ {
				if selfUse[i] != si {
					continue
				}
				b.WriteString(s[prev:uses[i].pos])
				b.WriteString(alt)
				prev = uses[i].end
			}
			b.WriteString(s[prev:a.valueEnd])
			built := bracedShellRefs(b.String())
			if !sv.addTemplate(n, built) {
				return s, false, false
			}
			if alt == n.chain {
				next = built
			}
		}
		n.chain = next
	}
	if !sv.resolve() {
		return s, false, false
	}

	// Turn the uses into slots. An assignment that names its own variable
	// is left as written: its values are in the name's set, and writing
	// them back would grow the text by the whole value at every append.
	slots := make([]shellSlot, 0, len(uses))
	for i, u := range uses {
		if selfUse[i] >= 0 {
			continue
		}
		n := sv.names[u.name]
		if n == nil || len(n.values.list) == 0 {
			continue
		}
		slot := shellSlot{pos: u.pos, end: u.end, key: shellSlotKey{name: u.name, indirect: u.indirect}, alts: n.values.list, widest: n.widest, mayUnset: mayUnset[i]}
		if u.indirect {
			slot.prefix = "${"
		}
		slots = append(slots, slot)
	}
	if len(slots) == 0 {
		return s, false, true
	}

	var b strings.Builder
	write := func(text string) bool {
		if !sb.spend(len(text)) {
			return false
		}
		b.WriteString(text)
		return true
	}
	// copied holds the commands already written once per combination. A
	// script that repeats one command for each value of a name (an unrolled
	// loop) needs those copies once, not once per repetition.
	copied := make(map[string]struct{})
	next := 0
	for segStart := 0; segStart < len(s); {
		segEnd, sepEnd := nextShellSeparator(s, segStart)
		first := next
		for next < len(slots) && slots[next].pos < segEnd {
			next++
		}
		if !writeShellCommand(sb, write, copied, s[segStart:segEnd], s[segEnd:sepEnd], segStart, slots[first:next]) {
			return s, false, false
		}
		segStart = sepEnd
	}
	return b.String(), true, true
}

// nextShellSeparator returns the end of the command that starts at from and
// the end of the separator after it. A pipeline stays one command, so a
// rule that reads across "|" sees one consistent copy. "&" inside a redirect
// (2>&1, &>file) is not a separator.
func nextShellSeparator(s string, from int) (segEnd, sepEnd int) {
	for i := from; i < len(s); i++ {
		switch s[i] {
		case ';', '\n':
			return i, i + 1
		case '|':
			if i+1 < len(s) && s[i+1] == '|' {
				return i, i + 2
			}
		case '&':
			if i+1 < len(s) && s[i+1] == '&' {
				return i, i + 2
			}
			if (i > from && (s[i-1] == '>' || s[i-1] == '<')) || (i+1 < len(s) && s[i+1] == '>') {
				continue
			}
			return i, i + 1
		}
	}
	return len(s), len(s)
}

// shellChoices lists the combinations of values a set of slots can take.
// Slots that share a key take the same value in one combination.
type shellChoices struct {
	slots []shellSlot
	// which[i] is the choice slots[i] follows, or -1 for a slot with one
	// value. sizes[k] is how many values choice k has.
	which []int
	sizes []int
	// count is the number of combinations, capped at maxShellChoices: more
	// than that never fits a copy budget.
	count int
}

const maxShellChoices = 1 << 30

func newShellChoices(slots []shellSlot) shellChoices {
	c := shellChoices{slots: slots, count: 1}
	if !slices.ContainsFunc(slots, func(sl shellSlot) bool { return len(sl.alts) > 1 }) {
		return c
	}
	var keys []shellSlotKey
	c.which = make([]int, len(slots))
	for i, sl := range slots {
		c.which[i] = -1
		if len(sl.alts) < 2 {
			continue
		}
		for k, key := range keys {
			if key == sl.key {
				c.which[i] = k
				break
			}
		}
		if c.which[i] >= 0 {
			continue
		}
		if len(keys) == maxShellSlotChoices {
			c.count = maxShellChoices
			return c
		}
		c.which[i] = len(keys)
		keys = append(keys, sl.key)
		c.sizes = append(c.sizes, len(sl.alts))
		c.count = min(c.count*len(sl.alts), maxShellChoices)
	}
	return c
}

// width is the most bytes one combination writes for a text of n bytes.
func (c shellChoices) width(n int) int {
	for _, sl := range c.slots {
		n += len(sl.prefix) + sl.widest
	}
	return n + 1
}

// each calls fn once per combination, or once with every slot's first value
// when count is 1. pick(i) is the value slots[i] takes. It returns false
// when fn does.
func (c shellChoices) each(fn func(pick func(int) string) bool) bool {
	if c.count == 1 {
		return fn(func(i int) string { return c.slots[i].alts[0] })
	}
	at := make([]int, len(c.sizes))
	pick := func(i int) string {
		if c.which[i] < 0 {
			return c.slots[i].alts[0]
		}
		return c.slots[i].alts[at[c.which[i]]]
	}
	for {
		if !fn(pick) {
			return false
		}
		k := 0
		for ; k < len(at); k++ {
			at[k]++
			if at[k] < c.sizes[k] {
				break
			}
			at[k] = 0
		}
		if k == len(at) {
			return true
		}
	}
}

// writeShellCommand writes seg once per combination of the values its slots
// can take, each copy followed by sep. base is the offset of seg in the text
// the slots index. A command already copied earlier in the pass is written
// once: its copies are in the output already. When the copies do not fit
// the copy budget it writes seg once, with the first value of each slot,
// and marks the reading partial.
func writeShellCommand(sb *shellBounds, write func(string) bool, copied map[string]struct{}, seg, sep string, base int, slots []shellSlot) bool {
	if len(slots) == 0 {
		return write(seg) && write(sep)
	}
	between := sep
	if between == "" {
		between = ";"
	}
	choices := newShellChoices(slots)
	key := strings.TrimSpace(seg)
	_, done := copied[key]
	if choices.count > 1 {
		// The same command text has the same slots and the same values
		// everywhere in one pass, so its copies are the same too.
		switch {
		case done:
			choices = shellChoices{slots: slots, count: 1}
		case sb.fitsCopies(choices.count, choices.width(len(seg)+len(between))):
			copied[key] = struct{}{}
		default:
			choices = shellChoices{slots: slots, count: 1}
			sb.partial = true
		}
	}
	first := true
	emit := func(pick func(int) string) bool {
		before := sb.work
		if !first && !write(between) {
			return false
		}
		prev := 0
		for i, sl := range slots {
			if !write(seg[prev:sl.pos-base]) || !write(sl.prefix) || !write(pick(i)) {
				return false
			}
			prev = sl.end - base
		}
		if !write(seg[prev:]) {
			return false
		}
		if !first {
			sb.spendCopies(before - sb.work)
		}
		first = false
		return true
	}
	if !choices.each(emit) {
		return false
	}
	// More copies with every name that may still be unset left empty, each
	// combined with every value of the other names while they fit.
	if !done && slices.ContainsFunc(slots, func(sl shellSlot) bool { return sl.mayUnset }) {
		copied[key] = struct{}{}
		empty := make([]shellSlot, len(slots))
		for i, sl := range slots {
			empty[i] = sl
			if sl.mayUnset {
				empty[i].alts, empty[i].widest = unsetShellValue, 0
			}
		}
		rest := newShellChoices(empty)
		if !sb.fitsCopies(rest.count+1, rest.width(len(seg)+len(between))) {
			rest = shellChoices{slots: empty, count: 1}
			sb.partial = true
		}
		if !rest.each(emit) {
			return false
		}
	}
	return write(sep)
}
