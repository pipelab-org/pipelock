// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package discover

import (
	"path/filepath"
	"strings"

	"github.com/luckyPipewrench/pipelock/internal/mcpwrap"
)

// SOPS launcher recognition.
//
// `sops exec-env FILE COMMAND` decrypts FILE into the environment and runs
// COMMAND with `/bin/sh -c` on Unix (getsops/sops v3.9.2,
// cmd/sops/subcommand/exec/exec_unix.go BuildCommand). COMMAND is therefore
// shell code, so discover accepts only a literal subset whose meaning the
// POSIX shell rules fix without expansion:
//
//	["exec-env", FILE, SCRIPT]
//	["exec-env", "--pristine", FILE, SCRIPT]
//	SCRIPT := "exec" SP ABS (SP WORD)*      SP = one ASCII space
//
// Characters come from POSIX.1-2024 XCU 2.2 (Quoting). Every character the
// standard says must be quoted, or may be special in some context, is
// rejected, with two sourced exceptions: '@' appears in neither list, and '='
// is special only in variable assignments, which XCU 2.9.1 places before the
// command name, so it is literal in words after ABS. ABS must be an absolute
// path, which XCU 2.9.1.4 executes directly with no alias, function or PATH
// lookup, and a single leading slash, because POSIX leaves a leading "//"
// implementation-defined. The inner command must then be this pipelock
// executable invoked as mcp proxy, verified by file identity.
//
// Recognizing this shape never proves protection: the outer program named
// sops is not authenticated, and an impostor could ignore its arguments. A
// recognized entry therefore stays unprotected and says why.

const (
	sopsCommandName  = "sops"
	sopsExecEnv      = "exec-env"
	sopsFlagPristine = "--pristine"
	shellExec        = "exec"
)

// Evidence for recognized-but-unproven launcher entries.
const (
	evidenceSOPSNestedUnverified = "sops exec-env runs this pipelock executable as mcp proxy; the sops launcher's identity is unverified, so protection is unconfirmed"
	evidenceSOPSUnsupported      = "sops exec-env command is outside the supported literal exec form; protection is unconfirmed"
	evidenceSOPSOptions          = "sops exec-env options are outside the supported foreground, same-user form; protection is unconfirmed"
	evidenceSOPSInnerMissing     = "sops exec-env runs an mcp proxy wrapper whose executable path does not exist"
	evidenceSOPSInnerDifferent   = "sops exec-env runs an mcp proxy wrapper whose executable differs from this pipelock executable"
	evidenceSOPSInnerUncheck     = "sops exec-env runs an mcp proxy wrapper whose executable identity could not be checked"
)

// sopsOutcome is the result of inspecting a sops exec-env entry.
type sopsOutcome int

const (
	sopsNotLauncher    sopsOutcome = iota // not a sops exec-env invocation
	sopsNestedVerified                    // inner command is this pipelock as mcp proxy
	sopsRejected                          // sops exec-env, but not provably the pipelock wrapper
)

// inspectSOPSLauncher classifies a sops exec-env invocation. It never runs
// sops or the command, and never decrypts anything.
func inspectSOPSLauncher(command string, args []string) (sopsOutcome, string) {
	if filepath.Base(command) != sopsCommandName || len(args) == 0 || args[0] != sopsExecEnv {
		return sopsNotLauncher, ""
	}
	var script string
	switch {
	case len(args) == 3 && isSOPSOperand(args[1]):
		script = args[2]
	case len(args) == 4 && args[1] == sopsFlagPristine && isSOPSOperand(args[2]):
		script = args[3]
	default:
		// --user switches identity, --background detaches stdio, and any
		// other layout has semantics this recognizer does not model.
		return sopsRejected, evidenceSOPSOptions
	}

	inner, innerArgs, ok := parseLiteralExecScript(script)
	if !ok {
		return sopsRejected, evidenceSOPSUnsupported
	}
	state, reason := mcpwrap.ExplainInvocation(inner, innerArgs)
	switch {
	case state == mcpwrap.WrapperSelf:
		return sopsNestedVerified, evidenceSOPSNestedUnverified
	case state == mcpwrap.WrapperNone:
		return sopsRejected, evidenceSOPSUnsupported
	case reason == mcpwrap.ForeignMissing:
		return sopsRejected, evidenceSOPSInnerMissing
	case reason == mcpwrap.ForeignDifferentFile:
		return sopsRejected, evidenceSOPSInnerDifferent
	default:
		return sopsRejected, evidenceSOPSInnerUncheck
	}
}

// isSOPSOperand reports whether a sops argument is a file operand rather than
// an option.
func isSOPSOperand(arg string) bool {
	return arg != "" && !strings.HasPrefix(arg, "-")
}

// parseLiteralExecScript splits SCRIPT under the grammar above, returning the
// absolute command and its arguments. Any deviation, including doubled
// spaces, quoting or expansion characters, returns ok=false.
func parseLiteralExecScript(script string) (string, []string, bool) {
	words := strings.Split(script, " ")
	if len(words) < 2 || words[0] != shellExec {
		return "", nil, false
	}
	abs := words[1]
	if !strings.HasPrefix(abs, "/") || strings.HasPrefix(abs, "//") || !isPathWord(abs) {
		return "", nil, false
	}
	rest := words[2:]
	for _, w := range rest {
		if !isArgWord(w) {
			return "", nil, false
		}
	}
	return abs, rest, true
}

// isPathWord reports whether w uses only the POSIX portable filename
// character set (XBD 3.265) plus '/'.
func isPathWord(w string) bool {
	if w == "" {
		return false
	}
	for _, r := range w {
		if !isPortableFilenameRune(r) && r != '/' {
			return false
		}
	}
	return true
}

// isArgWord reports whether w is literal in an argument position: portable
// filename characters, '/', ':', '@' and '='. ':' and '@' are in neither
// XCU 2.2 quoting list; '=' is literal after the command name (XCU 2.9.1).
func isArgWord(w string) bool {
	if w == "" {
		return false
	}
	for _, r := range w {
		switch {
		case isPortableFilenameRune(r), r == '/', r == ':', r == '@', r == '=':
		default:
			return false
		}
	}
	return true
}

// isPortableFilenameRune reports membership in the POSIX portable filename
// character set (XBD 3.265): letters, digits, period, underscore and hyphen-minus.
func isPortableFilenameRune(r rune) bool {
	return (r >= 'A' && r <= 'Z') || (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') ||
		r == '.' || r == '_' || r == '-'
}
