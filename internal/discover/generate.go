// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package discover

import (
	"fmt"
	"os"
	"sort"
	"strings"
)

// GenerateWrapper returns a human-readable wrapper suggestion for an unprotected server.
func GenerateWrapper(s MCPServer) string {
	return generateWrapperForCurrent(s, os.Executable)
}

func generateWrapperForCurrent(s MCPServer, executable func() (string, error)) string {
	self, err := executable()
	if err != nil {
		self = ""
	}
	return generateWrapper(s, self)
}

func generateWrapper(s MCPServer, pipelockBin string) string {
	var b strings.Builder
	if pipelockBin == "" {
		return "  (cannot suggest a verified wrapper because the current pipelock executable path is unavailable)"
	}

	if s.Transport == TransportStdio && s.Command != "" && isProxyShaped(s.Args) {
		// Already an mcp proxy wrapper whose executable is not this one
		// (missing, relative, or a different file). Wrapping it again would
		// launch the same broken command as the child, so point the command
		// at this executable and keep its arguments.
		_, _ = fmt.Fprintf(&b, "  This entry already runs mcp proxy, but not through this pipelock executable.\n")
		_, _ = fmt.Fprintf(&b, "  Point its command at this executable in your %s config:\n\n", s.Client)
		_, _ = fmt.Fprintf(&b, "  Before:\n")
		_, _ = fmt.Fprintf(&b, "    \"command\": %q,\n\n", s.Command)
		_, _ = fmt.Fprintf(&b, "  After:\n")
		_, _ = fmt.Fprintf(&b, "    \"command\": %q,\n", pipelockBin)
		_, _ = fmt.Fprintf(&b, "    (keep \"args\" unchanged; check that any --config file it names exists)\n")
		return b.String()
	}

	if s.Transport == TransportStdio && s.Command != "" {
		_, _ = fmt.Fprintf(&b, "  Replace in your %s config:\n\n", s.Client)

		// Before
		_, _ = fmt.Fprintf(&b, "  Before:\n")
		_, _ = fmt.Fprintf(&b, "    \"command\": %q,\n", s.Command)
		_, _ = fmt.Fprintf(&b, "    \"args\": %s\n\n", formatArgs(s.Args))

		// After: include --env flags for each env var so they are passed through
		_, _ = fmt.Fprintf(&b, "  After:\n")
		_, _ = fmt.Fprintf(&b, "    \"command\": %q,\n", pipelockBin)

		afterArgs := []string{wrapperArgMCP, wrapperArgProxy, flagConfig, "~/.config/pipelock/local.yaml"}
		for _, k := range sortedEnvKeys(s.Env) {
			afterArgs = append(afterArgs, "--env", k)
		}
		afterArgs = append(afterArgs, "--", s.Command)
		afterArgs = append(afterArgs, s.Args...)
		_, _ = fmt.Fprintf(&b, "    \"args\": %s\n", formatArgs(afterArgs))

		return b.String()
	}

	if s.URL != "" {
		_, _ = fmt.Fprintf(&b, "  Replace in your %s config:\n\n", s.Client)

		_, _ = fmt.Fprintf(&b, "  Before:\n")
		_, _ = fmt.Fprintf(&b, "    \"url\": %q\n\n", s.URL)

		_, _ = fmt.Fprintf(&b, "  After:\n")
		_, _ = fmt.Fprintf(&b, "    \"command\": %q,\n", pipelockBin)
		_, _ = fmt.Fprintf(&b, "    \"args\": [\"mcp\", \"proxy\", \"--config\", \"~/.config/pipelock/local.yaml\", \"--upstream\", %q]\n", s.URL)

		return b.String()
	}

	return "  (no suggestion available for this transport type)"
}

// isProxyShaped reports whether args begin with the mcp proxy subcommand.
func isProxyShaped(args []string) bool {
	return len(args) >= 2 && args[0] == wrapperArgMCP && args[1] == wrapperArgProxy
}

// sortedEnvKeys returns the keys from a map in sorted order for deterministic output.
func sortedEnvKeys(env map[string]string) []string {
	if len(env) == 0 {
		return nil
	}
	keys := make([]string, 0, len(env))
	for k := range env {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func formatArgs(args []string) string {
	if len(args) == 0 {
		return "[]"
	}
	quoted := make([]string, len(args))
	for i, a := range args {
		quoted[i] = fmt.Sprintf("%q", a)
	}
	return "[" + strings.Join(quoted, ", ") + "]"
}
