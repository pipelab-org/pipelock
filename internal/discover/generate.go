// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package discover

import (
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/BurntSushi/toml"
)

// GenerateWrapper returns a human-readable wrapper suggestion for an unprotected server.
func GenerateWrapper(s MCPServer) string {
	if s.Protection == Unconfirmed {
		return evidenceLaunchUnconfirmed + " Check project files, profiles, plugins, and launch overrides; another wrapper cannot confirm the launch."
	}
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
	if s.Client == clientCodex || s.Client == clientGrok {
		return generateTOMLWrapper(s, pipelockBin)
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

// Codex and Grok publish [mcp_servers.<name>] tables in config.toml:
// https://developers.openai.com/codex/config-reference
// https://docs.x.ai/build/features/mcp-servers
// Marshal the whole table so quoted names, arguments, and URLs remain TOML.
func generateTOMLWrapper(s MCPServer, pipelockBin string) string {
	before := map[string]any{}
	after := map[string]any{"command": pipelockBin}
	var lead string
	switch {
	case s.Transport == TransportStdio && s.Command != "" && isProxyShaped(s.Args):
		lead = "  Point the existing mcp proxy command at this executable; keep args unchanged."
		before["command"] = s.Command
		before["args"] = s.Args
		after["args"] = s.Args
	case s.Transport == TransportStdio && s.Command != "":
		lead = "  Replace this stdio entry:"
		before["command"] = s.Command
		before["args"] = s.Args
		args := []string{wrapperArgMCP, wrapperArgProxy, flagConfig, "~/.config/pipelock/local.yaml"}
		for _, key := range sortedEnvKeys(s.Env) {
			args = append(args, "--env", key)
		}
		after["args"] = append(append(args, "--", s.Command), s.Args...)
	case s.URL != "":
		lead = "  Replace this HTTP entry:"
		before["url"] = s.URL
		after["args"] = []string{wrapperArgMCP, wrapperArgProxy, flagConfig, "~/.config/pipelock/local.yaml", "--upstream", s.URL}
	default:
		return "  (no suggestion available for this transport type)"
	}
	oldSnippet, oldErr := tomlServerTable(s.ServerName, before)
	newSnippet, newErr := tomlServerTable(s.ServerName, after)
	if oldErr != nil || newErr != nil {
		return "  (cannot encode a TOML wrapper suggestion for this entry)"
	}
	return fmt.Sprintf("%s\n  Before:\n%s\n  After:\n%s", lead, oldSnippet, newSnippet)
}

// tomlServerTable renders one [mcp_servers.<name>] table and nothing else.
// Marshalling the nested document would also emit a bare [mcp_servers]
// header, and TOML forbids declaring a table twice: an operator who applied
// two such suggestions would leave a config.toml the client refuses to load.
// The key is quoted by the encoder itself, and the result is decoded back so
// a snippet that does not reproduce exactly this one entry is never printed.
func tomlServerTable(name string, fields map[string]any) (string, error) {
	const probeSuffix = " = 0\n"
	probe, err := toml.Marshal(map[string]int{name: 0})
	if err != nil {
		return "", err
	}
	key, ok := strings.CutSuffix(string(probe), probeSuffix)
	if !ok || key == "" {
		return "", fmt.Errorf("unexpected TOML key encoding %q", probe)
	}
	body, err := toml.Marshal(fields)
	if err != nil {
		return "", err
	}
	snippet := "[" + tomlKeyServers + "." + key + "]\n" + string(body)
	var document map[string]map[string]map[string]any
	if _, err := toml.Decode(snippet, &document); err != nil {
		return "", err
	}
	if entries := document[tomlKeyServers]; len(document) != 1 || len(entries) != 1 || entries[name] == nil {
		return "", fmt.Errorf("TOML snippet does not round-trip server %q", name)
	}
	return snippet, nil
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
