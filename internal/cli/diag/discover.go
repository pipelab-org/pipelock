// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package diag

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/luckyPipewrench/pipelock/internal/cliutil"
	"github.com/luckyPipewrench/pipelock/internal/discover"
)

func DiscoverCmd() *cobra.Command {
	var jsonOutput bool
	var generate bool
	var homeDir string
	var claudeConfigDirs []string
	var projectDirs []string

	cmd := &cobra.Command{
		Use:   "discover",
		Short: "Scan for AI agent configs and report MCP server protection status",
		Long: `Scan the local machine for AI agent client configurations (Claude Code,
Claude Desktop, Codex, Grok, Cursor, VS Code, Cline, Continue.dev, JetBrains/Junie, Zed
stable, Zed Preview, Flatpak Zed stable, Flatpak Zed Preview) and report
which MCP servers are configured, their protection status, and risk level.

Claude Code configs under CLAUDE_CONFIG_DIR (<dir>/.claude.json) are included
when that variable is set and --home is not, and for every --claude-config-dir.
Codex configs under CODEX_HOME (<dir>/config.toml) are included when that
variable is set and --home is not.

Registered trusted Codex projects are included. --project adds a Codex/Grok
working directory; without --home, the current directory is included too.
Wrapper detection is a file observation: unchecked client launch settings
leave wrapped entries unconfirmed. See docs/cli/discover.md for coverage.

Exit codes:
  0  All servers protected (or none found)
  1  Unprotected, unconfirmed, unknown, or unparseable configs found
  2  Usage or runtime error

Examples:
  pipelock discover
  pipelock discover --json
  pipelock discover --generate
  pipelock discover --home /home/otheruser
  pipelock discover --claude-config-dir /home/me/.claude-work`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			// An explicit --home suppresses ambient directory overrides and
			// implicit cwd; those inputs describe this user, not that one.
			var opts discover.Options
			if homeDir == "" {
				h, err := os.UserHomeDir()
				if err != nil {
					return cliutil.ExitCodeError(2, fmt.Errorf("determining home directory: %w", err))
				}
				homeDir = h
				opts = discover.AmbientOptions(os.Getenv)
				if cwd, err := os.Getwd(); err == nil {
					opts.ProjectDirs = append(opts.ProjectDirs, cwd)
				}
			}
			opts.ClaudeConfigDirs = append(opts.ClaudeConfigDirs, claudeConfigDirs...)
			opts.ProjectDirs = append(opts.ProjectDirs, projectDirs...)

			report, err := discover.DiscoverWithOptions(homeDir, opts)
			if err != nil {
				return cliutil.ExitCodeError(2, fmt.Errorf("discovery failed: %w", err))
			}

			if jsonOutput {
				return printDiscoverJSON(cmd, report)
			}

			printDiscoverHuman(cmd, report)

			if generate {
				printDiscoverGenerate(cmd, report)
			}

			if report.Summary.Unprotected > 0 || report.Summary.Unknown > 0 || report.Summary.Unconfirmed > 0 || report.Summary.ParseErrors > 0 {
				return &cliutil.ExitError{
					Err:  errors.New("unprotected, unconfirmed, or unknown MCP servers or config parse errors found"),
					Code: 1,
				}
			}

			return nil
		},
	}

	cmd.Flags().StringArrayVar(&projectDirs, "project", nil, "Inspect Codex/Grok project files for this working directory (repeatable; absolute path)")
	cmd.Flags().BoolVar(&jsonOutput, "json", false, "Output machine-readable JSON")
	cmd.Flags().BoolVar(&generate, "generate", false, "Print pipelock wrapper suggestions for unprotected servers")
	cmd.Flags().StringVar(&homeDir, "home", "", "Override home directory (default: $HOME)")
	cmd.Flags().StringArrayVar(&claudeConfigDirs, "claude-config-dir", nil, "Also inspect <dir>/.claude.json for a Claude Code CLAUDE_CONFIG_DIR (repeatable; absolute path)")

	return cmd
}

func printDiscoverJSON(cmd *cobra.Command, report *discover.Report) error {
	enc := json.NewEncoder(cmd.OutOrStdout())
	enc.SetIndent("", "  ")
	safeReport := discover.RedactReportForOutput(report)
	// The SOPS subset is an operator-facing discover detail. Keep it out of
	// shared Summary JSON, which assess embeds and posture signs separately.
	output := struct {
		Clients []discover.ClientConfig `json:"clients"`
		Servers []discover.MCPServer    `json:"servers"`
		Summary struct {
			discover.Summary
			SOPSExecEnv int `json:"sops_exec_env"`
		} `json:"summary"`
	}{Clients: safeReport.Clients, Servers: safeReport.Servers}
	output.Summary.Summary = safeReport.Summary
	output.Summary.SOPSExecEnv = safeReport.Summary.SOPSExecEnv
	if err := enc.Encode(output); err != nil {
		return cliutil.ExitCodeError(2, fmt.Errorf("encoding JSON: %w", err))
	}

	if report.Summary.Unprotected > 0 || report.Summary.Unknown > 0 || report.Summary.Unconfirmed > 0 || report.Summary.ParseErrors > 0 {
		return &cliutil.ExitError{
			Err:  errors.New("unprotected, unconfirmed, or unknown MCP servers or config parse errors found"),
			Code: 1,
		}
	}
	return nil
}

func printDiscoverHuman(cmd *cobra.Command, report *discover.Report) {
	w := cmd.OutOrStdout()
	safeReport := discover.RedactReportForOutput(report)

	_, _ = fmt.Fprintln(w, "Pipelock Discovery")
	_, _ = fmt.Fprintln(w, "==================")
	_, _ = fmt.Fprintln(w)

	if len(safeReport.Clients) == 0 {
		_, _ = fmt.Fprintln(w, "No AI agent configs found.")
		_, _ = fmt.Fprintln(w)
		return
	}

	_, _ = fmt.Fprintf(w, "Configs found: %d\n", len(safeReport.Clients))
	for _, c := range safeReport.Clients {
		if c.ParseError != "" {
			_, _ = fmt.Fprintf(w, "  %-16s %-50s PARSE ERROR\n", c.Client, c.ConfigPath)
		} else {
			_, _ = fmt.Fprintf(w, "  %-16s %-50s %d server(s)\n", c.Client, c.ConfigPath, c.ServerCount)
		}
	}
	_, _ = fmt.Fprintln(w)

	if safeReport.Summary.ParseErrors > 0 {
		_, _ = fmt.Fprintf(w, "Parse errors: %d config(s) could not be read\n", safeReport.Summary.ParseErrors)
		for _, c := range safeReport.Clients {
			if c.ParseError != "" {
				_, _ = fmt.Fprintf(w, "  %s: %s\n", c.ConfigPath, c.ParseError)
			}
		}
		_, _ = fmt.Fprintln(w)
	}

	_, _ = fmt.Fprintf(w, "MCP Servers: %d total\n", safeReport.Summary.TotalServers)
	_, _ = fmt.Fprintf(w, "  Protected (pipelock):  %d\n", safeReport.Summary.ProtectedPipelock)
	_, _ = fmt.Fprintf(w, "  Protected (other):     %d\n", safeReport.Summary.ProtectedOther)
	_, _ = fmt.Fprintf(w, "  Unprotected:           %d\n", safeReport.Summary.Unprotected)
	_, _ = fmt.Fprintf(w, "    via sops exec-env:   %d\n", safeReport.Summary.SOPSExecEnv)
	_, _ = fmt.Fprintf(w, "  Unconfirmed:           %d\n", safeReport.Summary.Unconfirmed)
	_, _ = fmt.Fprintf(w, "  Unknown:               %d\n", safeReport.Summary.Unknown)
	_, _ = fmt.Fprintf(w, "  Marked enabled=false:  %d (still counted above)\n", safeReport.Summary.Disabled)
	_, _ = fmt.Fprintln(w)

	// List unprotected servers sorted by risk
	unprotected := false
	for _, s := range safeReport.Servers {
		if s.Protection == discover.Unprotected || s.Protection == discover.Unknown || s.Protection == discover.Unconfirmed {
			if !unprotected {
				_, _ = fmt.Fprintln(w, "Servers needing attention:")
				unprotected = true
			}
			risk := strings.ToUpper(string(s.Risk))
			desc := serverDescription(s)
			if s.ProjectPath != "" {
				desc += fmt.Sprintf(" (project: %s)", s.ProjectPath)
			}
			_, _ = fmt.Fprintf(w, "  [%-6s] [%-16s] %-20s %s\n",
				risk, s.Client, s.ServerName, desc)
			_, _ = fmt.Fprintf(w, "           %s: %s\n", s.Protection, s.Evidence)
			for _, warn := range s.ParseWarnings {
				_, _ = fmt.Fprintf(w, "           WARNING: %s\n", warn)
			}
		}
	}

	if unprotected {
		_, _ = fmt.Fprintln(w)
		_, _ = fmt.Fprintln(w, "Use --generate to print pipelock wrapper suggestions.")
	} else if safeReport.Summary.TotalServers > 0 {
		_, _ = fmt.Fprintln(w, "All servers are protected.")
	}
	_, _ = fmt.Fprintln(w, "Use --json for machine-readable output.")
}

func printDiscoverGenerate(cmd *cobra.Command, report *discover.Report) {
	w := cmd.OutOrStdout()
	printed := false
	if report.Summary.Unconfirmed > 0 {
		_, _ = fmt.Fprintln(w, "Unconfirmed entries already contain a wrapper. Check project files, profiles, plugins, and launch overrides; another wrapper suggestion cannot confirm what the client launches.")
	}

	for _, s := range report.Servers {
		if s.Protection != discover.Unprotected {
			continue
		}
		if !printed {
			_, _ = fmt.Fprintln(w)
			_, _ = fmt.Fprintln(w, "Wrapper suggestions:")
			_, _ = fmt.Fprintln(w, "====================")
			_, _ = fmt.Fprintln(w, "Sensitive argument and URL values are redacted; copy real values from the local config when applying.")
			printed = true
		}
		_, _ = fmt.Fprintln(w)
		safeServer := discover.RedactServerForOutput(s)
		if s.ProjectPath != "" {
			_, _ = fmt.Fprintf(w, "Server: %s (%s, project: %s)\n", s.ServerName, s.Client, s.ProjectPath)
		} else {
			_, _ = fmt.Fprintf(w, "Server: %s (%s)\n", s.ServerName, s.Client)
		}
		suggestion := discover.GenerateWrapper(safeServer)
		_, _ = fmt.Fprintln(w, suggestion)
	}
}

func serverDescription(s discover.MCPServer) string {
	if s.Command != "" {
		parts := []string{s.Command}
		parts = append(parts, s.Args...)
		return strings.Join(parts, " ")
	}
	if s.URL != "" {
		return s.URL
	}
	return "(unknown)"
}
