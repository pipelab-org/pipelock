// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package setup

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/luckyPipewrench/pipelock/internal/cliutil"
	"github.com/luckyPipewrench/pipelock/internal/mcp"
	"github.com/luckyPipewrench/pipelock/internal/mcpwrap"
	"github.com/spf13/cobra"
)

// Codex MCP wrapping uses the same shape as VS Code: rewrite each server's
// command/args so traffic flows through `pipelock mcp proxy` before reaching
// the original server. Differences from vscode.go: Codex stores config in
// TOML (~/.codex/config.toml). We use `codex mcp list/add/remove` for
// registration, then persist env_vars by name with a private atomic write.
// The add CLI accepts literal env values only, which must never reach argv.

const (
	codexBinaryDefault  = "codex"
	pipelockBinaryName  = "pipelock"
	codexMCPProxy       = "proxy"
	codexMCP            = "mcp"
	codexArgSeparator   = "--"
	codexFlagConfig     = "--config"
	codexFlagEnv        = "--env"
	codexFlagUpstream   = "--upstream"
	codexTransportStdio = "stdio"

	codexActionWrapStdio       = "wrap-stdio"
	codexActionWrapURL         = "wrap-url"
	codexActionSkipWrapped     = "skip-already-wrapped"
	codexActionSkipUnsupported = "skip-unsupported"
	codexActionUnwrapStdio     = "unwrap-stdio"
	codexActionUnwrapURL       = "unwrap-url"
	codexActionSkipNotWrapped  = "skip-not-wrapped"
)

// codexMCPServer mirrors `codex mcp list --json` output.
type codexMCPServer struct {
	Name              string            `json:"name"`
	Enabled           *bool             `json:"enabled"`
	Transport         codexMCPTransport `json:"transport"`
	StartupTimeoutSec json.RawMessage   `json:"startup_timeout_sec,omitempty"`
	ToolTimeoutSec    json.RawMessage   `json:"tool_timeout_sec,omitempty"`
}

// codexMCPTransport is the per-server transport block. Codex emits both
// stdio (command/args/env) and streamable HTTP (url) shapes under this key
// distinguished by `type`.
type codexMCPTransport struct {
	Type              string            `json:"type"`
	Command           string            `json:"command,omitempty"`
	Args              []string          `json:"args,omitempty"`
	Env               map[string]string `json:"env,omitempty"`
	EnvVars           codexEnvNames     `json:"env_vars,omitempty"`
	CWD               string            `json:"cwd,omitempty"`
	URL               string            `json:"url,omitempty"`
	BearerTokenEnvVar string            `json:"bearer_token_env_var,omitempty"`
	HTTPHeaders       json.RawMessage   `json:"http_headers,omitempty"`
	EnvHTTPHeaders    json.RawMessage   `json:"env_http_headers,omitempty"`
}

// CodexCmd returns the `pipelock codex` command tree.
func CodexCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "codex",
		Short: "Codex CLI integration",
		Long: `Wrap Codex CLI's MCP servers through pipelock so all tool traffic is scanned.

The install subcommand rewrites each registered MCP server in ~/.codex/config.toml
so its command becomes 'pipelock mcp proxy -- <original command>'. URL-based
streamable HTTP servers are converted to stdio with --upstream.

The remove subcommand restores wrapped servers by reading the original command
out of the wrapped args list. Servers that were not wrapped by pipelock are
left unchanged.

HTTP fetches from Codex itself (LLM API calls, the WebFetch tool) are routed
through pipelock when HTTPS_PROXY is set in the user's shell. Codex inherits
HTTP_PROXY/HTTPS_PROXY/NO_PROXY by default per its shell_environment_policy,
so no codex-side change is needed for those.`,
	}
	cmd.AddCommand(codexInstallCmd(), codexRemoveCmd())
	return cmd
}

func codexInstallCmd() *cobra.Command {
	var (
		dryRun     bool
		configFile string
		codexPath  string
		quiet      bool
	)
	cmd := &cobra.Command{
		Use:   "install",
		Short: "Wrap Codex MCP servers through pipelock",
		Long: `Iterates servers reported by 'codex mcp list --json' and wraps each one
through pipelock's MCP proxy. Already-wrapped servers are skipped (idempotent).
Streamable HTTP (URL) servers are converted to stdio with --upstream.

Use --dry-run to preview the changes without modifying the Codex config.
Use --config to point pipelock at a specific YAML config when wrapping.
Use --codex-path to override the codex binary location (default: PATH lookup).`,
		SilenceUsage:  true,
		SilenceErrors: true,
		Args:          cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runCodexInstall(cmd, dryRun, configFile, codexPath, quiet)
		},
	}
	cmd.Flags().BoolVar(&dryRun, "dry-run", false, "preview changes without modifying Codex config")
	cmd.Flags().StringVarP(&configFile, "config", "c", "", "pipelock config path passed through to 'pipelock mcp proxy'")
	cmd.Flags().StringVar(&codexPath, "codex-path", "", "path to the codex binary (default: PATH lookup)")
	cmd.Flags().BoolVar(&quiet, "quiet", false, "suppress config provenance output")
	return cmd
}

func codexRemoveCmd() *cobra.Command {
	var (
		dryRun    bool
		codexPath string
	)
	cmd := &cobra.Command{
		Use:   "remove",
		Short: "Unwrap Codex MCP servers previously wrapped by pipelock",
		Long: `Reverses 'pipelock codex install'. For each server whose command points at
the running pipelock binary, the original command/args are recovered from the
wrapped args list and re-registered. Non-wrapped servers are left unchanged.`,
		SilenceUsage:  true,
		SilenceErrors: true,
		Args:          cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runCodexRemove(cmd, dryRun, codexPath)
		},
	}
	cmd.Flags().BoolVar(&dryRun, "dry-run", false, "preview changes without modifying Codex config")
	cmd.Flags().StringVar(&codexPath, "codex-path", "", "path to the codex binary (default: PATH lookup)")
	return cmd
}

// resolveCodexBinary returns the codex binary path. Honors --codex-path if set,
// otherwise falls back to PATH lookup. Errors clearly if not found.
func resolveCodexBinary(override string) (string, error) {
	if override != "" {
		abs, err := filepath.Abs(override)
		if err != nil {
			return "", fmt.Errorf("resolving --codex-path: %w", err)
		}
		if _, err := os.Stat(abs); err != nil {
			return "", fmt.Errorf("codex binary at %s: %w", abs, err)
		}
		return abs, nil
	}
	resolved, err := exec.LookPath(codexBinaryDefault)
	if err != nil {
		return "", fmt.Errorf("codex binary not found on PATH (install Codex CLI or pass --codex-path)")
	}
	return resolved, nil
}

// resolvePipelockBinary returns the running pipelock binary path with symlinks
// evaluated. Used so wrapped configs reference a stable absolute path.
func resolvePipelockBinary() (string, error) {
	exe, err := os.Executable()
	if err != nil {
		return "", fmt.Errorf("finding pipelock binary: %w", err)
	}
	resolved, err := filepath.EvalSymlinks(exe)
	if err != nil {
		return "", fmt.Errorf("resolving pipelock binary path: %w", err)
	}
	return resolved, nil
}

// codexMCPList shells out to `codex mcp list --json` and parses the result.
func codexMCPList(ctx context.Context, codexBin string) ([]codexMCPServer, error) {
	out, err := runCodexMCPListCommand(ctx, codexBin)
	if err != nil {
		return nil, fmt.Errorf("codex mcp list: %w", err)
	}
	return parseCodexMCPList(out)
}

// runCodexMCPListCommand returns only stdout because Codex emits the JSON list
// there. Child diagnostics are withheld on failure because parser errors can
// quote environment values. Successful stderr warnings never enter the parser.
//
//nolint:gosec // G204: canonical CLI subprocess invocation; see runCodexCommand.
func runCodexMCPListCommand(ctx context.Context, codexBin string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, codexBin, "mcp", "list", "--json")
	cmd.Env = append(os.Environ(), "NO_COLOR=1")
	cmd.Stderr = io.Discard
	stdout, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("codex mcp list failed; %s: %w", codexParserFailureHint, err)
	}
	return stdout, nil
}

// parseCodexMCPList separates parsing from the shell-out so tests can feed
// canned JSON without mocking exec.
func parseCodexMCPList(data []byte) ([]codexMCPServer, error) {
	data = bytes.TrimSpace(data)
	if len(data) == 0 {
		return nil, nil
	}
	var servers []codexMCPServer
	if err := json.Unmarshal(data, &servers); err != nil {
		return nil, fmt.Errorf("parsing codex mcp list JSON: %w", err)
	}
	return servers, nil
}

// classifyCodexWrapper answers the same question for a Codex transport that
// classifyWrapper answers for the map-shaped configs, using the same file-identity
// test so the two cannot drift apart.
//
// The previous form keyed on the args prefix AND a binary BASENAME of "pipelock".
// That basename check is a fail-open, and its own comment described it as guarding
// only the "unlikely case of a non-pipelock tool" while the real case is
// deliberate: a config naming an attacker binary "pipelock" with leading
// "mcp proxy" arguments was treated as already wrapped and skipped, so that binary
// ran with nothing in front of it.
func classifyCodexWrapper(server codexMCPServer) wrapperState {
	if server.Transport.Type != codexTransportStdio {
		return stateNotWrapper
	}
	if !argsBeginMCPProxy(server.Transport.Args) {
		return stateNotWrapper
	}
	if isThisExecutable(server.Transport.Command) {
		return stateSelf
	}
	return stateForeignWrapper
}

// isCodexWrappedBySelf reports a transport already mediated by this binary, the
// only state an installer may skip.
func isCodexWrappedBySelf(server codexMCPServer) bool {
	return classifyCodexWrapper(server) == stateSelf
}

// isCodexRestorableWrapper reports a transport remove should unwrap. It accepts a
// wrapper written by a pipelock at another path, so upgrading the binary does not
// strand entries as permanently un-removable.
func isCodexRestorableWrapper(server codexMCPServer) bool {
	return classifyCodexWrapper(server) != stateNotWrapper
}

func serverEnabled(server codexMCPServer) bool {
	return server.Enabled == nil || *server.Enabled
}

func rawJSONHasValue(raw json.RawMessage) bool {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 {
		return false
	}
	switch string(trimmed) {
	case "null", "{}", "[]", `""`:
		return false
	default:
		return true
	}
}

func unsupportedCodexInstallReason(server codexMCPServer) string {
	if !serverEnabled(server) {
		return "server disabled"
	}
	if rawJSONHasValue(server.StartupTimeoutSec) || rawJSONHasValue(server.ToolTimeoutSec) {
		return "custom timeout settings cannot be preserved by codex mcp add"
	}
	if server.Transport.CWD != "" {
		return "cwd cannot be preserved by codex mcp add"
	}
	if _, err := codexEnvKeys(server.Transport); err != nil {
		return "unsafe env key cannot be passed through safely"
	}
	if server.Transport.URL != "" && codexURLTransportHasAuthOrHeaders(server.Transport) {
		return "HTTP auth/header settings cannot be preserved by stdio --upstream wrapper"
	}
	return ""
}

func unsupportedCodexRemoveReason(server codexMCPServer) string {
	if !serverEnabled(server) {
		return "server disabled (codex mcp add re-adds as enabled, which would silently mutate state)"
	}
	if rawJSONHasValue(server.StartupTimeoutSec) || rawJSONHasValue(server.ToolTimeoutSec) {
		return "custom timeout settings cannot be preserved by codex mcp add"
	}
	if server.Transport.CWD != "" {
		return "cwd cannot be preserved by codex mcp add"
	}
	if _, err := codexEnvKeys(server.Transport); err != nil {
		return "unsafe env key cannot be passed through safely"
	}
	return ""
}

func codexURLTransportHasAuthOrHeaders(transport codexMCPTransport) bool {
	return transport.BearerTokenEnvVar != "" ||
		rawJSONHasValue(transport.HTTPHeaders) ||
		rawJSONHasValue(transport.EnvHTTPHeaders)
}

// wrapCodexArgs builds the args list for a stdio server wrapped through
// pipelock. The result is: ["mcp", "proxy", "--config", CFG?, "--env", K1, ...,
// "--", ORIG_CMD, ORIG_ARG_1, ...]. Pass-through env keys are included as
// `--env KEY` repeats so pipelock's mcp proxy forwards them to the wrapped
// subprocess without embedding values in its command line.
func wrapCodexArgs(origCmd string, origArgs []string, env map[string]string, configFile string) []string {
	args := []string{codexMCP, codexMCPProxy}
	if configFile != "" {
		args = append(args, codexFlagConfig, configFile)
	}
	// Sort env keys so output is deterministic for tests and dry-run diffs.
	keys := make([]string, 0, len(env))
	for k := range env {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		if !mcp.IsSafeEnvKey(k) {
			args = append(args, codexFlagEnv, k)
		}
	}
	args = append(args, codexArgSeparator)
	args = append(args, origCmd)
	args = append(args, origArgs...)
	return args
}

// wrapCodexURL builds the args list for an HTTP/SSE server wrapped through
// pipelock. Streamable-HTTP servers convert to stdio with --upstream pointing
// at the original URL.
func wrapCodexURL(url, configFile string) []string {
	args := []string{codexMCP, codexMCPProxy}
	if configFile != "" {
		args = append(args, codexFlagConfig, configFile)
	}
	args = append(args, codexFlagUpstream, url)
	return args
}

// unwrapCodexArgs reverses wrapCodexArgs / wrapCodexURL, returning the
// original command/args (or url, in the streamable-HTTP case) so the server
// can be re-registered with codex mcp add. Returns origURL non-empty for
// URL-shaped wraps, otherwise origCmd+origArgs are populated.
func unwrapCodexArgs(args []string) (origCmd string, origArgs []string, origURL string, err error) {
	if len(args) < 2 || args[0] != codexMCP || args[1] != codexMCPProxy {
		return "", nil, "", errors.New("not a pipelock-wrapped args list")
	}
	rest := args[2:]
	for len(rest) > 0 {
		switch rest[0] {
		case codexFlagConfig, codexFlagEnv:
			if len(rest) < 2 {
				return "", nil, "", fmt.Errorf("malformed wrap: trailing %s", rest[0])
			}
			rest = rest[2:]
		case codexFlagUpstream:
			if len(rest) < 2 {
				return "", nil, "", fmt.Errorf("malformed wrap: trailing %s", codexFlagUpstream)
			}
			return "", nil, rest[1], nil
		case codexArgSeparator:
			rest = rest[1:]
			if len(rest) == 0 {
				return "", nil, "", errors.New("malformed wrap: separator with no command")
			}
			return rest[0], append([]string(nil), rest[1:]...), "", nil
		default:
			return "", nil, "", fmt.Errorf("malformed wrap: unexpected token %q", rest[0])
		}
	}
	return "", nil, "", errors.New("malformed wrap: no command or upstream found")
}

// codexInstallPlan is the precomputed action list for a server (preview-able
// before any shell-out). One per input server.
type codexInstallPlan struct {
	Server string
	Action string // codexActionWrapStdio, codexActionWrapURL, codexActionSkipWrapped, codexActionSkipUnsupported
	Reason string // human-readable detail; set when skipped, or when a wrap
	// replaces a wrapper this binary cannot confirm
	NewCmd   string
	NewArgs  []string
	Env      map[string]string
	EnvVars  []string
	Original codexMCPTransport // pre-wrap state, used for rollback if `codex mcp add` fails
}

// planCodexInstall computes the wrap plan for each server. Pure function:
// no I/O, no exec.
func planCodexInstall(servers []codexMCPServer, pipelockBin, configFile string) ([]codexInstallPlan, error) {
	plans := make([]codexInstallPlan, 0, len(servers))
	for _, s := range servers {
		// Blocked declarations must be refused even on an existing wrapper,
		// rather than silently skipped as already installed or unsupported.
		if keys, err := codexEnvKeys(s.Transport); err == nil {
			if err := validateCodexForwarding(keys); err != nil {
				return nil, fmt.Errorf("server %q: %w", s.Name, err)
			}
		}
		unsupportedReason := unsupportedCodexInstallReason(s)
		switch {
		case isCodexWrappedBySelf(s):
			plans = append(plans, codexInstallPlan{
				Server: s.Name,
				Action: codexActionSkipWrapped,
				Reason: "already routed through pipelock",
			})
		case unsupportedReason != "":
			plans = append(plans, codexInstallPlan{
				Server: s.Name,
				Action: codexActionSkipUnsupported,
				Reason: unsupportedReason,
			})
		case s.Transport.Type == codexTransportStdio && s.Transport.Command != "":
			action := codexActionWrapStdio
			envKeys, err := codexEnvKeys(s.Transport)
			if err != nil {
				return nil, err
			}
			newArgs := wrapCodexArgs(s.Transport.Command, s.Transport.Args, envKeys, configFile)
			if classifyCodexWrapper(s) == stateForeignWrapper {
				if codexURLTransportHasAuthOrHeaders(s.Transport) {
					return nil, fmt.Errorf("server %q: %w: wrapper has HTTP authentication settings outside its invocation; restore the original server configuration before installing again", s.Name, mcpwrap.ErrCannotNormalize)
				}
				inner, err := mcpwrap.RecoverInner(s.Transport.Args)
				if err != nil {
					return nil, fmt.Errorf("server %q: %w", s.Name, err)
				}
				if inner.Transport == mcpwrap.TransportUpstream {
					action = codexActionWrapURL
					newArgs = wrapCodexURL(inner.UpstreamURL, configFile)
				} else {
					newArgs = wrapCodexArgs(inner.Command, inner.Args, envKeys, configFile)
				}
			}
			plans = append(plans, codexInstallPlan{
				Server:   s.Name,
				Action:   action,
				Reason:   foreignCodexWrapperReason(s),
				NewCmd:   pipelockBin,
				NewArgs:  newArgs,
				Env:      copyStringMap(s.Transport.Env),
				EnvVars:  append([]string(nil), s.Transport.EnvVars...),
				Original: s.Transport,
			})
		case s.Transport.URL != "":
			plans = append(plans, codexInstallPlan{
				Server:   s.Name,
				Action:   codexActionWrapURL,
				Reason:   foreignCodexWrapperReason(s),
				NewCmd:   pipelockBin,
				NewArgs:  wrapCodexURL(s.Transport.URL, configFile),
				Original: s.Transport,
			})
		default:
			plans = append(plans, codexInstallPlan{
				Server: s.Name,
				Action: codexActionSkipUnsupported,
				Reason: fmt.Sprintf("unsupported transport %q", s.Transport.Type),
			})
		}
	}
	return plans, nil
}

// codexRemovePlan describes how to unwrap one server. Pure function output.
type codexRemovePlan struct {
	Server   string
	Action   string // codexActionUnwrapStdio, codexActionUnwrapURL, codexActionSkipNotWrapped
	Reason   string
	NewCmd   string
	NewArgs  []string
	NewURL   string
	Env      map[string]string
	EnvVars  []string
	Original codexMCPTransport // pre-unwrap (wrapped) state, used for rollback if `codex mcp add` fails
}

// planCodexRemove computes the unwrap plan for each server. Pure function.
func planCodexRemove(servers []codexMCPServer) ([]codexRemovePlan, error) {
	plans := make([]codexRemovePlan, 0, len(servers))
	for _, s := range servers {
		if !isCodexRestorableWrapper(s) {
			plans = append(plans, codexRemovePlan{
				Server: s.Name,
				Action: codexActionSkipNotWrapped,
				Reason: "not wrapped by pipelock",
			})
			continue
		}
		if reason := unsupportedCodexRemoveReason(s); reason != "" {
			return nil, fmt.Errorf("unwrapping %q: %s; edit ~/.codex/config.toml manually", s.Name, reason)
		}
		origCmd, origArgs, origURL, err := unwrapCodexArgs(s.Transport.Args)
		if err != nil {
			return nil, fmt.Errorf("unwrapping %q: %w", s.Name, err)
		}
		switch {
		case origURL != "":
			if len(s.Transport.Env)+len(s.Transport.EnvVars) > 0 {
				return nil, fmt.Errorf("unwrapping %q: stdio environment cannot be preserved on a Codex URL server; restore its URL configuration manually", s.Name)
			}
			plans = append(plans, codexRemovePlan{
				Server:   s.Name,
				Action:   codexActionUnwrapURL,
				NewURL:   origURL,
				Original: s.Transport,
			})
		default:
			plans = append(plans, codexRemovePlan{
				Server:   s.Name,
				Action:   codexActionUnwrapStdio,
				NewCmd:   origCmd,
				NewArgs:  origArgs,
				Env:      copyStringMap(s.Transport.Env),
				EnvVars:  append([]string(nil), s.Transport.EnvVars...),
				Original: s.Transport,
			})
		}
	}
	return plans, nil
}

func copyStringMap(in map[string]string) map[string]string {
	if in == nil {
		return nil
	}
	out := make(map[string]string, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

// runCodexInstall is the top-level handler for `pipelock codex install`.
func runCodexInstall(cmd *cobra.Command, dryRun bool, configFile, codexPathOverride string, quiet bool) error {
	codexBin, err := resolveCodexBinary(codexPathOverride)
	if err != nil {
		return err
	}
	pipelockBin, err := resolvePipelockBinary()
	if err != nil {
		return err
	}
	resolvedConfig, err := cliutil.ResolveConfigForInstall(configFile)
	if err != nil {
		return err
	}
	cliutil.WriteInstallConfigProvenance(cmd.ErrOrStderr(), "codex install", resolvedConfig, quiet)

	servers, err := codexMCPList(cmd.Context(), codexBin)
	if err != nil {
		return err
	}
	plans, err := planCodexInstall(servers, pipelockBin, resolvedConfig.Path)
	if err != nil {
		return err
	}

	// Validate every candidate before any remove/add can change a server.
	for _, p := range plans {
		if p.Action == codexActionWrapStdio || p.Action == codexActionWrapURL {
			if err := preflightCodexEnv(p.Original); err != nil {
				return fmt.Errorf("wrapping %q: %w", p.Server, err)
			}
		}
	}
	wrapped, skipped := 0, 0
	for _, p := range plans {
		switch p.Action {
		case codexActionWrapStdio, codexActionWrapURL:
			if p.Reason != "" {
				_, _ = fmt.Fprintf(cmd.ErrOrStderr(), "warning: server %q %s\n", p.Server, p.Reason)
			}
			if dryRun {
				_, _ = fmt.Fprintf(cmd.OutOrStdout(),
					"would wrap %s (%s): codex mcp add %s -- %s %s\n",
					p.Server, p.Action, p.Server, strconv.Quote(p.NewCmd), joinArgs(p.NewArgs)+formatEnvFlags(p.Env, p.EnvVars))
				wrapped++
				continue
			}
			if err := codexReplaceServer(cmd.Context(), codexBin, p.Server, codexMCPTransport{Type: codexTransportStdio, Command: p.NewCmd, Args: p.NewArgs, Env: p.Env, EnvVars: p.EnvVars}, p.Original); err != nil {
				return fmt.Errorf("wrapping %q: %w", p.Server, err)
			}
			_, _ = fmt.Fprintf(cmd.OutOrStdout(), "wrapped %s\n", p.Server)
			writeCodexRuntimeEnv(cmd.OutOrStdout(), p.Server, p.Env, p.EnvVars)
			wrapped++
		case codexActionSkipWrapped, codexActionSkipUnsupported:
			_, _ = fmt.Fprintf(cmd.OutOrStdout(), "skip %s (%s)\n", p.Server, p.Reason)
			skipped++
		}
	}

	if dryRun {
		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Plan: %d to wrap, %d skipped (dry-run, no changes made)\n", wrapped, skipped)
	} else {
		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Wrapped %d server(s), skipped %d.\n", wrapped, skipped)
		if wrapped > 0 {
			_, _ = fmt.Fprintln(cmd.OutOrStdout(), "Restart Codex sessions to pick up the wrapped MCP servers.")
			_, _ = fmt.Fprintln(cmd.OutOrStdout(), "Note: Codex's HTTP fetches (LLM calls, WebFetch) follow HTTPS_PROXY from your shell.")
			_, _ = fmt.Fprintln(cmd.OutOrStdout(), "      Run pipelock locally and export HTTPS_PROXY=http://127.0.0.1:8888 to scan those.")
		}
	}
	return nil
}

// runCodexRemove is the top-level handler for `pipelock codex remove`.
func runCodexRemove(cmd *cobra.Command, dryRun bool, codexPathOverride string) error {
	codexBin, err := resolveCodexBinary(codexPathOverride)
	if err != nil {
		return err
	}
	// Remove no longer resolves the pipelock binary. Identity now comes from
	// os.Executable() inside the classifier, and requiring a PATH lookup here
	// made remove fail for an operator whose pipelock had been moved, which is
	// exactly when they most need to unwrap their editors.
	servers, err := codexMCPList(cmd.Context(), codexBin)
	if err != nil {
		return err
	}
	plans, err := planCodexRemove(servers)
	if err != nil {
		return err
	}

	for _, p := range plans {
		if p.Action == codexActionUnwrapStdio || p.Action == codexActionUnwrapURL {
			if err := preflightCodexEnv(p.Original); err != nil {
				return fmt.Errorf("unwrapping %q: %w", p.Server, err)
			}
		}
	}
	unwrapped, skipped := 0, 0
	for _, p := range plans {
		switch p.Action {
		case codexActionUnwrapStdio:
			if dryRun {
				_, _ = fmt.Fprintf(cmd.OutOrStdout(),
					"would unwrap %s: codex mcp add %s -- %s %s\n",
					p.Server, p.Server, strconv.Quote(p.NewCmd), joinArgs(p.NewArgs)+formatEnvFlags(p.Env, p.EnvVars))
				unwrapped++
				continue
			}
			if err := codexReplaceServer(cmd.Context(), codexBin, p.Server, codexMCPTransport{Type: codexTransportStdio, Command: p.NewCmd, Args: p.NewArgs, Env: p.Env, EnvVars: p.EnvVars}, p.Original); err != nil {
				return fmt.Errorf("unwrapping %q: %w", p.Server, err)
			}
			_, _ = fmt.Fprintf(cmd.OutOrStdout(), "unwrapped %s\n", p.Server)
			writeCodexRuntimeEnv(cmd.OutOrStdout(), p.Server, p.Env, p.EnvVars)
			unwrapped++
		case codexActionUnwrapURL:
			if dryRun {
				_, _ = fmt.Fprintf(cmd.OutOrStdout(), "would unwrap %s: codex mcp add %s --url %s\n", p.Server, p.Server, strconv.Quote(p.NewURL))
				unwrapped++
				continue
			}
			if err := codexReplaceURL(cmd.Context(), codexBin, p.Server, p.NewURL, p.Original); err != nil {
				return fmt.Errorf("unwrapping %q: %w", p.Server, err)
			}
			_, _ = fmt.Fprintf(cmd.OutOrStdout(), "unwrapped %s\n", p.Server)
			writeCodexRuntimeEnv(cmd.OutOrStdout(), p.Server, p.Env, p.EnvVars)
			unwrapped++
		case codexActionSkipNotWrapped:
			_, _ = fmt.Fprintf(cmd.OutOrStdout(), "skip %s (%s)\n", p.Server, p.Reason)
			skipped++
		}
	}

	if dryRun {
		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Plan: %d to unwrap, %d skipped (dry-run, no changes made)\n", unwrapped, skipped)
	} else {
		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Unwrapped %d server(s), skipped %d.\n", unwrapped, skipped)
	}
	return nil
}

// codexReplaceServer is the stdio-server replace primitive: remove + add.
// The remove is best-effort: a "not found" error is treated as success.
//
// If the add step fails after the remove succeeded, the server is gone from
// Codex's config. We attempt to roll back by re-adding the original transport
// (captured before the remove call). The error returned distinguishes the
// rollback-succeeded case ("rolled back to original config") from the
// rollback-failed case ("rollback also failed; verify with codex mcp list").
func codexReplaceServer(ctx context.Context, codexBin, name string, replacement, original codexMCPTransport) error {
	// Check inheritance and config readability before removing the original.
	for _, transport := range []codexMCPTransport{replacement, original} {
		if err := preflightCodexEnv(transport); err != nil {
			return err
		}
	}
	if err := codexMCPRemoveBestEffort(ctx, codexBin, name); err != nil {
		return err
	}
	if addErr := addCodexStdio(ctx, codexBin, name, replacement); addErr != nil {
		if rbErr := rollbackCodexAdd(ctx, codexBin, name, original); rbErr != nil {
			return fmt.Errorf("codex mcp add %s failed and rollback also failed (server may be missing; verify with `codex mcp list`): %w", name, errors.Join(addErr, rbErr))
		}
		return fmt.Errorf("codex mcp add %s: %w (rolled back to original config)", name, addErr)
	}
	return nil
}

// codexReplaceURL is the URL-server replace primitive: remove + add --url.
// Same rollback semantics as codexReplaceServer.
func codexReplaceURL(ctx context.Context, codexBin, name, url string, original codexMCPTransport) error {
	if err := preflightCodexEnv(original); err != nil {
		return err
	}
	if err := codexMCPRemoveBestEffort(ctx, codexBin, name); err != nil {
		return err
	}
	if _, addErr := runCodexCommand(ctx, codexBin, "mcp", "add", name, "--url", url); addErr != nil {
		if rbErr := rollbackCodexAdd(ctx, codexBin, name, original); rbErr != nil {
			return fmt.Errorf("codex mcp add %s --url failed and rollback also failed (server may be missing; verify with `codex mcp list`): %w", name, errors.Join(addErr, rbErr))
		}
		return fmt.Errorf("codex mcp add %s --url: %w (rolled back to original config)", name, addErr)
	}
	return nil
}

// buildCodexAddArgs contains only the command and its arguments. Environment
// declarations are persisted separately as env_vars, never as --env KEY=VALUE.
func buildCodexAddArgs(name, command string, args []string) []string {
	addArgs := []string{"mcp", "add", name, "--", command}
	return append(addArgs, args...)
}

func addCodexStdio(ctx context.Context, codexBin, name string, transport codexMCPTransport) error {
	if err := preflightCodexEnv(transport); err != nil {
		return err
	}
	if _, err := runCodexCommand(ctx, codexBin, buildCodexAddArgs(name, transport.Command, transport.Args)...); err != nil {
		return err
	}
	return persistCodexEnvNames(name, transport)
}

// rollbackCodexAdd re-registers a server using the captured original transport
// so a failed wrap or unwrap does not leave the user's Codex config with a
// missing server. Returns the rollback error if the re-add itself fails.
func rollbackCodexAdd(ctx context.Context, codexBin, name string, original codexMCPTransport) error {
	if original.Type == codexTransportStdio || (original.Command != "" && original.URL == "") {
		return addCodexStdio(ctx, codexBin, name, original)
	}
	if original.URL != "" {
		_, err := runCodexCommand(ctx, codexBin, "mcp", "add", name, "--url", original.URL)
		return err
	}
	return fmt.Errorf("captured original transport has neither command nor url (type=%q)", original.Type)
}

// codexMCPRemoveBestEffort removes a server, treating "not found" as success.
func codexMCPRemoveBestEffort(ctx context.Context, codexBin, name string) error {
	_, err := runCodexCommand(ctx, codexBin, "mcp", "remove", name)
	if err == nil || errors.Is(err, errCodexServerNotFound) {
		return nil
	}
	return fmt.Errorf("codex mcp remove %s: %w", name, err)
}

// runCodexCommand returns output only on success. Failed child output may
// contain config values, so only the exit status and safe repair hint escape.
// Missing-server classification for remove stays private to this function. codexBin is the resolved path of an external CLI tool, either from
// exec.LookPath (PATH) or the user-supplied --codex-path; passing a malicious
// path would be the user attacking themselves.
//
//nolint:gosec // G204: canonical CLI subprocess invocation; see comment above.
func runCodexCommand(ctx context.Context, codexBin string, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, codexBin, args...)
	cmd.Env = append(os.Environ(), "NO_COLOR=1")
	out, err := cmd.CombinedOutput()
	if err != nil {
		safeErr := fmt.Errorf("codex MCP command failed; %s: %w", codexParserFailureHint, err)
		if len(args) >= 2 && args[0] == codexMCP && args[1] == "remove" {
			low := bytes.ToLower(out)
			if bytes.Contains(low, []byte("not found")) || bytes.Contains(low, []byte("does not exist")) {
				return nil, errors.Join(errCodexServerNotFound, safeErr)
			}
		}
		return nil, safeErr
	}
	return out, nil
}

const codexParserFailureHint = "repair config.toml before retrying; parser details withheld to protect environment values"

var errCodexServerNotFound = errors.New("codex MCP server not found")

func writeCodexRuntimeEnv(w io.Writer, server string, env map[string]string, envVars []string) {
	keys, _ := codexEnvKeys(codexMCPTransport{Env: env, EnvVars: envVars})
	if len(keys) == 0 {
		return
	}
	names := make([]string, 0, len(keys))
	for key := range keys {
		names = append(names, key)
	}
	sort.Strings(names)
	_, _ = fmt.Fprintf(w, "Codex must inherit for %s: %s\n", server, strings.Join(names, ", "))
}

// formatEnvFlags previews the config whitelist without displaying values.
func formatEnvFlags(env map[string]string, envVars []string) string {
	keys, _ := codexEnvKeys(codexMCPTransport{Env: env, EnvVars: envVars})
	if len(keys) == 0 {
		return ""
	}
	names := make([]string, 0, len(keys))
	for key := range keys {
		names = append(names, key)
	}
	sort.Strings(names)
	return " (Codex env_vars: " + strings.Join(names, ", ") + ")"
}

// joinArgs renders args for human-readable preview output.
func joinArgs(args []string) string {
	out := ""
	for i, a := range args {
		if i > 0 {
			out += " "
		}
		out += strconv.Quote(a)
	}
	return out
}

// foreignCodexWrapperReason describes an entry that runs proxy arguments through a
// binary this one cannot confirm. Wrapping proceeds, so the result IS mediated;
// the note exists so a false mediation claim is visible rather than silently
// corrected, matching the warning the map-based installers emit.
func foreignCodexWrapperReason(server codexMCPServer) string {
	if classifyCodexWrapper(server) != stateForeignWrapper {
		return ""
	}
	return fmt.Sprintf(
		"runs %q with proxy arguments from another binary; replacing the wrapper from its invocation",
		server.Transport.Command)
}
