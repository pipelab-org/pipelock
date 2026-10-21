// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package discover

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"sort"
)

// ProtectionStatus classifies how (or if) an MCP server is wrapped.
type ProtectionStatus string

const (
	ProtectedPipelock ProtectionStatus = "protected_pipelock"
	ProtectedOther    ProtectionStatus = "protected_other"
	Unprotected       ProtectionStatus = "unprotected"
	Unknown           ProtectionStatus = "unknown"
)

// RiskLevel for unprotected servers based on capability heuristics.
type RiskLevel string

const (
	RiskHigh   RiskLevel = "high"
	RiskMedium RiskLevel = "medium"
	RiskLow    RiskLevel = "low"
)

// Transport type constants.
const (
	TransportStdio   = "stdio"
	TransportHTTP    = "http"
	TransportUnknown = "unknown"
)

// OS name constants for platform-aware logic.
const (
	osDarwin  = "darwin"
	osWindows = "windows"
)

// MCP client name constants.
const (
	clientClaudeCode        = "claude-code"
	clientCodex             = "codex"
	clientGrok              = "grok"
	clientClaudeDesktop     = "claude-desktop"
	clientCursor            = "cursor"
	clientJunie             = "junie"
	clientVSCode            = "vscode"
	clientZed               = "zed"
	clientZedPreview        = "zed-preview"
	clientZedFlatpak        = "zed-flatpak"
	clientZedPreviewFlatpak = "zed-preview-flatpak"
)

// Config scope constants.
const (
	scopeUser = "user"
)

// Config-key constants shared across parsers.
const (
	configKeyMCPServers     = "mcpServers"
	configKeyServers        = "servers"
	configKeyContextServers = "context_servers"
)

// evidenceNoProxy is the warning string emitted when no proxy wrapper is detected.
const evidenceNoProxy = "no proxy wrapper detected"

// CLI flags emitted in wrapper-suggestion args and matched by detection logic.
const (
	flagConfig = "--config"
)

var continueConfigExtensions = []string{".yaml", ".yml"}

// IsContinueConfigExtension reports whether ext is a documented Continue YAML
// configuration extension. Setup imports this package so discovery and install
// use this one extension set rather than duplicating it.
func IsContinueConfigExtension(ext string) bool {
	for _, supported := range continueConfigExtensions {
		if ext == supported {
			return true
		}
	}
	return false
}

// Pipelock wrapper command/arg constants used by classifier + generator.
const (
	wrapperCommand  = "pipelock"
	wrapperArgMCP   = "mcp"
	wrapperArgProxy = "proxy"
)

// MCPServer is a single discovered MCP server configuration.
type MCPServer struct {
	Client        string            `json:"client"`
	ConfigPath    string            `json:"config_path"`
	ProjectPath   string            `json:"project_path,omitempty"`
	ServerName    string            `json:"server_name"`
	Transport     string            `json:"transport"` // "stdio", "http", "sse", "unknown"
	Command       string            `json:"command"`
	Args          []string          `json:"args"`
	Env           map[string]string `json:"env,omitempty"`
	URL           string            `json:"url"`
	Protection    ProtectionStatus  `json:"protection_state"`
	Risk          RiskLevel         `json:"risk"`
	Evidence      string            `json:"evidence"`
	ParseWarnings []string          `json:"parse_warnings"`
}

// ClientConfig is one discovered agent client installation.
type ClientConfig struct {
	Client      string `json:"client"`
	ConfigPath  string `json:"config_path"`
	Scope       string `json:"scope"` // "user", "project"
	ServerCount int    `json:"server_count"`
	ParseError  string `json:"parse_error,omitempty"`
}

// Report is the full discovery result.
type Report struct {
	Clients []ClientConfig `json:"clients"`
	Servers []MCPServer    `json:"servers"`
	Summary Summary        `json:"summary"`
}

// Summary has aggregate counts.
type Summary struct {
	TotalClients      int `json:"total_clients"`
	TotalServers      int `json:"total_servers"`
	ProtectedPipelock int `json:"protected_pipelock"`
	ProtectedOther    int `json:"protected_other"`
	Unprotected       int `json:"unprotected"`
	Unknown           int `json:"unknown"`
	HighRisk          int `json:"high_risk"`
	ParseErrors       int `json:"parse_errors"`
	SOPSExecEnv       int `json:"-"` // only the discover CLI emits this sub-count
}

// clientPath maps a client tool to its config file location.
type clientPath struct {
	Client string // "claude-code", "claude-desktop", "cursor", etc.
	Path   string // absolute path to config file
	Key    string // JSON key containing servers: "mcpServers" or "servers"
	Scope  string // "user" or "project"
	// Warning, when set, is added to every server parsed from this path.
	Warning string
}

// EnvClaudeConfigDir is Claude Code's documented configuration-directory
// override (https://code.claude.com/docs/en/env-vars). With it set, Claude
// Code keeps its global config, including MCP servers, in
// <dir>/.claude.json instead of ~/.claude.json.
const EnvClaudeConfigDir = "CLAUDE_CONFIG_DIR"

// claudeGlobalConfigName is the global config file Claude Code writes in the
// home directory, or in CLAUDE_CONFIG_DIR when that override is set.
const claudeGlobalConfigName = ".claude.json"

// claudeLegacyConfigName is the legacy global config file inside Claude
// Code's config directory. The published @anthropic-ai/claude-code 2.1.0
// resolver reads <config dir>/.config.json in place of .claude.json when it
// exists, where the config dir is CLAUDE_CONFIG_DIR or ~/.claude. Discover
// inventories it alongside .claude.json rather than choosing between them:
// listing a file Claude Code may ignore can only add servers to the report,
// never hide them.
const claudeLegacyConfigName = ".config.json"

// warnClaudeLegacyConfig marks servers read from claudeLegacyConfigName.
const warnClaudeLegacyConfig = "from legacy Claude Code config .config.json; Claude Code 2.1.0 reads this file in place of .claude.json when it exists"

// claudeLegacyPath returns the legacy config entry for a Claude config dir.
func claudeLegacyPath(configDir string) clientPath {
	return clientPath{
		Client:  clientClaudeCode,
		Path:    filepath.Join(configDir, claudeLegacyConfigName),
		Key:     configKeyMCPServers,
		Scope:   scopeUser,
		Warning: warnClaudeLegacyConfig,
	}
}

// errClaudeConfigDirNotAbsolute is reported for a CLAUDE_CONFIG_DIR value that
// is not absolute. Claude Code's docs require an absolute path; a relative one
// would resolve against whichever directory the client starts in, so discover
// reports it instead of guessing.
var errClaudeConfigDirNotAbsolute = errors.New(EnvClaudeConfigDir + " must be an absolute path")

// Options names additional configuration roots to inventory alongside the
// conventional locations under home. Discover never reads the environment
// itself, so its result is determined by its arguments; callers resolve
// overrides at the CLI boundary (see AmbientOptions).
type Options struct {
	// ClaudeConfigDirs are CLAUDE_CONFIG_DIR values. Each contributes
	// <dir>/.claude.json as an additional Claude Code config.
	ClaudeConfigDirs []string
	// CodexHomes are CODEX_HOME values. Each contributes <dir>/config.toml as
	// an additional Codex config.
	CodexHomes []string
}

// EnvCodexHome is Codex's documented home-directory override
// (https://developers.openai.com/codex/config-reference names $CODEX_HOME as
// the directory holding config.toml). With it set, Codex reads and writes its
// MCP servers in <dir>/config.toml instead of ~/.codex/config.toml.
const EnvCodexHome = "CODEX_HOME"

// codexConfigName is the config file inside Codex's home directory.
const codexConfigName = "config.toml"

// errCodexHomeNotAbsolute is reported for a CODEX_HOME value that is not
// absolute, for the same reason as errClaudeConfigDirNotAbsolute.
var errCodexHomeNotAbsolute = errors.New(EnvCodexHome + " must be an absolute path")

// AmbientOptions returns the documented overrides set in the given
// environment lookup, normally os.Getenv.
func AmbientOptions(getenv func(string) string) Options {
	var opts Options
	if dir := getenv(EnvClaudeConfigDir); dir != "" {
		opts.ClaudeConfigDirs = append(opts.ClaudeConfigDirs, dir)
	}
	if dir := getenv(EnvCodexHome); dir != "" {
		opts.CodexHomes = append(opts.CodexHomes, dir)
	}
	return opts
}

// Discover scans the home directory for AI agent client configs and reports
// which MCP servers are configured, their protection status, and risk level.
func Discover(home string) (*Report, error) {
	return DiscoverWithOptions(home, Options{})
}

// DiscoverWithOptions is Discover plus the explicitly supplied configuration
// roots in opts. A file reachable from more than one root for the same client
// and parser is reported once.
func DiscoverWithOptions(home string, opts Options) (*Report, error) {
	paths := configPaths(home)
	var rootErrors []ClientConfig
	for _, dir := range opts.ClaudeConfigDirs {
		if !filepath.IsAbs(dir) {
			rootErrors = append(rootErrors, ClientConfig{
				Client:     clientClaudeCode,
				ConfigPath: dir,
				Scope:      scopeUser,
				ParseError: errClaudeConfigDirNotAbsolute.Error(),
			})
			continue
		}
		paths = append(paths, clientPath{
			Client: clientClaudeCode,
			Path:   filepath.Join(filepath.Clean(dir), claudeGlobalConfigName),
			Key:    configKeyMCPServers,
			Scope:  scopeUser,
		}, claudeLegacyPath(filepath.Clean(dir)))
	}
	for _, dir := range opts.CodexHomes {
		if !filepath.IsAbs(dir) {
			rootErrors = append(rootErrors, ClientConfig{
				Client:     clientCodex,
				ConfigPath: dir,
				Scope:      scopeUser,
				ParseError: errCodexHomeNotAbsolute.Error(),
			})
			continue
		}
		paths = append(paths, clientPath{
			Client: clientCodex,
			Path:   filepath.Join(filepath.Clean(dir), codexConfigName),
			Key:    tomlKeyServers,
			Scope:  scopeUser,
		})
	}
	paths = dedupeConfigPaths(paths)

	clients := rootErrors
	var servers []MCPServer

	for _, cp := range paths {
		present, inspectErr := inspectConfigPath(cp.Path)
		if inspectErr != nil {
			// The path exists in some form but cannot be read as a config
			// file: report it rather than presenting an unread config as
			// an empty, clean scan.
			clients = append(clients, ClientConfig{
				Client:     cp.Client,
				ConfigPath: cp.Path,
				Scope:      cp.Scope,
				ParseError: inspectErr.Error(),
			})
			continue
		}
		if !present {
			continue
		}

		var parsed []MCPServer
		var err error

		// Claude Code has nested per-project servers
		if cp.Client == clientClaudeCode {
			parsed, err = parseClaudeCodeConfig(cp.Path)
		} else if cp.Client == clientCodex || cp.Client == clientGrok {
			parsed, err = parseTOMLConfig(cp.Path, cp.Client)
		} else if cp.Client == "continue" && (filepath.Ext(cp.Path) == ".yaml" || filepath.Ext(cp.Path) == ".yml") {
			parsed, err = parseContinueYAMLConfig(cp.Path)
		} else {
			parsed, err = parseConfigFile(cp.Path, cp.Key, cp.Client)
		}

		if err != nil {
			// Non-fatal: record the client with a parse error so operators
			// know a config exists but could not be read.
			clients = append(clients, ClientConfig{
				Client:      cp.Client,
				ConfigPath:  cp.Path,
				Scope:       cp.Scope,
				ServerCount: 0,
				ParseError:  err.Error(),
			})
			continue
		}

		if len(parsed) > 0 {
			clients = append(clients, ClientConfig{
				Client:      cp.Client,
				ConfigPath:  cp.Path,
				Scope:       cp.Scope,
				ServerCount: len(parsed),
			})
		}

		// Classify each server
		for i := range parsed {
			parsed[i].Protection, parsed[i].Evidence = classifyServer(parsed[i])
			risk, reason := classifyRisk(parsed[i])
			parsed[i].Risk = risk
			if parsed[i].Evidence == evidenceNoProxy {
				parsed[i].Evidence = reason
			}
			if parsed[i].ParseWarnings == nil {
				parsed[i].ParseWarnings = []string{}
			}
			if cp.Warning != "" {
				parsed[i].ParseWarnings = append(parsed[i].ParseWarnings, cp.Warning)
			}
		}

		servers = append(servers, parsed...)
	}

	// Deterministic sort: risk (high first), then client, config path, project path, server name.
	sort.SliceStable(servers, func(i, j int) bool {
		ri, rj := riskOrder(servers[i].Risk), riskOrder(servers[j].Risk)
		if ri != rj {
			return ri < rj
		}
		if servers[i].Client != servers[j].Client {
			return servers[i].Client < servers[j].Client
		}
		if servers[i].ConfigPath != servers[j].ConfigPath {
			return servers[i].ConfigPath < servers[j].ConfigPath
		}
		if servers[i].ProjectPath != servers[j].ProjectPath {
			return servers[i].ProjectPath < servers[j].ProjectPath
		}
		return servers[i].ServerName < servers[j].ServerName
	})

	summary := buildSummary(clients, servers)

	return &Report{
		Clients: clients,
		Servers: servers,
		Summary: summary,
	}, nil
}

// dedupeConfigPaths drops a config path that names the same existing file as
// an earlier one for the same client and parser (for example CLAUDE_CONFIG_DIR
// set to the home directory, or a symlinked root). Different clients or parsers
// can read different servers from one file and must retain their own views.
func dedupeConfigPaths(paths []clientPath) []clientPath {
	type seenPath struct {
		path clientPath
		info os.FileInfo
	}
	var seen []seenPath
	out := make([]clientPath, 0, len(paths))
	for _, cp := range paths {
		info, err := os.Stat(cp.Path)
		if err == nil {
			duplicate := false
			for _, prior := range seen {
				if cp.Client != prior.path.Client || cp.Key != prior.path.Key || cp.Scope != prior.path.Scope {
					continue
				}
				// Continue dispatches by extension: YAML and JSON views of
				// the same file can have different results, including errors.
				if cp.Client == "continue" && IsContinueConfigExtension(filepath.Ext(cp.Path)) != IsContinueConfigExtension(filepath.Ext(prior.path.Path)) {
					continue
				}
				if os.SameFile(prior.info, info) {
					duplicate = true
					break
				}
			}
			if duplicate {
				continue
			}
			seen = append(seen, seenPath{path: cp, info: info})
		}
		out = append(out, cp)
	}
	return out
}

func riskOrder(r RiskLevel) int {
	switch r {
	case RiskHigh:
		return 0
	case RiskMedium:
		return 1
	default:
		return 2
	}
}

func buildSummary(clients []ClientConfig, servers []MCPServer) Summary {
	s := Summary{
		TotalClients: len(clients),
		TotalServers: len(servers),
	}
	for _, c := range clients {
		if c.ParseError != "" {
			s.ParseErrors++
		}
	}
	for _, srv := range servers {
		switch srv.Protection {
		case ProtectedPipelock:
			s.ProtectedPipelock++
		case ProtectedOther:
			s.ProtectedOther++
		case Unprotected:
			s.Unprotected++
			if isSOPSExecEnv(srv.Command, srv.Args) {
				s.SOPSExecEnv++
			}
		case Unknown:
			s.Unknown++
		}
		if srv.Risk == RiskHigh {
			s.HighRisk++
		}
	}
	return s
}

// Errors for a config path that exists but cannot be inspected as a file.
// The messages carry no path or OS error text: the path is already on the
// ClientConfig, and shareable reports redact it there.
var (
	errConfigUninspectable = errors.New("config path exists but could not be inspected")
	errConfigNotFile       = errors.New("config path is not a regular file")
)

// inspectConfigPath reports whether a config file is present. Only proven
// absence (fs.ErrNotExist) means "no config"; every other failure, such as a
// permission error or a symlink loop, is returned so the caller reports it.
func inspectConfigPath(path string) (bool, error) {
	info, err := os.Stat(path)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return false, nil
	case err != nil:
		return false, errConfigUninspectable
	case !info.Mode().IsRegular():
		return false, errConfigNotFile
	}
	return true, nil
}

// configPaths returns all known MCP client config paths for the given home directory.
// Paths are platform-aware: Linux uses XDG (~/.config/), macOS uses
// ~/Library/Application Support/, Windows uses %APPDATA%. Clients that store
// config in the home directory (claude-code, cursor, continue) work on all platforms.
func configPaths(home string) []clientPath {
	return configPathsForOS(home, runtime.GOOS)
}

func configPathsForOS(home, goos string) []clientPath {
	appData := appDataDirForOS(home, goos)

	paths := []clientPath{
		{
			Client: clientClaudeCode,
			Path:   filepath.Join(home, ".claude.json"),
			Key:    configKeyMCPServers,
			Scope:  scopeUser,
		},
		claudeLegacyPath(filepath.Join(home, ".claude")),
		// OpenAI Codex config reference: https://developers.openai.com/codex/config-reference
		{Client: clientCodex, Path: filepath.Join(home, ".codex", codexConfigName), Key: tomlKeyServers, Scope: scopeUser},
		// xAI MCP servers guide: https://docs.x.ai/build/features/mcp-servers
		{Client: clientGrok, Path: filepath.Join(home, ".grok", "config.toml"), Key: tomlKeyServers, Scope: scopeUser},
		{
			Client: clientClaudeDesktop,
			Path:   filepath.Join(appData, "Claude", "claude_desktop_config.json"),
			Key:    configKeyMCPServers,
			Scope:  scopeUser,
		},
		{
			Client: clientCursor,
			Path:   filepath.Join(home, ".cursor", "mcp.json"),
			Key:    configKeyMCPServers,
			Scope:  scopeUser,
		},
		{
			Client: clientVSCode,
			Path:   filepath.Join(appData, "Code", "User", "mcp.json"),
			Key:    configKeyServers,
			Scope:  scopeUser,
		},
		{
			Client: "cline",
			Path:   filepath.Join(appData, "Code", "User", "globalStorage", "saoudrizwan.claude-dev", "settings", "cline_mcp_settings.json"),
			Key:    configKeyMCPServers,
			Scope:  scopeUser,
		},
		{
			Client: "continue",
			Path:   filepath.Join(home, ".continue", "config.yaml"),
			Key:    configKeyMCPServers,
			Scope:  scopeUser,
		},
		{
			Client: "continue",
			Path:   filepath.Join(home, ".continue", "config.json"),
			Key:    configKeyMCPServers,
			Scope:  scopeUser,
		},
		{
			Client: clientJunie,
			Path:   filepath.Join(home, ".junie", wrapperArgMCP, "mcp.json"),
			Key:    configKeyMCPServers,
			Scope:  scopeUser,
		},
		// Zed stores config under ~/.config/zed/ on both Linux and macOS
		// per zed.dev/docs (it does not follow the macOS Application Support
		// convention). The settings.json top-level key is "context_servers"
		// rather than "mcpServers" or "servers".
		{
			Client: clientZed,
			Path:   filepath.Join(home, ".config", "zed", "settings.json"),
			Key:    configKeyContextServers,
			Scope:  scopeUser,
		},
		// Zed Preview is a separate binary that ships ahead of stable; its
		// config dir is "zed-preview" rather than "zed". Users who run both
		// channels need both wraps detected.
		{
			Client: clientZedPreview,
			Path:   filepath.Join(home, ".config", "zed-preview", "settings.json"),
			Key:    configKeyContextServers,
			Scope:  scopeUser,
		},
		// Flatpak-sandboxed Zed lives under $HOME/.var/app/<app-id>/config/.
		// Inside the sandbox Zed sees its own XDG_CONFIG_HOME pointing at
		// that dir, but from outside (where discover runs) the path is fixed.
		{
			Client: clientZedFlatpak,
			Path:   filepath.Join(home, ".var", "app", "dev.zed.Zed", "config", "zed", "settings.json"),
			Key:    configKeyContextServers,
			Scope:  scopeUser,
		},
		{
			Client: clientZedPreviewFlatpak,
			Path:   filepath.Join(home, ".var", "app", "dev.zed.Zed.Preview", "config", "zed-preview", "settings.json"),
			Key:    configKeyContextServers,
			Scope:  scopeUser,
		},
		// Note: project-local .junie/mcp/mcp.json and project-local
		// .zed/settings.json are not scanned here. Discover(home) must be
		// deterministic from its inputs. Project-local scanning requires
		// an explicit project root parameter (future work). Consistent
		// with VS Code (.vscode/mcp.json also not scanned).
	}
	for _, extension := range continueConfigExtensions {
		continueBlocks, _ := filepath.Glob(filepath.Join(home, ".continue", "mcpServers", "*"+extension))
		for _, path := range continueBlocks {
			paths = append(paths, clientPath{Client: "continue", Path: path, Key: configKeyMCPServers, Scope: scopeUser})
		}
	}
	if goos == osWindows {
		// Packaged desktop apps can redirect Roaming data into their private
		// LocalCache. Keep both locations: an existing classic installation
		// can have different entries, and each result retains its source path.
		// Family and config location verified on Claude Desktop 1.40609.0.0
		// via Get-AppxPackage (2026-09-04). Windows package data redirection:
		// https://learn.microsoft.com/windows/msix/desktop/desktop-to-uwp-behind-the-scenes
		paths = append(paths, clientPath{
			Client: clientClaudeDesktop,
			Path: filepath.Join(home, "AppData", "Local", "Packages",
				"Claude_pzs8sxrjxfjjc", "LocalCache", "Roaming", "Claude", "claude_desktop_config.json"),
			Key:   configKeyMCPServers,
			Scope: scopeUser,
		})
	}
	return paths
}

// appDataDir returns the platform-specific application data directory
// derived from the given home directory. This keeps discovery deterministic
// from its inputs (important for testing with temp dirs).
// Linux: home/.config, macOS: home/Library/Application Support,
// Windows: home/AppData/Roaming.
func appDataDir(home string) string {
	return appDataDirForOS(home, runtime.GOOS)
}

func appDataDirForOS(home, goos string) string {
	switch goos {
	case osDarwin:
		return filepath.Join(home, "Library", "Application Support")
	case osWindows:
		return filepath.Join(home, "AppData", "Roaming")
	default:
		return filepath.Join(home, ".config")
	}
}
