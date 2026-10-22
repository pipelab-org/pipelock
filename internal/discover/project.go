// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package discover

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"sort"

	"github.com/BurntSushi/toml"
)

// launchLimit describes evidence we did not collect, not an assertion that a
// particular override is active. Even an unknown client's launch configuration
// cannot be authenticated by reading a home-level file.
func launchLimit(client string) string {
	switch client {
	case clientCodex:
		// https://developers.openai.com/codex/config-basic/#configuration-precedence
		return "Codex profiles, CLI overrides, plugins, and managed settings are not resolved; only registered trusted projects and requested project directories are checked"
	case clientGrok:
		// https://docs.x.ai/build/features/mcp-servers (Project scope, Compatibility)
		return "Grok plugins, compatibility sources, environment expansion, and managed settings are not resolved; project files are checked only for requested directories"
	case clientClaudeCode:
		// https://code.claude.com/docs/en/mcp (MCP installation scopes)
		return "Claude Code project .mcp.json files and launch overrides are not checked"
	case clientCursor:
		// https://cursor.com/docs/context/mcp (Configuration locations)
		return "Cursor project .cursor/mcp.json files are not checked"
	case clientVSCode:
		// https://code.visualstudio.com/docs/copilot/customization/mcp-servers
		return "VS Code workspace .vscode/mcp.json files and profiles are not checked"
	default:
		return "Discovery checks configuration files only; other configuration sources and the client's launch context are not verified"
	}
}

// discoverProjects emits a separate effective file view per project. The user
// view is retained for launches elsewhere. These are inventories of checked
// layers, never proof of the client's actual launch (see launchLimit).
func discoverProjects(cp clientPath, requested []string) ([]MCPServer, []ClientConfig) {
	base, err := readTOMLDocument(cp.Path)
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	} // caller records base parse errors
	if base == nil {
		base = map[string]any{}
	}
	roots := append([]string(nil), requested...)
	explicit := make(map[string]bool, len(requested))
	for _, root := range requested {
		explicit[filepath.Clean(root)] = true
	}
	projects, _ := base["projects"].(map[string]any)
	if cp.Client == clientCodex {
		// projects.<path>.trust_level is documented in the configuration reference:
		// https://developers.openai.com/codex/config-reference/#config-toml
		for path, raw := range projects {
			if entry, ok := raw.(map[string]any); ok && entry["trust_level"] == "trusted" {
				roots = append(roots, path)
			}
		}
	}
	sort.Strings(roots)
	seen := map[string]bool{}
	var servers []MCPServer
	var clients []ClientConfig
	for _, root := range roots {
		root = filepath.Clean(root)
		if seen[root] {
			continue
		}
		seen[root] = true
		failure := ClientConfig{Client: cp.Client, ConfigPath: root, Scope: "project"}
		info, statErr := os.Stat(root)
		// A registered trust entry outlives the directory it names (a deleted
		// clone or worktree). No process can start in a missing directory, so
		// such an entry has no layers to check. A requested directory, and any
		// failure other than absence, is still reported.
		if filepath.IsAbs(root) && errors.Is(statErr, fs.ErrNotExist) && !explicit[root] {
			continue
		}
		if !filepath.IsAbs(root) || statErr != nil || !info.IsDir() {
			failure.ParseError = "project directory is missing, unreadable, or not absolute"
			clients = append(clients, failure)
			continue
		}
		dirs := projectAncestors(root)
		effective := cloneTOMLTable(base)
		origins := map[string]string{}
		urlOrigins := map[string]string{}
		found, failed := false, false
		trust := ""
		for _, dir := range dirs {
			if cp.Client == clientCodex {
				// Codex checks trust per layer: a trusted root still applies when
				// a child is untrusted; a trusted child can apply over an untrusted
				// root. Reproduced with codex-cli 0.162.0 mcp list --json in a
				// Git fixture (root/child trust matrix in TestDiscoverProjectLayers).
				if entry, ok := projects[dir].(map[string]any); ok {
					trust, _ = entry["trust_level"].(string)
				}
				if trust != "trusted" {
					continue
				}
			}
			name := ".codex"
			if cp.Client == clientGrok {
				name = ".grok"
			}
			path := filepath.Join(dir, name, codexConfigName)
			// Do not count the user file again when the requested cwd is home.
			if path == cp.Path {
				continue
			}
			present, inspectErr := inspectConfigPath(path)
			if inspectErr == nil && !present {
				continue
			}
			layerClient := ClientConfig{Client: cp.Client, ConfigPath: path, Scope: "project"}
			if inspectErr != nil {
				layerClient.ParseError = inspectErr.Error()
				clients = append(clients, layerClient)
				failed = true
				break
			}
			layer, readErr := readTOMLDocument(path)
			if readErr != nil {
				layerClient.ParseError = errInvalidTOMLMCPConfig.Error()
				clients = append(clients, layerClient)
				failed = true
				break
			}
			// Validate each layer's exact MCP table shape before merging. Partial
			// Codex entries are legal: unspecified fields inherit from lower layers.
			parsed, parseErr := parseTOMLDocument(layer, path, cp.Client)
			if parseErr != nil {
				layerClient.ParseError = errInvalidTOMLMCPConfig.Error()
				clients = append(clients, layerClient)
				failed = true
				break
			}
			layerClient.ServerCount = len(parsed)
			clients = append(clients, layerClient)
			found = true
			for _, server := range parsed {
				// Codex inherits unspecified fields. A layer that only toggles
				// enabled does not define the command to edit when wrapping.
				entries := layer[tomlKeyServers].(map[string]any)
				entry := entries[server.ServerName].(map[string]any)
				if _, definesCommand := entry[tomlKeyCommand]; definesCommand || cp.Client == clientGrok {
					origins[server.ServerName] = path
				}
				if _, definesURL := entry[tomlKeyURL]; definesURL {
					urlOrigins[server.ServerName] = path
				}
			}
			if cp.Client == clientGrok {
				replaceGrokServers(effective, layer)
			} else {
				mergeTOMLTable(effective, layer)
			}
		}
		if !found || failed {
			continue
		}
		parsed, parseErr := parseTOMLDocument(effective, cp.Path, cp.Client)
		if parseErr != nil {
			failure.ParseError = errInvalidTOMLMCPConfig.Error()
			clients = append(clients, failure)
			continue
		}
		for i := range parsed {
			parsed[i].ProjectPath = root
			path := origins[parsed[i].ServerName]
			if parsed[i].Command == "" && parsed[i].URL != "" {
				path = urlOrigins[parsed[i].ServerName]
			}
			if path != "" {
				parsed[i].ConfigPath = path
			}
		}
		servers = append(servers, parsed...)
	}
	return servers, clients
}

func readTOMLDocument(path string) (map[string]any, error) {
	data, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		return nil, err
	}
	var document map[string]any
	if _, err = toml.Decode(string(data), &document); err != nil {
		return nil, errInvalidTOMLMCPConfig
	}
	return document, nil
}

// projectAncestors follows the documented root-to-cwd order using a .git
// marker, which can be a directory or a worktree pointer file. It does not
// validate Git metadata or resolve client-specific root markers. Without a
// marker only the requested directory is checked; launch stays unconfirmed.
// Codex: https://developers.openai.com/codex/config-basic/#configuration-precedence
// Grok: https://docs.x.ai/build/features/mcp-servers#project-scope
func projectAncestors(cwd string) []string {
	dirs := []string{}
	for dir := cwd; ; dir = filepath.Dir(dir) {
		dirs = append(dirs, dir)
		if _, err := os.Stat(filepath.Join(dir, ".git")); err == nil {
			for i, j := 0, len(dirs)-1; i < j; i, j = i+1, j-1 {
				dirs[i], dirs[j] = dirs[j], dirs[i]
			}
			return dirs
		}
		if filepath.Dir(dir) == dir {
			return []string{cwd}
		}
	}
}

func cloneTOMLTable(table map[string]any) map[string]any {
	out := make(map[string]any, len(table))
	for key, value := range table {
		if nested, ok := value.(map[string]any); ok {
			out[key] = cloneTOMLTable(nested)
		} else {
			out[key] = value
		}
	}
	return out
}

// Codex tables are recursively merged, scalars and arrays replaced. This is
// the client behavior reproduced with codex-cli 0.162.0: in a trusted project,
// `codex mcp list --json` retains user args when a project overrides only
// command and enabled. See TestDiscoverProjectLayers for the fixture.
// Layer precedence: https://developers.openai.com/codex/config-basic/
func mergeTOMLTable(base, layer map[string]any) {
	for key, value := range layer {
		lower, lowerOK := base[key].(map[string]any)
		upper, upperOK := value.(map[string]any)
		if lowerOK && upperOK {
			mergeTOMLTable(lower, upper)
		} else {
			base[key] = value
		}
	}
}

// Grok replaces same-name project servers entirely, rather than inheriting
// command/args/env from the user entry. Nearest project file wins.
// https://docs.x.ai/build/features/mcp-servers#project-scope
func replaceGrokServers(base, layer map[string]any) {
	upper, ok := layer[tomlKeyServers].(map[string]any)
	if !ok {
		return
	}
	lower, ok := base[tomlKeyServers].(map[string]any)
	if !ok {
		lower = map[string]any{}
		base[tomlKeyServers] = lower
	}
	for name, entry := range upper {
		lower[name] = entry
	}
}
