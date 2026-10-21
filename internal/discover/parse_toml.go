// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package discover

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/BurntSushi/toml"
)

// Codex: https://developers.openai.com/codex/config-reference
// Grok: https://docs.x.ai/build/features/mcp-servers
// Both publish [mcp_servers.<name>] entries. Only fields needed by discovery
// are decoded; unrelated client settings remain outside this inventory.
type tomlMCPServer struct {
	Type           string            `toml:"type"`
	Command        string            `toml:"command"`
	Args           []string          `toml:"args"`
	Env            map[string]string `toml:"env"`
	URL            string            `toml:"url"`
	Headers        map[string]string `toml:"headers"`
	HTTPHeaders    map[string]string `toml:"http_headers"`
	EnvHTTPHeaders map[string]string `toml:"env_http_headers"`
}

var errInvalidTOMLMCPConfig = errors.New("invalid TOML MCP config")

// parseTOMLConfig inventories the published client MCP table without running
// a client executable. Parser errors are deliberately fixed text: a TOML
// decoder error may echo a line containing a credential.
func parseTOMLConfig(path, client string) ([]MCPServer, error) {
	data, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", path, err)
	}
	var document struct {
		Servers map[string]tomlMCPServer `toml:"mcp_servers"`
	}
	metadata, err := toml.Decode(string(data), &document)
	if err != nil {
		return nil, fmt.Errorf("parsing %s: %w", path, errInvalidTOMLMCPConfig)
	}
	// BurntSushi/toml MetaData.Type calls TOML tables "Hash"; an
	// implicit parent table has no type. Scalars otherwise decode as an
	// empty map without an error.
	if kind := metadata.Type("mcp_servers"); kind != "" && kind != "Hash" {
		return nil, fmt.Errorf("parsing %s: %w", path, errInvalidTOMLMCPConfig)
	}

	servers := make([]MCPServer, 0, len(document.Servers))
	for name, entry := range document.Servers {
		if kind := metadata.Type("mcp_servers", name); kind != "" && kind != "Hash" {
			return nil, fmt.Errorf("parsing %s: %w", path, errInvalidTOMLMCPConfig)
		}
		args := entry.Args
		if args == nil {
			args = []string{}
		}
		s := MCPServer{
			Client:     client,
			ConfigPath: path,
			ServerName: name,
			Command:    entry.Command,
			Args:       args,
			Env:        entry.Env,
			URL:        entry.URL,
		}
		s.Transport = inferTransport(rawServer{Type: entry.Type, Command: entry.Command}, entry.URL)
		if len(entry.Headers) > 0 || len(entry.HTTPHeaders) > 0 || len(entry.EnvHTTPHeaders) > 0 {
			s.ParseWarnings = append(s.ParseWarnings, "headers present but not preserved in wrapper suggestions")
		}
		servers = append(servers, s)
	}
	return servers, nil
}
