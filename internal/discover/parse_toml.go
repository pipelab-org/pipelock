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
// are read; unrelated client settings remain outside this inventory.
//
// Keys are matched exactly. TOML keys are case-sensitive and the clients
// read them that way, but the decoder's struct mapping also accepts a
// case-variant key (Command for command), which would let a key the client
// ignores shadow the one it runs and report an unwrapped server as protected.
// Decoding into generic tables and looking keys up by exact name keeps the
// inventory describing what the client will launch.
const (
	tomlKeyServers  = "mcp_servers"
	tomlKeyType     = "type"
	tomlKeyCommand  = "command"
	tomlKeyArgs     = "args"
	tomlKeyEnv      = "env"
	tomlKeyURL      = "url"
	tomlKeyHeaders  = "headers"
	tomlKeyHTTPHdrs = "http_headers"
	tomlKeyEnvHdrs  = "env_http_headers"
)

var errInvalidTOMLMCPConfig = errors.New("invalid TOML MCP config")

// parseTOMLConfig inventories the published client MCP table without running
// a client executable. Parser errors are deliberately fixed text: a TOML
// decoder error may echo a line containing a credential.
func parseTOMLConfig(path, client string) ([]MCPServer, error) {
	data, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", path, err)
	}
	invalid := fmt.Errorf("parsing %s: %w", path, errInvalidTOMLMCPConfig)

	var document map[string]any
	if _, err := toml.Decode(string(data), &document); err != nil {
		return nil, invalid
	}
	rawServers, present := document[tomlKeyServers]
	if !present {
		return nil, nil
	}
	table, ok := rawServers.(map[string]any)
	if !ok {
		return nil, invalid
	}

	servers := make([]MCPServer, 0, len(table))
	for name, rawEntry := range table {
		entry, ok := rawEntry.(map[string]any)
		if !ok {
			return nil, invalid
		}
		s := MCPServer{Client: client, ConfigPath: path, ServerName: name}
		var serverType string
		var hasHeaders bool
		if serverType, ok = tomlString(entry, tomlKeyType); !ok {
			return nil, invalid
		}
		if s.Command, ok = tomlString(entry, tomlKeyCommand); !ok {
			return nil, invalid
		}
		if s.URL, ok = tomlString(entry, tomlKeyURL); !ok {
			return nil, invalid
		}
		if s.Args, ok = tomlStringList(entry, tomlKeyArgs); !ok {
			return nil, invalid
		}
		if s.Env, ok = tomlStringTable(entry, tomlKeyEnv); !ok {
			return nil, invalid
		}
		for _, key := range []string{tomlKeyHeaders, tomlKeyHTTPHdrs, tomlKeyEnvHdrs} {
			headers, valid := tomlStringTable(entry, key)
			if !valid {
				return nil, invalid
			}
			hasHeaders = hasHeaders || len(headers) > 0
		}
		s.Transport = inferTransport(rawServer{Type: serverType, Command: s.Command}, s.URL)
		if hasHeaders {
			s.ParseWarnings = append(s.ParseWarnings, "headers present but not preserved in wrapper suggestions")
		}
		servers = append(servers, s)
	}
	return servers, nil
}

// tomlString returns the string under the exact key, or "" when absent. A
// present value of another type is not ok.
func tomlString(table map[string]any, key string) (string, bool) {
	raw, present := table[key]
	if !present {
		return "", true
	}
	s, ok := raw.(string)
	return s, ok
}

// tomlStringList returns the string array under the exact key, or an empty
// list when absent. A present value of another type is not ok.
func tomlStringList(table map[string]any, key string) ([]string, bool) {
	raw, present := table[key]
	if !present {
		return []string{}, true
	}
	items, ok := raw.([]any)
	if !ok {
		return nil, false
	}
	out := make([]string, 0, len(items))
	for _, item := range items {
		s, ok := item.(string)
		if !ok {
			return nil, false
		}
		out = append(out, s)
	}
	return out, true
}

// tomlStringTable returns the string-valued table under the exact key, or nil
// when absent. A present value of another type is not ok.
func tomlStringTable(table map[string]any, key string) (map[string]string, bool) {
	raw, present := table[key]
	if !present {
		return nil, true
	}
	entries, ok := raw.(map[string]any)
	if !ok {
		return nil, false
	}
	out := make(map[string]string, len(entries))
	for k, v := range entries {
		s, ok := v.(string)
		if !ok {
			return nil, false
		}
		out[k] = s
	}
	return out, true
}
