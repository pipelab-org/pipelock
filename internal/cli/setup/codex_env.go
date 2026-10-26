// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package setup

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/BurntSushi/toml"
)

// codexEnvKeys combines literal declarations and Codex's name-only whitelist.
// Name syntax matches the child-environment contract in internal/mcpwrap,
// additionally excluding a leading dash because names also reach --env flags.
func codexEnvKeys(transport codexMCPTransport) (map[string]string, error) {
	env := make(map[string]string, len(transport.Env)+len(transport.EnvVars))
	for key := range transport.Env {
		env[key] = ""
	}
	for _, key := range transport.EnvVars {
		env[key] = ""
	}
	for key := range env {
		if key == "" || strings.HasPrefix(key, "-") || strings.ContainsAny(key, "=\x00") {
			return nil, errors.New("invalid Codex environment variable name: empty, leading dash, equals sign or NUL; correct the name before retrying")
		}
	}
	return env, nil
}

// validateCodexEnv refuses to convert a literal unless inheritance preserves
// its value. Only the key is included in diagnostics, even on mismatches.
func validateCodexEnv(transport codexMCPTransport) error {
	if _, err := codexEnvKeys(transport); err != nil {
		return err
	}
	for key, value := range transport.Env {
		inherited, present := os.LookupEnv(key)
		if !present || inherited != value {
			return fmt.Errorf("environment variable %q must be exported with its configured value in the environment running setup and Codex; export it there and retry", key)
		}
	}
	return nil
}

func codexConfigPath() (string, error) {
	home := os.Getenv("CODEX_HOME")
	if home == "" {
		userHome, err := os.UserHomeDir()
		if err != nil {
			return "", fmt.Errorf("finding Codex home: %w", err)
		}
		home = filepath.Join(userHome, ".codex")
	}
	if !filepath.IsAbs(home) {
		return "", errors.New("CODEX_HOME must be an absolute path")
	}
	return filepath.Join(home, "config.toml"), nil
}

func readCodexConfig() (string, map[string]any, error) {
	path, err := codexConfigPath()
	if err != nil {
		return "", nil, err
	}
	data, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		return "", nil, fmt.Errorf("reading Codex config: %w", err)
	}
	var document map[string]any
	if _, err := toml.Decode(string(data), &document); err != nil {
		// TOML errors can quote a line containing credentials.
		return "", nil, errors.New("cannot parse Codex config; repair config.toml before retrying (parser details withheld to protect environment values)")
	}
	return path, document, nil
}

// persistCodexEnvNames updates the entry written by `codex mcp add`. The CLI
// has no name-only stdio flag; the vendor config reference defines env_vars:
// https://developers.openai.com/codex/config-reference/#config-toml
// Reuse the installers' private atomic writer rather than passing values in
// argv. Unrelated TOML data is retained, but comments/formatting are normalized.
func persistCodexEnvNames(name string, transport codexMCPTransport) error {
	env, err := codexEnvKeys(transport)
	if err != nil {
		return err
	}
	if len(env) == 0 {
		return nil
	}
	path, document, err := readCodexConfig()
	if err != nil {
		return err
	}
	servers, ok := document["mcp_servers"].(map[string]any)
	if !ok {
		return errors.New("no mcp_servers table in Codex config after registration")
	}
	server, ok := servers[name].(map[string]any)
	if !ok {
		return fmt.Errorf("no server %q in Codex config after registration", name)
	}
	keys := make([]string, 0, len(env))
	for key := range env {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	delete(server, "env")
	server["env_vars"] = keys
	var output bytes.Buffer
	if err := toml.NewEncoder(&output).Encode(document); err != nil {
		return errors.New("cannot encode Codex config for name-only environment forwarding")
	}
	return vscodeAtomicWrite(path, output.Bytes(), filepath.Dir(path))
}

// preflightCodexEnv verifies all value-bearing prerequisites before mutation.
func preflightCodexEnv(transport codexMCPTransport) error {
	if err := validateCodexEnv(transport); err != nil {
		return err
	}
	if len(transport.Env)+len(transport.EnvVars) > 0 {
		_, _, err := readCodexConfig()
		return err
	}
	return nil
}
