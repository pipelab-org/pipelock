// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package setup

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/BurntSushi/toml"
	"github.com/luckyPipewrench/pipelock/internal/mcp"
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
	keys, err := codexEnvKeys(transport)
	if err != nil {
		return err
	}
	if err := validateCodexForwarding(keys); err != nil {
		return err
	}
	for key, value := range transport.Env {
		inherited, present := os.LookupEnv(key)
		if !present || inherited != value {
			return fmt.Errorf("environment variable %q must be exported with its configured value in the environment running setup and Codex; load it from a secret store or file into setup and the launcher environment (IDE, desktop launcher or systemd EnvironmentFile/profile), then retry; do not type the value on a command line", key)
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
	// Codex writes through a symlinked config.toml; replacing the link with a
	// regular file would detach it from the operator's managed copy.
	path, err = filepath.EvalSymlinks(path)
	if err != nil {
		return "", nil, fmt.Errorf("resolving Codex config: %w", err)
	}
	var document map[string]any
	if _, err := toml.Decode(string(data), &document); err != nil {
		// TOML errors can quote a line containing credentials.
		return "", nil, errors.New("cannot parse Codex config; repair config.toml before retrying (parser details withheld to protect environment values)")
	}
	return path, document, nil
}

// encodeCodexConfig re-encodes the whole document and refuses unless decoding
// the output yields the same data. Comments and layout are still normalized.
func encodeCodexConfig(document map[string]any) ([]byte, error) {
	var output bytes.Buffer
	if err := toml.NewEncoder(&output).Encode(preserveTOMLLocalTimes(document)); err != nil {
		return nil, errors.New("cannot encode Codex config for name-only environment forwarding")
	}
	var reparsed map[string]any
	if _, err := toml.Decode(output.String(), &reparsed); err != nil ||
		!reflect.DeepEqual(canonicalTOML(document), canonicalTOML(reparsed)) {
		return nil, errors.New("cannot rewrite Codex config without changing other settings; add env_vars to the server entry manually")
	}
	return output.Bytes(), nil
}

// The TOML library decodes local date/time values in the host's UTC offset and
// encodes them converted to UTC, shifting their wall-clock text. It also writes
// a numeric zero offset (+00:00) as Z, which reparses in a different location.
// tomlTimeText writes the decoded text back in its original form.
type tomlTimeText string

func (t tomlTimeText) MarshalTOML() ([]byte, error) { return []byte(t), nil }

var tomlLocalLayouts = map[string]string{
	"datetime-local": "2006-01-02T15:04:05.999999999",
	"date-local":     "2006-01-02",
	"time-local":     "15:04:05.999999999",
}

// tomlNumericOffsetLayout renders a zero offset as +00:00 rather than Z.
const tomlNumericOffsetLayout = "2006-01-02T15:04:05.999999999-07:00"

func preserveTOMLLocalTimes(value any) any {
	switch v := value.(type) {
	case map[string]any:
		out := make(map[string]any, len(v))
		for key, item := range v {
			out[key] = preserveTOMLLocalTimes(item)
		}
		return out
	case []map[string]any:
		out := make([]map[string]any, len(v))
		for i, item := range v {
			out[i], _ = preserveTOMLLocalTimes(item).(map[string]any)
		}
		return out
	case []any:
		out := make([]any, len(v))
		for i, item := range v {
			out[i] = preserveTOMLLocalTimes(item)
		}
		return out
	case time.Time:
		if layout, local := tomlLocalLayouts[v.Location().String()]; local {
			return tomlTimeText(v.Format(layout))
		}
		// The decoder returns time.UTC only for a Z suffix.
		if v.Location() != time.UTC {
			return tomlTimeText(v.Format(tomlNumericOffsetLayout))
		}
	}
	return value
}

// tomlScalar compares values whose Go form is not comparable as decoded:
// wall-clock text and zone for times, and formatted text for floats (NaN).
type tomlScalar struct{ kind, text string }

func canonicalTOML(value any) any {
	switch v := value.(type) {
	case map[string]any:
		out := make(map[string]any, len(v))
		for key, item := range v {
			out[key] = canonicalTOML(item)
		}
		return out
	case time.Time:
		layout, local := tomlLocalLayouts[v.Location().String()]
		if !local {
			layout = time.RFC3339Nano
		}
		return tomlScalar{kind: "time:" + v.Location().String(), text: v.Format(layout)}
	case float64:
		return tomlScalar{kind: "float", text: strconv.FormatFloat(v, 'g', -1, 64)}
	}
	// Decoding yields []any or []map[string]any; written values may be typed.
	if rv := reflect.ValueOf(value); rv.Kind() == reflect.Slice {
		out := make([]any, rv.Len())
		for i := range out {
			out[i] = canonicalTOML(rv.Index(i).Interface())
		}
		return out
	}
	return value
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
	output, err := encodeCodexConfig(document)
	if err != nil {
		return err
	}
	return vscodeAtomicWrite(path, output, filepath.Dir(path))
}

// preflightCodexEnv verifies all value-bearing prerequisites before mutation.
func preflightCodexEnv(transport codexMCPTransport) error {
	if err := validateCodexEnv(transport); err != nil {
		return err
	}
	if len(transport.Env)+len(transport.EnvVars) > 0 {
		_, document, err := readCodexConfig()
		if err != nil {
			return err
		}
		_, err = encodeCodexConfig(document)
		return err
	}
	return nil
}

// validateCodexForwarding joins the runtime's policy without copying its lists.
func validateCodexForwarding(keys map[string]string) error {
	for key := range keys {
		if mcp.IsDangerousEnvKey(key) {
			return fmt.Errorf("environment variable %q is blocked by the MCP wrapper because it can inject code or redirect child traffic; remove it from the server environment before installing", key)
		}
	}
	return nil
}
