// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package setup

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/luckyPipewrench/pipelock/internal/cli/presets"
	"github.com/luckyPipewrench/pipelock/internal/config"
)

func TestRunSidecar_DryRun(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	cmd := SidecarCmd()
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)
	cmd.SetArgs([]string{
		"--inject-spec", testdataPath(t, "deployment.yaml"),
		"--dry-run",
	})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	output := buf.String()

	// Verify all 7 phase markers appear.
	for i := 1; i <= 7; i++ {
		marker := "[" + itoa(i) + "/7]"
		if !strings.Contains(output, marker) {
			t.Errorf("output should contain phase marker %s", marker)
		}
	}

	// Verify dry-run message.
	if !strings.Contains(output, "Dry run") {
		t.Errorf("output should contain 'Dry run', got:\n%s", output)
	}

	// Verify diff preview section is present.
	if !strings.Contains(output, "Diff preview") {
		t.Errorf("output should contain 'Diff preview', got:\n%s", output)
	}
}

func TestRunSidecar_JSON(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	cmd := SidecarCmd()
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)
	cmd.SetArgs([]string{
		"--inject-spec", testdataPath(t, "deployment.yaml"),
		"--dry-run",
		"--json",
	})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var result sidecarResult
	if err := json.Unmarshal(buf.Bytes(), &result); err != nil {
		t.Fatalf("invalid JSON output: %v\n%s", err, buf.String())
	}

	if result.Detect == nil {
		t.Fatal("detect field should not be nil")
	}
	if result.Detect.Kind != kindDeployment {
		t.Errorf("detect.kind = %q, want %q", result.Detect.Kind, kindDeployment)
	}
	if result.Detect.Name != "my-agent" {
		t.Errorf("detect.name = %q, want %q", result.Detect.Name, "my-agent")
	}

	if result.Patch == nil {
		t.Fatal("patch field should not be nil")
	}
	if !result.Patch.DryRun {
		t.Error("patch.dry_run should be true")
	}
	if result.Patch.EmitFormat != emitPatch {
		t.Errorf("patch.emit_format = %q, want %q", result.Patch.EmitFormat, emitPatch)
	}
}

func TestRunSidecar_JSONMCPUpstream(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	cmd := SidecarCmd()
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)
	cmd.SetArgs([]string{
		"--inject-spec", testdataPath(t, "deployment.yaml"),
		"--dry-run",
		"--json",
		"--mcp-upstream", "http://openclaw:3000/mcp",
	})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var result sidecarResult
	if err := json.Unmarshal(buf.Bytes(), &result); err != nil {
		t.Fatalf("invalid JSON output: %v\n%s", err, buf.String())
	}
	if result.Patch == nil {
		t.Fatal("patch field should not be nil")
	}
	if result.Patch.MCPProxyURL != "http://my-agent-pipelock:8889" {
		t.Fatalf("patch.mcp_proxy_url = %q, want %q", result.Patch.MCPProxyURL, "http://my-agent-pipelock:8889")
	}
	if result.Patch.MCPConfigPath != sidecarMCPConfigPath() {
		t.Fatalf("patch.mcp_config_path = %q, want %q", result.Patch.MCPConfigPath, sidecarMCPConfigPath())
	}
	if result.Patch.MCPServerName != defaultMCPServerName {
		t.Fatalf("patch.mcp_server_name = %q, want %q", result.Patch.MCPServerName, defaultMCPServerName)
	}
}

func TestRunSidecar_MCPUpstreamSummaryReminder(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	cmd := SidecarCmd()
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)
	cmd.SetArgs([]string{
		"--inject-spec", testdataPath(t, "deployment.yaml"),
		"--dry-run",
		"--mcp-upstream", "http://openclaw:3000/mcp",
	})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	output := buf.String()
	if !strings.Contains(output, "MCP proxy URL:") {
		t.Fatalf("summary missing MCP proxy URL:\n%s", output)
	}
	if !strings.Contains(output, "MCP config:") {
		t.Fatalf("summary missing MCP config path:\n%s", output)
	}
	if !strings.Contains(output, "Configure the agent MCP launcher to read PIPELOCK_MCP_CONFIG") {
		t.Fatalf("summary missing agent MCP wiring reminder:\n%s", output)
	}
}

func TestRunSidecar_InvalidMCPUpstream(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name    string
		raw     string
		wantSub string
	}{
		{name: "bad scheme", raw: "ws://openclaw:3000/mcp", wantSub: "must use http:// or https://"},
		{name: "no host", raw: "http:///mcp", wantSub: "must include http:// or https:// and a host"},
		{name: "userinfo", raw: "http://user@openclaw:3000/mcp", wantSub: "must not contain user info or credentials"},
		{name: "port out of range high", raw: "http://openclaw:99999/mcp", wantSub: "must be 1-65535"},
		{name: "port zero", raw: "http://openclaw:0/mcp", wantSub: "must be 1-65535"},
		{name: "trailing colon", raw: "http://openclaw:/mcp", wantSub: "malformed host/port syntax"},
		{name: "extra port fragment", raw: "http://openclaw:65536:/mcp", wantSub: "malformed host/port syntax"},
		{name: "valid port bad path escape", raw: "http://host:8080/%ZZ", wantSub: "must include http:// or https:// and a host"},
		{name: "non-numeric port", raw: "http://host:80a/mcp", wantSub: "malformed host/port syntax"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			var buf bytes.Buffer
			cmd := SidecarCmd()
			cmd.SetOut(&buf)
			cmd.SetErr(&buf)
			cmd.SetArgs([]string{
				"--inject-spec", testdataPath(t, "deployment.yaml"),
				"--dry-run",
				"--mcp-upstream", tc.raw,
			})
			err := cmd.Execute()
			if err == nil {
				t.Fatalf("expected invalid --mcp-upstream error for %q", tc.raw)
			}
			if !strings.Contains(err.Error(), tc.wantSub) {
				t.Fatalf("err = %v, want substring %q", err, tc.wantSub)
			}
		})
	}
}

func TestRunSidecar_InvalidMCPServerName(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name    string
		raw     string
		wantSub string
	}{
		{name: "bad chars", raw: "bad/name", wantSub: "may contain only"},
		{name: "empty", raw: "   ", wantSub: "must not be empty"},
		{name: "too long", raw: strings.Repeat("a", maxMCPServerNameLen+1), wantSub: "exceeds maximum length"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			var buf bytes.Buffer
			cmd := SidecarCmd()
			cmd.SetOut(&buf)
			cmd.SetErr(&buf)
			cmd.SetArgs([]string{
				"--inject-spec", testdataPath(t, "deployment.yaml"),
				"--dry-run",
				"--mcp-upstream", "http://openclaw:3000/mcp",
				"--mcp-server-name", tc.raw,
			})
			err := cmd.Execute()
			if err == nil {
				t.Fatalf("expected invalid MCP server name error for %q", tc.raw)
			}
			if !strings.Contains(err.Error(), tc.wantSub) {
				t.Fatalf("err = %v, want substring %q", err, tc.wantSub)
			}
		})
	}
}

// TestSidecarMCPContractChanged_FallsBackToPodSpec verifies that annotation
// drift does not silently leave stale MCP env/volume in the workload on a
// disable run. If MCP annotations were stripped (e.g. by hand) but the env
// var or ConfigMap mount remains, the contract-change detector must still
// flag the workload for regeneration so the scrub fires.
func TestSidecarMCPContractChanged_FallsBackToPodSpec(t *testing.T) {
	t.Parallel()

	// Build a fake patched-but-annotation-stripped workload. Only the
	// PIPELOCK_MCP_PROXY_URL env entry remains.
	raw := map[string]interface{}{
		"kind":     kindDeployment,
		"metadata": map[string]interface{}{"name": "agent", "annotations": map[string]interface{}{}},
		"spec": map[string]interface{}{
			"template": map[string]interface{}{
				"spec": map[string]interface{}{
					"containers": []interface{}{
						map[string]interface{}{
							"name": "agent",
							"env": []interface{}{
								map[string]interface{}{"name": envMCPProxy, "value": "http://stale:8889"},
							},
						},
					},
				},
			},
		},
	}

	// Disable run: no --mcp-upstream. Annotations are empty so the
	// annotation-only detector would have returned false. The fallback
	// must catch the stale env and report a change.
	if !sidecarMCPContractChanged(raw, sidecarOptions{}) {
		t.Fatal("disable run with stale MCP env must trigger contract change")
	}

	// Same check via the volume path: empty env, but the MCP config
	// volume is still mounted from a prior run.
	raw["spec"].(map[string]interface{})["template"].(map[string]interface{})["spec"].(map[string]interface{})["containers"].([]interface{})[0].(map[string]interface{})["env"] = []interface{}{}
	raw["spec"].(map[string]interface{})["template"].(map[string]interface{})["spec"].(map[string]interface{})["volumes"] = []interface{}{
		map[string]interface{}{"name": sidecarMCPConfigVolume},
	}
	if !sidecarMCPContractChanged(raw, sidecarOptions{}) {
		t.Fatal("disable run with stale MCP volume must trigger contract change")
	}

	// Clean slate: no annotations, no env, no volume. Detector must NOT
	// flag drift, otherwise non-MCP workloads would always re-emit.
	raw["spec"].(map[string]interface{})["template"].(map[string]interface{})["spec"].(map[string]interface{})["volumes"] = nil
	if sidecarMCPContractChanged(raw, sidecarOptions{}) {
		t.Fatal("clean workload must not trigger contract change on disable run")
	}
}

func TestRunSidecar_AllKinds(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		file     string
		wantKind string
		wantName string
	}{
		{
			name:     "deployment",
			file:     "deployment.yaml",
			wantKind: kindDeployment,
			wantName: "my-agent",
		},
		{
			name:     "statefulset",
			file:     "statefulset.yaml",
			wantKind: kindStatefulSet,
			wantName: "my-db-agent",
		},
		{
			name:     "job",
			file:     "job.yaml",
			wantKind: kindJob,
			wantName: "batch-runner",
		},
		{
			name:     "cronjob",
			file:     "cronjob.yaml",
			wantKind: kindCronJob,
			wantName: "scheduled-scan",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var buf bytes.Buffer
			cmd := SidecarCmd()
			cmd.SetOut(&buf)
			cmd.SetErr(&buf)
			cmd.SetArgs([]string{
				"--inject-spec", testdataPath(t, tc.file),
				"--dry-run",
				"--json",
			})

			if err := cmd.Execute(); err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			var result sidecarResult
			if err := json.Unmarshal(buf.Bytes(), &result); err != nil {
				t.Fatalf("invalid JSON: %v\n%s", err, buf.String())
			}

			if result.Detect.Kind != tc.wantKind {
				t.Errorf("detect.kind = %q, want %q", result.Detect.Kind, tc.wantKind)
			}
			if result.Detect.Name != tc.wantName {
				t.Errorf("detect.name = %q, want %q", result.Detect.Name, tc.wantName)
			}
		})
	}
}

func TestRunSidecar_EmitPatch(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	outPath := filepath.Join(dir, "patched.yaml")

	var buf bytes.Buffer
	cmd := SidecarCmd()
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)
	cmd.SetArgs([]string{
		"--inject-spec", testdataPath(t, "deployment.yaml"),
		"--output", outPath,
		"--skip-canary",
		"--skip-verify",
	})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify file was written.
	data, err := os.ReadFile(filepath.Clean(outPath))
	if err != nil {
		t.Fatalf("reading output: %v", err)
	}
	if len(data) == 0 {
		t.Error("output file is empty")
	}

	// Verify it contains multi-document YAML.
	if !strings.Contains(string(data), "---") {
		t.Error("output should contain YAML document separator")
	}
}

func TestRunSidecar_Idempotent(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	outDir := filepath.Join(dir, "kustomize-out")

	var buf1 bytes.Buffer
	cmd1 := SidecarCmd()
	cmd1.SetOut(&buf1)
	cmd1.SetErr(&buf1)
	cmd1.SetArgs([]string{
		"--inject-spec", testdataPath(t, "deployment.yaml"),
		"--emit", "kustomize",
		"--output", outDir,
		"--skip-canary",
		"--skip-verify",
	})

	if err := cmd1.Execute(); err != nil {
		t.Fatalf("first run: %v", err)
	}

	agentWorkloadPath := filepath.Join(outDir, "agent-workload.yaml")

	var buf2 bytes.Buffer
	cmd2 := SidecarCmd()
	cmd2.SetOut(&buf2)
	cmd2.SetErr(&buf2)
	cmd2.SetArgs([]string{
		"--inject-spec", agentWorkloadPath,
		"--dry-run",
		"--json",
	})

	if err := cmd2.Execute(); err != nil {
		t.Fatalf("second run: %v", err)
	}

	var result sidecarResult
	if err := json.Unmarshal(buf2.Bytes(), &result); err != nil {
		t.Fatalf("invalid JSON: %v\n%s", err, buf2.String())
	}

	if !result.Detect.AlreadyPatched {
		t.Error("second run should detect already_patched=true")
	}
}

func TestRunSidecar_MCPDisableRerunEmitsScrubbedWorkload(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	outDir := filepath.Join(dir, "enabled")

	var buf1 bytes.Buffer
	cmd1 := SidecarCmd()
	cmd1.SetOut(&buf1)
	cmd1.SetErr(&buf1)
	cmd1.SetArgs([]string{
		"--inject-spec", testdataPath(t, "deployment.yaml"),
		"--emit", "kustomize",
		"--output", outDir,
		"--mcp-upstream", "http://openclaw:3000/mcp",
		"--skip-canary",
		"--skip-verify",
	})
	if err := cmd1.Execute(); err != nil {
		t.Fatalf("first run: %v\n%s", err, buf1.String())
	}

	disabledPath := filepath.Join(dir, "disabled.yaml")
	var buf2 bytes.Buffer
	cmd2 := SidecarCmd()
	cmd2.SetOut(&buf2)
	cmd2.SetErr(&buf2)
	cmd2.SetArgs([]string{
		"--inject-spec", filepath.Join(outDir, "agent-workload.yaml"),
		"--output", disabledPath,
		"--skip-canary",
		"--skip-verify",
	})
	if err := cmd2.Execute(); err != nil {
		t.Fatalf("disable run: %v\n%s", err, buf2.String())
	}

	data, err := os.ReadFile(filepath.Clean(disabledPath))
	if err != nil {
		t.Fatalf("reading disabled output: %v", err)
	}
	content := string(data)
	for _, stale := range []string{envMCPProxy, envMCPConfig, managedMCPProxyAnnotation, managedMCPUpstreamAnnotation, managedMCPUpstreamHash, managedMCPConfigAnnotation, managedMCPServerAnnotation, sidecarMCPConfigVolume} {
		if strings.Contains(content, stale) {
			t.Fatalf("disabled output still contains %q:\n%s", stale, content)
		}
	}
}

func TestRunSidecar_CanaryDetection(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	cmd := SidecarCmd()
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)
	cmd.SetArgs([]string{
		"--inject-spec", testdataPath(t, "deployment.yaml"),
		"--output", filepath.Join(t.TempDir(), "out.yaml"),
		"--skip-verify",
		"--json",
	})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var result sidecarResult
	if err := json.Unmarshal(buf.Bytes(), &result); err != nil {
		t.Fatalf("invalid JSON: %v\n%s", err, buf.String())
	}

	if result.Canary == nil {
		t.Fatal("canary field should not be nil")
	}
	if !result.Canary.Detected {
		t.Error("canary.detected should be true (DLP should catch the synthetic secret)")
	}
}

func TestRunSidecar_AllPresetsDryRun(t *testing.T) {
	for _, name := range presets.All {
		t.Run(name, func(t *testing.T) {
			var buf bytes.Buffer
			cmd := SidecarCmd()
			cmd.SetOut(&buf)
			cmd.SetErr(&buf)
			cmd.SetArgs([]string{
				"--inject-spec", testdataPath(t, "deployment.yaml"),
				"--preset", name,
				"--dry-run",
			})

			if err := cmd.Execute(); err != nil {
				t.Fatalf("Execute: %v\n%s", err, buf.String())
			}
		})
	}
}

func TestGenerateSidecarPatch_AllPresetsProduceValidConfig(t *testing.T) {
	manifest, err := detectWorkload(testdataPath(t, "deployment.yaml"))
	if err != nil {
		t.Fatalf("detectWorkload: %v", err)
	}

	for _, name := range presets.All {
		t.Run(name, func(t *testing.T) {
			result, err := generateSidecarPatch(manifest, sidecarOptions{preset: name})
			if err != nil {
				t.Fatalf("generateSidecarPatch: %v", err)
			}
			if err := result.Config.Validate(); err != nil {
				t.Fatalf("sidecar config Validate: %v", err)
			}
			switch result.Config.Mode {
			case config.ModeStrict, config.ModeBalanced, config.ModeAudit:
			default:
				t.Fatalf("mode = %q, want valid mode", result.Config.Mode)
			}
		})
	}
}

func TestGenerateSidecarPatch_InvalidPreset(t *testing.T) {
	manifest, err := detectWorkload(testdataPath(t, "deployment.yaml"))
	if err != nil {
		t.Fatalf("detectWorkload: %v", err)
	}

	if _, err := generateSidecarPatch(manifest, sidecarOptions{preset: "bogus"}); err == nil {
		t.Fatal("expected error for invalid preset")
	}
}

func TestRunSidecar_InvalidPreset(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	cmd := SidecarCmd()
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)
	cmd.SetArgs([]string{
		"--inject-spec", testdataPath(t, "deployment.yaml"),
		"--preset", "bogus",
		"--dry-run",
	})

	err := cmd.Execute()
	if err == nil {
		t.Fatal("expected error for invalid preset")
	}
	for _, name := range presets.All {
		if !strings.Contains(err.Error(), name) {
			t.Errorf("error %q does not list %q", err, name)
		}
	}
}

func TestRunSidecar_InvalidEmitFormat(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	cmd := SidecarCmd()
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)
	cmd.SetArgs([]string{
		"--inject-spec", testdataPath(t, "deployment.yaml"),
		"--emit", "bad-format",
		"--dry-run",
	})

	err := cmd.Execute()
	if err == nil {
		t.Fatal("expected error for invalid emit format")
	}
}

func TestRunSidecar_MissingInjectSpec(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	cmd := SidecarCmd()
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)
	cmd.SetArgs([]string{"--dry-run"})

	err := cmd.Execute()
	if err == nil {
		t.Fatal("expected error for missing --inject-spec")
	}
}

func TestRunSidecar_EmitKustomize(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	outDir := filepath.Join(dir, "kustomize-out")

	var buf bytes.Buffer
	cmd := SidecarCmd()
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)
	cmd.SetArgs([]string{
		"--inject-spec", testdataPath(t, "deployment.yaml"),
		"--emit", "kustomize",
		"--output", outDir,
		"--skip-canary",
		"--skip-verify",
	})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify kustomize files exist.
	for _, name := range []string{
		"kustomization.yaml",
		"agent-workload.yaml",
		"pipelock-configmap.yaml",
		"pipelock-deployment.yaml",
		"pipelock-service.yaml",
		"agent-networkpolicy.yaml",
		"pipelock-networkpolicy.yaml",
		"pipelock-pdb.yaml",
	} {
		path := filepath.Join(outDir, name)
		if _, err := os.Stat(path); os.IsNotExist(err) {
			t.Errorf("expected file %s not created", name)
		}
	}
}

func TestRunSidecar_JSONRequiresOutputWhenEmitting(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	cmd := SidecarCmd()
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)
	cmd.SetArgs([]string{
		"--inject-spec", testdataPath(t, "deployment.yaml"),
		"--json",
		"--skip-canary",
		"--skip-verify",
	})

	err := cmd.Execute()
	if err == nil {
		t.Fatal("expected error when --json emits to stdout without --output")
	}
	if !strings.Contains(err.Error(), "--json requires --output") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestRunSidecar_EmitHelmValues(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	outDir := filepath.Join(dir, "helm-bundle")

	var buf bytes.Buffer
	cmd := SidecarCmd()
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)
	cmd.SetArgs([]string{
		"--inject-spec", testdataPath(t, "deployment.yaml"),
		"--emit", "helm-values",
		"--output", outDir,
		"--skip-canary",
		"--skip-verify",
	})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	data, err := os.ReadFile(filepath.Clean(filepath.Join(outDir, "values.yaml")))
	if err != nil {
		t.Fatalf("reading output: %v", err)
	}

	if !strings.Contains(string(data), "Helm bundle values") {
		t.Error("output should contain Helm header comment")
	}
	if _, err := os.Stat(filepath.Join(outDir, "README.txt")); err != nil {
		t.Fatalf("expected README.txt in helm bundle: %v", err)
	}
	if _, err := os.Stat(filepath.Join(outDir, "pipelock-pdb.yaml")); err != nil {
		t.Fatalf("expected pipelock-pdb.yaml in helm bundle: %v", err)
	}
}

func TestRunSidecar_VerifyHealthy(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	outPath := filepath.Join(dir, "patched.yaml")

	var buf bytes.Buffer
	cmd := SidecarCmd()
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)
	cmd.SetArgs([]string{
		"--inject-spec", testdataPath(t, "deployment.yaml"),
		"--output", outPath,
		"--skip-canary",
		"--json",
	})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var result sidecarResult
	if err := json.Unmarshal(buf.Bytes(), &result); err != nil {
		t.Fatalf("invalid JSON: %v\n%s", err, buf.String())
	}
	if result.Verify == nil {
		t.Fatal("verify field should not be nil")
	}
	if result.Verify.Skipped {
		t.Fatal("verify should not be skipped")
	}
	if !result.Verify.Healthy {
		t.Fatalf("verify should be healthy, got: %+v", result.Verify)
	}
}

func TestRunSidecar_SkipCanary(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	cmd := SidecarCmd()
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)
	cmd.SetArgs([]string{
		"--inject-spec", testdataPath(t, "deployment.yaml"),
		"--dry-run",
		"--skip-canary",
		"--json",
	})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var result sidecarResult
	if err := json.Unmarshal(buf.Bytes(), &result); err != nil {
		t.Fatalf("invalid JSON: %v\n%s", err, buf.String())
	}

	if result.Canary == nil {
		t.Fatal("canary field should not be nil")
	}
	if !result.Canary.Skipped {
		t.Error("canary.skipped should be true with --skip-canary")
	}
}

func TestRunSidecar_CustomAgentIdentity(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	cmd := SidecarCmd()
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)
	cmd.SetArgs([]string{
		"--inject-spec", testdataPath(t, "deployment.yaml"),
		"--dry-run",
		"--json",
		"--agent-identity", "team/custom-bot",
	})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var result sidecarResult
	if err := json.Unmarshal(buf.Bytes(), &result); err != nil {
		t.Fatalf("invalid JSON: %v\n%s", err, buf.String())
	}

	if result.Patch.AgentIdentity != "team/custom-bot" {
		t.Errorf("agent_identity = %q, want %q", result.Patch.AgentIdentity, "team/custom-bot")
	}
}

// itoa is a minimal int-to-string without importing strconv (keeps imports lean).
func itoa(n int) string {
	if n < 0 {
		return "-" + itoa(-n)
	}
	if n < 10 {
		return string(rune('0' + n))
	}
	return itoa(n/10) + string(rune('0'+n%10))
}

func TestRawURLAuthority(t *testing.T) {
	t.Parallel()

	cases := map[string]string{
		"http://openclaw:65536:/mcp": "openclaw:65536:",
		"https://host:8080?x=1":      "host:8080",
		"http://host#frag":           "host",
		"http://[::1]:443/":          "[::1]:443",
		"no-scheme-here":             "",
	}
	for raw, want := range cases {
		if got := rawURLAuthority(raw); got != want {
			t.Errorf("rawURLAuthority(%q) = %q, want %q", raw, got, want)
		}
	}
}

func TestMCPUpstreamHostHasMalformedPort(t *testing.T) {
	t.Parallel()

	cases := map[string]bool{
		"host":         false,
		"host:8080":    false,
		"host:":        true,
		"host:80a":     true,
		"a:b:c":        true,
		"[::1]":        false,
		"[::1]:443":    false,
		"[::1]x":       true,
		"[::1]:44a":    true,
		"[::1]:":       true,
		"[::1":         true,
		"[::1]:443:80": true,
	}
	for host, want := range cases {
		if got := mcpUpstreamHostHasMalformedPort(host); got != want {
			t.Errorf("mcpUpstreamHostHasMalformedPort(%q) = %v, want %v", host, got, want)
		}
	}
}

func TestRunSidecar_EmittedProxyState(t *testing.T) {
	t.Parallel()
	for _, format := range []string{"patch", "kustomize", "helm-values"} {
		t.Run(format, func(t *testing.T) {
			output := filepath.Join(t.TempDir(), "bundle")
			var buf bytes.Buffer
			cmd := SidecarCmd()
			cmd.SetOut(&buf)
			cmd.SetErr(&buf)
			cmd.SetArgs([]string{"--inject-spec", testdataPath(t, "deployment.yaml"), "--emit", format, "--output", output, "--skip-canary"})
			if err := cmd.Execute(); err != nil {
				t.Fatalf("emit: %v: %s", err, buf.String())
			}
			var data []byte
			var err error
			switch format {
			case "patch":
				data, err = os.ReadFile(filepath.Clean(output))
			case "kustomize":
				data, err = os.ReadFile(filepath.Clean(filepath.Join(output, "pipelock-deployment.yaml")))
			case "helm-values":
				_, lookupErr := exec.LookPath("helm")
				if lookupErr != nil {
					t.Skip("Helm unavailable; chart policy checks cover rendering")
				}
				// #nosec G204 -- fixed chart and generated values in a private t.TempDir.
				data, err = exec.CommandContext(t.Context(), "helm", "template", "pipelock", "../../../charts/pipelock", "-f", filepath.Join(output, "values.yaml")).CombinedOutput()
				if err != nil {
					t.Fatalf("helm render: %v: %s", err, data)
				}
				// The chart supplies its default state home through a ConfigMap
				// so later operator envFrom sources retain their precedence.
				rendered := filepath.Join(output, "rendered.yaml")
				if err := os.WriteFile(rendered, data, 0o600); err != nil {
					t.Fatal(err)
				}
				// #nosec G204 -- fixed validation chart and private generated input.
				checked, err := exec.CommandContext(t.Context(), "helm", "template", "state-check", "../../../scripts/helmstate", "--set-file", "manifests.emitted="+rendered).CombinedOutput()
				if err != nil || !bytes.Contains(checked, []byte("decoded Helm proxy state checks passed")) {
					t.Fatalf("decoded Helm state checks: %v: %s", err, checked)
				}
				return
			}
			if err != nil {
				t.Fatalf("read/render: %v: %s", err, data)
			}
			decoder := yaml.NewDecoder(bytes.NewReader(data))
			proxies := 0
			for {
				var doc map[string]interface{}
				if err := decoder.Decode(&doc); errors.Is(err, io.EOF) {
					break
				} else if err != nil {
					t.Fatal(err)
				}
				if doc["kind"] != kindDeployment {
					continue
				}
				pod, err := getPodSpec(doc, kindDeployment)
				if err != nil {
					t.Fatal(err)
				}
				containers := pod["containers"].([]interface{})
				c := containers[0].(map[string]interface{})
				if c["name"] == proxyContainerName {
					encoded, err := yaml.Marshal(doc)
					if err != nil {
						t.Fatal(err)
					}
					if !deploymentHasProxyState(string(encoded)) {
						t.Fatalf("emitted proxy lacks writable state: %s", encoded)
					}
					proxies++
				} else {
					for _, entry := range containers {
						agent := entry.(map[string]interface{})
						env, _ := agent["env"].([]interface{})
						for _, variable := range env {
							if variable.(map[string]interface{})["name"] == envXDGStateHome {
								t.Fatal("state home leaked into agent")
							}
						}
					}
				}
			}
			if proxies != 1 {
				t.Fatalf("got %d proxy Deployments, want 1", proxies)
			}
		})
	}
}

func TestRunSidecar_RegeneratePatchedOutput(t *testing.T) {
	t.Parallel()
	for _, format := range []string{emitPatch, emitKustomize, emitHelmValues} {
		t.Run(format, func(t *testing.T) {
			dir := t.TempDir()
			output := filepath.Join(dir, "output")
			run := func(input string, flags ...string) (sidecarResult, string, error) {
				t.Helper()
				var buf bytes.Buffer
				cmd := SidecarCmd()
				cmd.SetOut(&buf)
				cmd.SetErr(&buf)
				args := []string{"--inject-spec", input, "--emit", format, "--output", output, "--skip-canary", "--json"}
				cmd.SetArgs(append(args, flags...))
				err := cmd.Execute()
				var result sidecarResult
				if err == nil {
					if decodeErr := json.Unmarshal(buf.Bytes(), &result); decodeErr != nil {
						t.Fatalf("decode result: %v: %s", decodeErr, buf.String())
					}
				}
				return result, buf.String(), err
			}
			original := testdataPath(t, "deployment.yaml")
			first, detail, err := run(original)
			if err != nil || !first.Patch.Written || first.Verify.Healthy != (format != emitHelmValues) || first.Verify.Skipped != (format == emitHelmValues) {
				t.Fatalf("first run: %v: %s", err, detail)
			}
			companion := output
			agent := output
			if format != emitPatch {
				agent = filepath.Join(output, "agent-workload.yaml")
				companion = filepath.Join(output, "pipelock-deployment.yaml")
				if format == emitHelmValues {
					companion = filepath.Join(output, "values.yaml")
				}
			}
			generated, err := os.ReadFile(filepath.Clean(companion))
			if err != nil {
				t.Fatal(err)
			}
			// Keep patched input separate even for the single-file bundle.
			patched, err := os.ReadFile(filepath.Clean(agent))
			if err != nil {
				t.Fatal(err)
			}
			input := filepath.Join(dir, "patched-input.yaml")
			if err := os.WriteFile(input, patched, 0o600); err != nil {
				t.Fatal(err)
			}
			manual := []byte("# operator-edited companion; do not overwrite without --force\n")
			if err := os.WriteFile(filepath.Clean(companion), manual, 0o600); err != nil {
				t.Fatal(err)
			}
			assertPreserved := func() {
				t.Helper()
				got, err := os.ReadFile(filepath.Clean(companion))
				if err != nil || !bytes.Equal(got, manual) {
					t.Fatalf("manual output changed without forced emission: %v: %s", err, got)
				}
			}
			if _, _, err := run(original); err == nil {
				t.Fatal("existing output from original input must require --force")
			}
			assertPreserved()
			skipped, detail, err := run(input)
			if err != nil || skipped.Patch.Written || !skipped.Verify.Skipped || skipped.Verify.Healthy || !strings.Contains(skipped.Verify.Detail, "existing files were not verified") {
				t.Fatalf("unforced patched run must not claim verification: %v: %s", err, detail)
			}
			assertPreserved()
			dry, detail, err := run(input, "--force", "--dry-run")
			if err != nil || dry.Patch.Written || !dry.Verify.Skipped || dry.Verify.Healthy {
				t.Fatalf("dry run: %v: %s", err, detail)
			}
			assertPreserved()
			for range 2 {
				forced, detail, err := run(input, "--force")
				if err != nil || !forced.Patch.Written || forced.Verify.Healthy != (format != emitHelmValues) || forced.Verify.Skipped != (format == emitHelmValues) || !forced.Detect.AlreadyPatched {
					t.Fatalf("forced patched run: %v: %s", err, detail)
				}
				got, err := os.ReadFile(filepath.Clean(companion))
				if err != nil || !bytes.Equal(got, generated) {
					t.Fatalf("forced output differs from first run: %v: %s", err, got)
				}
			}
			// A patched input alone is no evidence that the requested output exists.
			output = filepath.Join(dir, "never-emitted")
			missing, detail, err := run(input)
			if err != nil || missing.Patch.Written || !missing.Verify.Skipped || missing.Verify.Healthy {
				t.Fatalf("unwritten output must not be verified: %v: %s", err, detail)
			}
			if _, err := os.Stat(output); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("skipped run created output: %v", err)
			}
		})
	}
}

func TestRunSidecar_VerificationOutputFormats(t *testing.T) {
	t.Parallel()
	for _, format := range []string{emitPatch, emitKustomize, emitHelmValues} {
		for _, jsonOutput := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/json=%t", format, jsonOutput), func(t *testing.T) {
				t.Parallel()
				output := filepath.Join(t.TempDir(), "bundle")
				var buf bytes.Buffer
				cmd := SidecarCmd()
				cmd.SetOut(&buf)
				cmd.SetErr(&buf)
				args := []string{"--inject-spec", testdataPath(t, "deployment.yaml"), "--emit", format, "--output", output}
				if jsonOutput {
					args = append(args, "--json")
				}
				cmd.SetArgs(args)
				if err := cmd.Execute(); err != nil {
					t.Fatalf("execute: %v: %s", err, &buf)
				}
				helm := format == emitHelmValues
				if jsonOutput {
					var result sidecarResult
					if err := json.Unmarshal(buf.Bytes(), &result); err != nil {
						t.Fatal(err)
					}
					if result.Verify == nil || result.Verify.Skipped != helm || result.Verify.Healthy == helm || result.Verify.Reachable == helm {
						t.Fatalf("verify: %+v", result.Verify)
					}
					if result.Canary == nil || result.Canary.Skipped || !result.Canary.Detected {
						t.Fatalf("canary must still run: %+v", result.Canary)
					}
				} else {
					want := "Verify:          healthy"
					if helm {
						want = "Verify:          skipped"
						if !strings.Contains(buf.String(), "not rendered or deployed") || strings.Contains(buf.String(), "Static topology checks passed") {
							t.Fatalf("chart boundary missing: %s", &buf)
						}
					}
					if !strings.Contains(buf.String(), want) || !strings.Contains(buf.String(), "Canary:          detected") {
						t.Fatalf("summary: %s", &buf)
					}
				}
				if helm {
					readme, err := os.ReadFile(filepath.Clean(filepath.Join(output, "README.txt")))
					if err != nil {
						t.Fatal(err)
					}
					for _, want := range []string{"not rendered or deployed", "helm show chart", "helm template", "--version \"$chart_version\"", "Inspect rendered.yaml"} {
						if !bytes.Contains(readme, []byte(want)) {
							t.Fatalf("README missing %q: %s", want, readme)
						}
					}
					// The chart is published only as an OCI artifact: every Helm command
					// must name that reference, and a repo search cannot list it.
					const ociChart = "oci://ghcr.io/luckypipewrench/charts/pipelock"
					if got := bytes.Count(readme, []byte(ociChart)); got != 3 || bytes.Contains(readme, []byte("helm search repo")) || bytes.Contains(readme, []byte(" pipelock/pipelock ")) {
						t.Fatalf("README must use the OCI chart reference in show, template and install (found %d): %s", got, readme)
					}
				}
			})
		}
	}
}
