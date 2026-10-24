// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package setup

import (
	"fmt"
	"io"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
)

// sidecarVerifyResult holds the outcome of the sidecar verify phase.
type sidecarVerifyResult struct {
	Reachable bool   `json:"reachable"`
	Healthy   bool   `json:"healthy"`
	Skipped   bool   `json:"skipped"`
	Detail    string `json:"detail,omitempty"`
}

// runSidecarVerify performs static verification of the generated enforced topology.
func runSidecarVerify(w io.Writer, result *sidecarPatchResult, opts sidecarOptions, jsonOutput bool) *sidecarVerifyResult {
	if opts.skipVerify {
		return &sidecarVerifyResult{Skipped: true, Detail: "skipped (--skip-verify)"}
	}

	if result == nil || result.Config == nil {
		return &sidecarVerifyResult{Healthy: false, Detail: "generated topology is missing proxy config"}
	}

	var failed []string
	if result.ProxyName == "" || result.ProxyURL == "" {
		failed = append(failed, "proxy identity metadata is incomplete")
	}
	// Helm values do not emit a Deployment or Service; the selected chart owns them.
	if opts.emit != emitHelmValues {
		if result.DeploymentYAML == "" {
			failed = append(failed, "proxy Deployment YAML is empty")
		}
		if !deploymentHasProxyState(result.DeploymentYAML) {
			failed = append(failed, "proxy Deployment is missing writable proxy-only state")
		}
		if result.ServiceYAML == "" {
			failed = append(failed, "proxy Service YAML is empty")
		}
		if !strings.Contains(result.DeploymentYAML, fmt.Sprintf("replicas: %d", proxyReplicaCount)) {
			failed = append(failed, fmt.Sprintf("proxy Deployment does not set replicas=%d", proxyReplicaCount))
		}
		if got, ok := deploymentTerminationGrace(result.DeploymentYAML); !ok || got != proxyTerminationGracePeriodSeconds {
			failed = append(failed, fmt.Sprintf("proxy Deployment does not set terminationGracePeriodSeconds=%d", proxyTerminationGracePeriodSeconds))
		}
		if strings.Contains(result.DeploymentYAML, "subPath:") {
			failed = append(failed, "proxy Deployment still uses subPath ConfigMap mount")
		}
		if !strings.Contains(result.DeploymentYAML, "mountPath: /etc/pipelock") {
			failed = append(failed, "proxy Deployment does not mount the config directory")
		}
		if !strings.Contains(result.DeploymentYAML, "imagePullPolicy: IfNotPresent") {
			failed = append(failed, "proxy Deployment does not set imagePullPolicy=IfNotPresent")
		}
	}
	if result.PodDisruptionBudgetYAML == "" {
		failed = append(failed, "proxy PodDisruptionBudget YAML is empty")
	}
	if !result.Config.ForwardProxy.Enabled {
		failed = append(failed, "forward_proxy.enabled is false")
	}
	if got := result.Config.FetchProxy.Listen; got != fmt.Sprintf("0.0.0.0:%d", sidecarHealthPort) {
		failed = append(failed, fmt.Sprintf("fetch_proxy.listen = %q", got))
	}
	if got := result.Config.MetricsListen; got != fmt.Sprintf("0.0.0.0:%d", sidecarMetricsPort) {
		failed = append(failed, fmt.Sprintf("metrics_listen = %q", got))
	}
	if !strings.Contains(result.AgentNetworkPolicyYAML, "matchLabels") || !strings.Contains(result.AgentNetworkPolicyYAML, "podSelector") {
		failed = append(failed, "agent NetworkPolicy missing selectors")
	}
	if networkPolicyHasPort(result.AgentNetworkPolicyYAML, 80) || networkPolicyHasPort(result.AgentNetworkPolicyYAML, 443) {
		failed = append(failed, "agent NetworkPolicy still allows direct web egress")
	}
	if !networkPolicyHasPort(result.AgentNetworkPolicyYAML, sidecarHealthPort) {
		failed = append(failed, "agent NetworkPolicy does not allow proxy port")
	}
	if result.MCPUpstream != "" && !networkPolicyHasPort(result.AgentNetworkPolicyYAML, sidecarMCPPort) {
		failed = append(failed, "agent NetworkPolicy does not allow MCP proxy port")
	}
	if result.MCPUpstream != "" {
		verifyMCPLauncherContract(result, &failed)
	}
	if !networkPolicyHasPort(result.ProxyNetworkPolicyYAML, sidecarHealthPort) {
		failed = append(failed, "proxy NetworkPolicy does not allow agent ingress on proxy port")
	}
	if result.MCPUpstream != "" {
		if !networkPolicyHasPort(result.ProxyNetworkPolicyYAML, sidecarMCPPort) {
			failed = append(failed, "proxy NetworkPolicy does not allow agent ingress on MCP proxy port")
		}
		if upstreamPort := mcpUpstreamPolicyPort(result.MCPUpstream); upstreamPort != 0 &&
			!networkPolicyHasPort(result.ProxyNetworkPolicyYAML, upstreamPort) {
			failed = append(failed, fmt.Sprintf("proxy NetworkPolicy does not allow MCP upstream port %d", upstreamPort))
		}
	}
	if !networkPolicyHasPort(result.ProxyNetworkPolicyYAML, 80) || !networkPolicyHasPort(result.ProxyNetworkPolicyYAML, 443) {
		failed = append(failed, "proxy NetworkPolicy does not allow web egress")
	}

	if len(failed) == 0 {
		if opts.emit == emitHelmValues {
			detail := "skipped (Helm chart topology was not rendered or deployed); generated config and emitted policy checks passed; render and inspect the selected chart version before applying"
			if !jsonOutput {
				_, _ = fmt.Fprintln(w, "  "+detail)
			}
			return &sidecarVerifyResult{Skipped: true, Detail: detail}
		}
		if !jsonOutput {
			_, _ = fmt.Fprintln(w, "  Static topology checks passed.")
			_, _ = fmt.Fprintf(w, "  Agent egress is limited to DNS + %s.\n", result.ProxyName)
			_, _ = fmt.Fprintln(w, "  Proxy config is cluster-reachable with forward proxy enabled.")
		}
		return &sidecarVerifyResult{
			Reachable: true,
			Healthy:   true,
			Detail:    "static topology verification passed",
		}
	}

	detail := "static topology verification failed: " + strings.Join(failed, "; ")
	if !jsonOutput {
		_, _ = fmt.Fprintln(w, "  Static topology verification failed.")
		_, _ = fmt.Fprintf(w, "  %s\n", detail)
	}
	return &sidecarVerifyResult{
		Healthy: false,
		Detail:  detail,
	}
}

func networkPolicyHasPort(policyYAML string, port int) bool {
	pattern := fmt.Sprintf(`(?m)^\s*-?\s*port:\s*%d\s*(?:#.*)?$`, port)
	return regexp.MustCompile(pattern).MatchString(policyYAML)
}

func verifyMCPLauncherContract(result *sidecarPatchResult, failed *[]string) {
	if result.MCPProxyURL == "" {
		*failed = append(*failed, "MCP proxy URL is empty")
	}
	if result.MCPConfigPath != sidecarMCPConfigPath() {
		*failed = append(*failed, fmt.Sprintf("MCP config path = %q", result.MCPConfigPath))
	}
	if result.MCPServerName == "" {
		*failed = append(*failed, "MCP server name is empty")
	}
	if result.MCPConfigMapYAML == "" {
		*failed = append(*failed, "MCP client ConfigMap YAML is empty")
	} else if !strings.Contains(result.MCPConfigMapYAML, result.MCPProxyURL) {
		*failed = append(*failed, "MCP client ConfigMap does not point at the MCP proxy URL")
	}

	kind, _ := result.PatchedManifest["kind"].(string)
	podSpec, err := getPodSpec(result.PatchedManifest, kind)
	if err != nil {
		*failed = append(*failed, "patched workload pod spec is unavailable")
		return
	}
	if !podSpecHasEnv(podSpec, envMCPProxy, result.MCPProxyURL) {
		*failed = append(*failed, fmt.Sprintf("agent workload does not set %s", envMCPProxy))
	}
	if !podSpecHasEnv(podSpec, envMCPConfig, result.MCPConfigPath) {
		*failed = append(*failed, fmt.Sprintf("agent workload does not set %s", envMCPConfig))
	}
	if !podSpecHasConfigMapVolume(podSpec, mcpClientConfigMapName(result.ProxyName)) {
		*failed = append(*failed, "agent workload does not mount the MCP client ConfigMap volume")
	}
	if !podSpecHasVolumeMount(podSpec) {
		*failed = append(*failed, "agent container does not mount the MCP client config directory")
	}
}

func podSpecHasEnv(podSpec map[string]interface{}, name, value string) bool {
	containers, ok := podSpec["containers"].([]interface{})
	if !ok {
		return false
	}
	for _, item := range containers {
		container, ok := item.(map[string]interface{})
		if !ok {
			continue
		}
		if containerName, _ := container["name"].(string); containerName == proxyContainerName {
			continue
		}
		envList, _ := container["env"].([]interface{})
		for _, envItem := range envList {
			envMap, ok := envItem.(map[string]interface{})
			if !ok {
				continue
			}
			if envName, _ := envMap["name"].(string); envName != name {
				continue
			}
			envValue, _ := envMap["value"].(string)
			if envValue == value {
				return true
			}
		}
	}
	return false
}

func podSpecHasConfigMapVolume(podSpec map[string]interface{}, configMapName string) bool {
	volumes, ok := podSpec["volumes"].([]interface{})
	if !ok {
		return false
	}
	for _, item := range volumes {
		volume, ok := item.(map[string]interface{})
		if !ok {
			continue
		}
		if name, _ := volume["name"].(string); name != sidecarMCPConfigVolume {
			continue
		}
		configMap, _ := volume["configMap"].(map[string]interface{})
		gotName, _ := configMap["name"].(string)
		return gotName == configMapName
	}
	return false
}

func podSpecHasVolumeMount(podSpec map[string]interface{}) bool {
	containers, ok := podSpec["containers"].([]interface{})
	if !ok {
		return false
	}
	for _, item := range containers {
		container, ok := item.(map[string]interface{})
		if !ok {
			continue
		}
		if containerName, _ := container["name"].(string); containerName == proxyContainerName {
			continue
		}
		mounts, _ := container["volumeMounts"].([]interface{})
		for _, mountItem := range mounts {
			mount, ok := mountItem.(map[string]interface{})
			if !ok {
				continue
			}
			name, _ := mount["name"].(string)
			path, _ := mount["mountPath"].(string)
			if name == sidecarMCPConfigVolume && path == sidecarMCPConfigMount {
				return true
			}
		}
	}
	return false
}

// deploymentTerminationGrace reads spec.template.spec.terminationGracePeriodSeconds
// from a Deployment manifest. It parses the field rather than matching text, so a
// different value that contains the expected digits, or the expected line inside
// a comment, does not pass.
func deploymentTerminationGrace(manifest string) (int64, bool) {
	var doc struct {
		Spec struct {
			Template struct {
				Spec struct {
					TerminationGracePeriodSeconds *int64 `yaml:"terminationGracePeriodSeconds"`
				} `yaml:"spec"`
			} `yaml:"template"`
		} `yaml:"spec"`
	}
	if err := yaml.Unmarshal([]byte(manifest), &doc); err != nil {
		return 0, false
	}
	grace := doc.Spec.Template.Spec.TerminationGracePeriodSeconds
	if grace == nil {
		return 0, false
	}
	return *grace, true
}

// deploymentHasProxyState checks the linked state environment, mount and volume
// on the companion proxy, with the group that makes emptyDir writable non-root.
func deploymentHasProxyState(manifest string) bool {
	var doc map[string]interface{}
	if err := yaml.Unmarshal([]byte(manifest), &doc); err != nil {
		return false
	}
	pod, err := getPodSpec(doc, kindDeployment)
	if err != nil {
		return false
	}
	security, _ := pod["securityContext"].(map[string]interface{})
	if security["fsGroup"] != proxyRunAsUser {
		return false
	}
	volumes, _ := pod["volumes"].([]interface{})
	stateVolumes := 0
	for _, entry := range volumes {
		volume, _ := entry.(map[string]interface{})
		if volume["name"] == proxyStateVolume {
			empty, ok := volume["emptyDir"].(map[string]interface{})
			if !ok || len(empty) != 0 || len(volume) != 2 {
				return false
			}
			stateVolumes++
		}
	}
	containers, _ := pod["containers"].([]interface{})
	if stateVolumes != 1 || len(containers) != 1 {
		return false
	}
	container, _ := containers[0].(map[string]interface{})
	if container["name"] != proxyContainerName {
		return false
	}
	env, _ := container["env"].([]interface{})
	stateEnvs := 0
	for _, entry := range env {
		variable, _ := entry.(map[string]interface{})
		if variable["name"] == envXDGStateHome {
			if variable["value"] != proxyStateHome || variable["valueFrom"] != nil {
				return false
			}
			stateEnvs++
		}
	}
	mounts, _ := container["volumeMounts"].([]interface{})
	stateMounts := 0
	for _, entry := range mounts {
		mount, _ := entry.(map[string]interface{})
		if mount["name"] == proxyStateVolume || mount["mountPath"] == proxyStateHome {
			if mount["name"] != proxyStateVolume || mount["mountPath"] != proxyStateHome ||
				mount["readOnly"] == true || mount["subPath"] != nil || mount["subPathExpr"] != nil {
				return false
			}
			stateMounts++
		}
	}
	return stateEnvs == 1 && stateMounts == 1
}
