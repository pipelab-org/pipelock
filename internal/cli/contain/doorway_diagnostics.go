// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package contain

import (
	"fmt"
	"path/filepath"
	"strings"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

const (
	doorwayInspectionRemedy  = "restore access to the managed containment state and rerun the diagnostic"
	loopbackDefinitionRemedy = "rerun `pipelock contain reload-nft-rules`"
)

type managedDoorway struct {
	socket    string
	relay     string
	forwarder string
	path      string
}

// combineDoorwayResults follows runDoctor's result contract: retain every
// finding, with fail taking precedence over unknown and unknown over pass.
// The caller supplies the established sorted doorway order.
func combineDoorwayResults(results []doctorResult) doctorResult {
	combined := pass("all managed doorway sockets and namespace forwarders are enabled and active")
	var findings []doctorResult
	for _, result := range results {
		if result.status == statusPass {
			continue
		}
		findings = append(findings, result)
		if result.status == statusFail || combined.status == statusPass {
			combined.status = result.status
		}
	}
	if len(findings) == 0 {
		return combined
	}
	if len(findings) == 1 {
		return findings[0]
	}
	var details, remedies []string
	for _, result := range findings {
		details = append(details, result.detail)
		// Associate each independent instruction with its own observation.
		// This is prose, not one shell command joining unrelated doorways.
		remedies = append(remedies, result.detail+": "+result.remediation)
	}
	combined.class = classInfra
	combined.detail = strings.Join(details, "; ")
	combined.remediation = strings.Join(remedies, "; ")
	return combined
}

// observeManagedDoorwayDefinitions admits only the rendered managed units before
// their names can appear in recovery commands. Each verified doorway remains
// inspectable even when another doorway needs its definitions reconciled.
func observeManagedDoorwayDefinitions(env *probeEnv, services []config.ContainmentLoopbackService) ([]managedDoorway, doctorResult) {
	if filepath.Base(env.proxyForwarderSocketPath) != containedProxyForwarderUnit+".socket" ||
		filepath.Base(env.proxyForwarderServicePath) != containedProxyForwarderUnit+".service" ||
		filepath.Base(env.namespaceForwarderServicePath) != containedNamespaceForwarderUnit {
		return nil, fail(classInfra, "managed doorway unit paths are not canonical", installRemedyForPort(env.port))
	}
	definitions := map[string][]doorwayDefinition{containedProxyForwarderUnit + ".socket": {
		{env.proxyForwarderSocketPath, renderContainedProxySocketUnit(env.agentUserName)},
		{env.proxyForwarderServicePath, renderContainedProxyForwarderUnitTo(env.pipelockTarget, env.proxyUserName, containedRelayTarget(env.configPath, env.port))},
		{env.namespaceForwarderServicePath, renderContainedNamespaceForwarderUnit(env.pipelockTarget, env.agentUserName, env.port)},
	}}
	doorways := []managedDoorway{{containedProxyForwarderUnit + ".socket", containedProxyForwarderUnit + ".service", containedNamespaceForwarderUnit, containedDoorwaySocketPath}}
	unitDir := filepath.Dir(env.proxyForwarderSocketPath)
	for _, service := range services {
		unit := loopbackForwarderUnitBase(service.Host, service.Port)
		doorways = append(doorways, managedDoorway{unit + ".socket", unit + ".service", unit + "-netns.service", declaredLoopbackDoorwayPath(service.Host, service.Port)})
		definitions[unit+".socket"] = []doorwayDefinition{
			{filepath.Join(unitDir, unit+".socket"), renderDeclaredLoopbackSocketUnit(env.agentUserName, service)},
			{filepath.Join(unitDir, unit+".service"), renderDeclaredLoopbackForwarderUnit(env.pipelockTarget, env.proxyUserName, service)},
			{filepath.Join(unitDir, unit+"-netns.service"), renderDeclaredLoopbackNamespaceForwarderUnit(env.pipelockTarget, env.agentUserName, service)},
		}
	}
	bySocket := make(map[string]managedDoorway, len(doorways))
	for _, doorway := range doorways {
		bySocket[doorway.socket] = doorway
	}
	ordered := make([]managedDoorway, 0, len(doorways))
	var results []doctorResult
	for _, socket := range managedDoorwaySocketNames(env.proxyForwarderSocketPath, services) {
		remedy := loopbackDefinitionRemedy
		if socket == containedProxyForwarderUnit+".socket" {
			remedy = installRemedyForPort(env.port)
		}
		result := observeDoorwayDefinitions(env, definitions[socket], remedy)
		if result.status == statusPass {
			ordered = append(ordered, bySocket[socket])
		} else {
			results = append(results, result)
		}
	}
	return ordered, combineDoorwayResults(results)
}

type doorwayDefinition struct{ path, want string }

func observeDoorwayDefinitions(env *probeEnv, definitions []doorwayDefinition, remedy string) doctorResult {
	for _, definition := range definitions {
		body, err := env.readFile(filepath.Clean(definition.path))
		if err != nil {
			return fail(classInfra, fmt.Sprintf("managed doorway definition %s could not be read: %v", definition.path, err), remedy)
		}
		if string(body) != definition.want {
			return fail(classInfra, fmt.Sprintf("managed doorway definition %s is missing or drifted", definition.path), remedy)
		}
	}
	return pass("managed doorway definitions match installation")
}
