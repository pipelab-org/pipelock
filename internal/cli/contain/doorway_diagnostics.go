// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package contain

import (
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/cliutil"
	"github.com/luckyPipewrench/pipelock/internal/config"
)

const (
	doorwayInspectionRemedy  = "restore access to the managed containment state and rerun the diagnostic"
	loopbackDefinitionRemedy = "rerun `pipelock contain reload-nft-rules`"
	doorwaysHealthyDetail    = "all managed doorway sockets and namespace forwarders are enabled and active"
)

type managedDoorway struct {
	socket    string
	relay     string
	forwarder string
	path      string
	listen    string
	// legacySimple marks a namespace forwarder whose definition is the exact
	// Type=simple rendering from before bind readiness.
	legacySimple bool
}

// combineDoorwayResults follows runDoctor's result contract: retain every
// finding, with fail taking precedence over unknown and unknown over pass.
// The caller supplies the established sorted doorway order.
func combineDoorwayResults(results []doctorResult) doctorResult {
	combined := pass(doorwaysHealthyDetail)
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
	doorways := []managedDoorway{{socket: containedProxyForwarderUnit + ".socket", relay: containedProxyForwarderUnit + ".service", forwarder: containedNamespaceForwarderUnit, path: containedDoorwaySocketPath, listen: systemdListenAddress("127.0.0.1", env.port)}}
	unitDir := filepath.Dir(env.proxyForwarderSocketPath)
	for _, service := range services {
		unit := loopbackForwarderUnitBase(service.Host, service.Port)
		doorways = append(doorways, managedDoorway{socket: unit + ".socket", relay: unit + ".service", forwarder: unit + "-netns.service", path: declaredLoopbackDoorwayPath(service.Host, service.Port), listen: systemdListenAddress(service.Host, service.Port)})
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
		result, legacy := observeDoorwayDefinitions(env, definitions[socket], remedy)
		if result.status == statusPass {
			doorway := bySocket[socket]
			doorway.legacySimple = legacy
			ordered = append(ordered, doorway)
		} else {
			results = append(results, result)
		}
	}
	return ordered, combineDoorwayResults(results)
}

type doorwayDefinition struct{ path, want string }

// observeDoorwayDefinitions also reports whether a namespace forwarder still
// carries the exact pre-readiness definition. `contain upgrade` replaces only
// the binary, so refusing that definition would roll back every upgraded host;
// the runtime check still refuses it when it is restart-looping.
func observeDoorwayDefinitions(env *probeEnv, definitions []doorwayDefinition, remedy string) (doctorResult, bool) {
	legacy := false
	for _, definition := range definitions {
		body, err := env.readFile(filepath.Clean(definition.path))
		if err != nil {
			return fail(classInfra, fmt.Sprintf("managed doorway definition %s could not be read: %v", definition.path, err), remedy), false
		}
		if string(body) == definition.want {
			continue
		}
		if old, ok := legacyNamespaceForwarderDefinition(definition.want); ok && string(body) == old {
			legacy = true
			continue
		}
		if strings.Contains(definition.want, "Type=notify\n") && strings.Contains(string(body), "Type=simple\n") {
			return fail(classInfra, fmt.Sprintf("managed namespace listener %s uses Type=simple without bind readiness", definition.path), remedy), false
		}
		return fail(classInfra, fmt.Sprintf("managed doorway definition %s is missing or drifted", definition.path), remedy), false
	}
	return pass("managed doorway definitions match installation"), legacy
}

// legacyNamespaceForwarderDefinition derives the Type=simple definition that
// releases before bind readiness rendered from the current one. Only the
// readiness directives and the notification socket bind differ.
func legacyNamespaceForwarderDefinition(want string) (string, bool) {
	readiness := fmt.Sprintf("Type=notify\nNotifyAccess=main\nTimeoutStartSec=%d\n", int64(cliutil.ServiceStartTimeout/time.Second))
	notifyBind := "BindReadOnlyPaths=" + systemdNotifySocketPath + "\n"
	if strings.Count(want, readiness) != 1 || strings.Count(want, notifyBind) != 1 {
		return "", false
	}
	old := strings.Replace(want, readiness, "Type=simple\n", 1)
	return strings.Replace(old, notifyBind, "", 1), true
}

// legacyNamespaceForwarderNote names forwarders still on the pre-readiness
// definition. A passing result keeps them visible with the migration command.
func legacyNamespaceForwarderNote(doorways []managedDoorway, port int) string {
	var units []string
	for _, doorway := range doorways {
		if doorway.legacySimple {
			units = append(units, doorway.forwarder)
		}
	}
	if len(units) == 0 {
		return ""
	}
	return "namespace listener " + strings.Join(units, ", ") + " still uses the Type=simple definition without bind readiness; " + installRemedyForPort(port) + " to migrate it"
}
