{{/*
Copyright 2026 Pipelock contributors
SPDX-License-Identifier: Apache-2.0

Inputs are actual helm template output, whose documents use --- separators.
Decode with Helm itself so chart policy checks require no Go or YAML package.
*/}}
{{- if not .Values.manifests }}{{ fail "no rendered manifests supplied" }}{{ end -}}
{{- range $case, $content := .Values.manifests -}}
{{- $deployments := list -}}
{{- $maps := dict -}}
{{- range $text := splitList "\n---\n" $content -}}
{{- $doc := fromYaml $text -}}
{{- if hasKey $doc "Error" }}{{ fail (printf "%s: invalid YAML: %s" $case $doc.Error) }}{{ end -}}
{{- if eq $doc.kind "Deployment" }}{{ $deployments = append $deployments $doc }}{{ end -}}
{{- if eq $doc.kind "ConfigMap" }}{{ $_ := set $maps $doc.metadata.name $doc.data }}{{ end -}}
{{- end -}}
{{- if ne (len $deployments) 1 }}{{ fail (printf "%s: expected one Deployment" $case) }}{{ end -}}
{{- $deployment := first $deployments -}}
{{- $pod := $deployment.spec.template.spec -}}
{{- if ne (len $pod.containers) 1 }}{{ fail (printf "%s: expected one container" $case) }}{{ end -}}
{{- $container := first $pod.containers -}}
{{- $proxy := eq (first $container.args) "run" -}}
{{- $custom := hasPrefix "custom-state" $case -}}
{{- $home := contains "-home" $case -}}
{{- $statePath := ternary "/custom/state" "/var/lib/pipelock" $custom -}}
{{- if $home }}{{ $statePath = "/custom/home/.local/state" }}{{ end -}}
{{- $envs := 0 -}}
{{- $mounts := 0 -}}
{{- $volumes := 0 -}}
{{- range $env := $container.env -}}
{{- if or (eq $env.name "XDG_STATE_HOME") (eq $env.name "HOME") -}}
{{- $envs = add1 $envs -}}
{{- if contains "valuefrom" $case -}}
{{- $ref := get $env.valueFrom (ternary "secretKeyRef" "configMapKeyRef" (contains "secret" $case)) -}}
{{- if or (not $ref) $env.value }}{{ fail (printf "%s: state valueFrom changed" $case) }}{{ end -}}
{{- else -}}
{{- if or (ne $env.value (ternary "/custom/home" $statePath $home)) $env.valueFrom }}{{ fail (printf "%s: state home changed" $case) }}{{ end -}}
{{- end -}}
{{- end -}}
{{- end -}}
{{- range $mount := $container.volumeMounts -}}
{{- if eq $mount.name "pipelock-state" -}}
{{- $mounts = add1 $mounts -}}
{{- if or (ne $mount.mountPath $statePath) (and (hasKey $mount "readOnly") (ne (toJson $mount.readOnly) "false")) }}{{ fail (printf "%s: state mount not writable at state home" $case) }}{{ end -}}
{{- end -}}
{{- end -}}
{{- range $volume := $pod.volumes -}}
{{- if eq $volume.name "pipelock-state" -}}
{{- $volumes = add1 $volumes -}}
{{- if $custom -}}
{{- if or (ne $volume.persistentVolumeClaim.claimName "existing-state") (hasKey $volume "emptyDir") }}{{ fail (printf "%s: custom storage changed" $case) }}{{ end -}}
{{- else -}}
{{- if not (kindIs "map" $volume.emptyDir) }}{{ fail (printf "%s: state emptyDir missing" $case) }}{{ end -}}
{{- end -}}
{{- end -}}
{{- end -}}
{{- $stateMap := printf "%s-state-env" $deployment.metadata.name -}}
{{- if not $proxy -}}
{{- if or (ne (int (add $envs $mounts $volumes)) 0) (hasKey $maps $stateMap) }}{{ fail (printf "%s: proxy state leaked into server mode" $case) }}{{ end -}}
{{- else -}}
{{- if or (ne (int $mounts) 1) (ne (int $volumes) 1) }}{{ fail (printf "%s: state links: mount=%d volume=%d" $case (int $mounts) (int $volumes)) }}{{ end -}}
{{- if $custom -}}
{{- if or (ne (int $envs) 1) (hasKey $maps $stateMap) }}{{ fail (printf "%s: explicit state home must replace defaults" $case) }}{{ end -}}
{{- if ne (len (default list $container.envFrom)) 2 }}{{ fail (printf "%s: operator envFrom lost" $case) }}{{ end -}}
{{- range $source := $container.envFrom -}}
{{- if eq (dig "configMapRef" "name" "" $source) $stateMap }}{{ fail (printf "%s: default state envFrom not suppressed" $case) }}{{ end -}}
{{- end -}}
{{- else -}}
{{- if ne (int $envs) 0 }}{{ fail (printf "%s: default state must not shadow operator envFrom" $case) }}{{ end -}}
{{- if or (ne (dig "configMapRef" "name" "" (first $container.envFrom)) $stateMap) (get (first $container.envFrom) "prefix") }}{{ fail (printf "%s: default state ConfigMap must be first envFrom source without a prefix" $case) }}{{ end -}}
{{- $data := get $maps $stateMap -}}
{{- if or (ne (len $data) 1) (ne $data.HOME "/var/lib/pipelock") }}{{ fail (printf "%s: default state ConfigMap changed" $case) }}{{ end -}}
{{- end -}}
{{- if eq $case "unrelated-envfrom" -}}
{{- if or (ne (len (default list $container.envFrom)) 2) (ne (dig "configMapRef" "name" "" (index $container.envFrom 1)) "unrelated-env") }}{{ fail "unrelated operator envFrom lost" }}{{ end -}}
{{- end -}}
{{- if hasPrefix "envfrom-state" $case -}}
{{/* Kubernetes Pod API: last envFrom source wins; explicit env wins over envFrom. */}}
{{- $sources := $container.envFrom -}}
{{- if or (ne (len $sources) 3) (ne (dig "configMapRef" "name" "" (index $sources 1)) "state-from-envfrom") (ne (dig "secretRef" "name" "" (index $sources 2)) "state-from-secret") }}{{ fail (printf "%s: operator envFrom order changed" $case) }}{{ end -}}
{{- $operatorMount := false -}}
{{- $operatorVolume := false -}}
{{- range $mount := $container.volumeMounts -}}
{{- if and (eq $mount.name "operator-state") (eq $mount.mountPath "/operator/state") (not $mount.readOnly) }}{{ $operatorMount = true }}{{ end -}}
{{- end -}}
{{- range $volume := $pod.volumes -}}
{{- if and (eq $volume.name "operator-state") (eq (dig "persistentVolumeClaim" "claimName" "" $volume) "operator-state") }}{{ $operatorVolume = true }}{{ end -}}
{{- end -}}
{{- if not (and $operatorMount $operatorVolume) }}{{ fail (printf "%s: operator storage changed" $case) }}{{ end -}}
{{- end -}}
{{- $security := $container.securityContext -}}
{{- if or (ne (toJson $pod.securityContext.fsGroup) "65534") (ne (toJson $security.readOnlyRootFilesystem) "true") (ne (toJson $security.runAsNonRoot) "true") (ne (toJson $security.runAsUser) "65534") (and (hasKey $security "allowPrivilegeEscalation") (ne (toJson $security.allowPrivilegeEscalation) "false")) (ne (toJson $security.capabilities.drop) "[\"ALL\"]") }}{{ fail (printf "%s: proxy security settings changed" $case) }}{{ end -}}
{{- end -}}
{{- end -}}
# decoded Helm proxy state checks passed
