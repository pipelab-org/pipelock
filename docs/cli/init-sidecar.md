# pipelock init sidecar

Generate an enforced pipelock companion proxy for a Kubernetes workload.

## Synopsis

```bash
pipelock init sidecar --inject-spec <manifest>
  [--emit patch|kustomize|helm-values]
  [--output <path>]
  [--dry-run]
  [--force]
  [--image <ref>]
  [--preset strict|balanced|audit|claude-code|cursor|generic-agent|hostile-model]
  [--skip-canary]
  [--skip-verify]
  [--json]
  [--agent-identity <name>]
  [--mcp-upstream <http-url>]
  [--mcp-server-name <name>]
```

## Description

`pipelock init sidecar` reads a Kubernetes workload manifest (Deployment, StatefulSet, Job, or CronJob), patches the workload to use a companion pipelock proxy Service, and emits the extra Kubernetes resources needed to enforce that topology.

The generated bundle includes:

- The patched agent workload with `HTTPS_PROXY` and `HTTP_PROXY` pointing at the companion Service, plus `NO_PROXY=localhost,127.0.0.1,.svc,.cluster.local` for local and in-cluster destinations that should bypass the proxy
- A pipelock ConfigMap with forward proxy mode enabled
- A companion pipelock Deployment with two replicas, anti-affinity, and production-oriented resource defaults
- A companion pipelock Service
- An agent NetworkPolicy that limits agent pod egress to DNS plus the pipelock proxy
- A proxy NetworkPolicy that allows agent ingress and standard web egress for the pipelock proxy pods
- A PodDisruptionBudget that keeps at least one proxy replica available during voluntary disruptions

When `--mcp-upstream` is set, the bundle also exposes the companion proxy's MCP listener on port `8889`, injects `PIPELOCK_MCP_PROXY_URL` and `PIPELOCK_MCP_CONFIG` into the agent workload, mounts a generated `mcp.json` file at `/etc/pipelock/mcp/mcp.json`, and updates NetworkPolicies so the agent can reach only the Pipelock MCP listener while the proxy can reach the configured upstream MCP endpoint.

This is not same-pod sidecar injection. The enforcement boundary comes from pod-scoped NetworkPolicies plus a separate pipelock proxy workload, not from trusting application containers to honor proxy environment variables on their own.

The command runs 7 phases: detect, generate, preview, emit, verify, canary, and summary.

## Flags

| Flag | Default | Description |
|------|---------|-------------|
| `--inject-spec` | (required) | Path to the Kubernetes workload manifest |
| `--emit` | `patch` | Output format: `patch`, `kustomize`, or `helm-values` |
| `--output`, `-o` | stdout (patch only) | Output path. **`patch` writes a multi-doc YAML stream to stdout when `-o` is omitted.** **`kustomize` and `helm-values` require `-o <dir>`** (bundle formats emit multi-file trees — overlay, resources, values.yaml, README — and error out when `-o` is missing). Passing a `.yaml` file path to a bundle format creates a directory with that name. |
| `--dry-run` | false | Show the generated topology without writing files or running canary |
| `--force` | false | Regenerate companion output even from an already-patched input, and overwrite existing output files |
| `--image` | `ghcr.io/pipelab-org/pipelock:<version>` | Companion proxy image (tag or digest ref) |
| `--preset` | `balanced` | Config preset: `strict`, `balanced`, `audit`, `claude-code`, `cursor`, `generic-agent`, `hostile-model` |
| `--skip-canary` | false | Skip the canary detection test |
| `--skip-verify` | false | Skip static topology verification |
| `--json` | false | Machine-readable JSON output (`--output` required unless `--dry-run`) |
| `--agent-identity` | `<kind>/<name>` | Default agent identity for attribution |
| `--mcp-upstream` | unset | Optional upstream MCP HTTP/SSE URL. When set, the companion proxy exposes `PIPELOCK_MCP_PROXY_URL=http://<proxy>:8889` and mounts a generated MCP client config. |
| `--mcp-server-name` | `pipelock` | Server name used inside the generated `mcp.json` when `--mcp-upstream` is set. |

## Supported Workload Kinds

| Kind | Pod spec location |
|------|-------------------|
| Deployment | `spec.template.spec` |
| StatefulSet | `spec.template.spec` |
| Job | `spec.template.spec` |
| CronJob | `spec.jobTemplate.spec.template.spec` |

## Output Formats

### patch (default)

Writes the full enforced topology as multi-document YAML:

1. Patched agent workload
2. Pipelock ConfigMap
3. Optional MCP client ConfigMap when `--mcp-upstream` is set
4. Pipelock Deployment
5. Pipelock Service
6. Agent NetworkPolicy
7. Pipelock NetworkPolicy
8. Pipelock PodDisruptionBudget

```bash
pipelock init sidecar --inject-spec deployment.yaml --output enforced.yaml
kubectl apply -f enforced.yaml
```

### kustomize

Writes a standalone directory with the emitted resources and `kustomization.yaml`.

Generated files:

- `agent-workload.yaml`
- `pipelock-configmap.yaml`
- `pipelock-mcp-configmap.yaml` when `--mcp-upstream` is set
- `pipelock-deployment.yaml`
- `pipelock-service.yaml`
- `agent-networkpolicy.yaml`
- `pipelock-networkpolicy.yaml`
- `pipelock-pdb.yaml`
- `kustomization.yaml`

```bash
pipelock init sidecar --inject-spec deployment.yaml --emit kustomize --output ./pipelock-overlay
kubectl apply -k ./pipelock-overlay
```

### helm-values

Writes a Helm bundle directory for the pipelock chart plus the agent workload and NetworkPolicies that stay outside the chart.

Generated files:

- `values.yaml`
- `agent-workload.yaml`
- `pipelock-mcp-configmap.yaml` when `--mcp-upstream` is set
- `agent-networkpolicy.yaml`
- `pipelock-networkpolicy.yaml`
- `pipelock-pdb.yaml`
- `README.txt`

```bash
pipelock init sidecar --inject-spec deployment.yaml --emit helm-values --output ./pipelock-bundle
# The chart is an OCI artifact and Helm cannot list its tags: use an exact chart version, which equals a Pipelock release version.
read -r -p 'Chart version to render and inspect: ' chart_version
helm show chart oci://ghcr.io/pipelab-org/charts/pipelock --version "$chart_version"
helm template my-agent-pipelock oci://ghcr.io/pipelab-org/charts/pipelock --version "$chart_version" \
  -f ./pipelock-bundle/values.yaml > ./pipelock-bundle/rendered.yaml
# Inspect rendered.yaml before continuing (see Verification below).
helm upgrade --install my-agent-pipelock oci://ghcr.io/pipelab-org/charts/pipelock --version "$chart_version" \
  -f ./pipelock-bundle/values.yaml
kubectl rollout status deployment/my-agent-pipelock
kubectl apply -f ./pipelock-bundle/pipelock-networkpolicy.yaml \
  -f ./pipelock-bundle/pipelock-pdb.yaml
kubectl apply -f ./pipelock-bundle/agent-networkpolicy.yaml
kubectl apply -f ./pipelock-bundle/agent-workload.yaml
```

## Examples

### Deployment (dry run)

```bash
pipelock init sidecar --inject-spec deployment.yaml --dry-run
```

### StatefulSet with strict preset

```bash
pipelock init sidecar --inject-spec statefulset.yaml --preset strict --output enforced.yaml
```

### Job with custom agent identity

```bash
pipelock init sidecar --inject-spec job.yaml --agent-identity ci-team/nightly-scan
```

### OpenClaw or Cluster MCP Gateway

```bash
pipelock init sidecar \
  --inject-spec deployment.yaml \
  --mcp-upstream http://openclaw-gateway:3000/mcp \
  --mcp-server-name openclaw \
  --output enforced.yaml
```

The generated workload receives `PIPELOCK_MCP_PROXY_URL=http://<proxy-service>:8889` and `PIPELOCK_MCP_CONFIG=/etc/pipelock/mcp/mcp.json`. That file contains a top-level `mcpServers` object whose configured server URL points at the Pipelock MCP listener, not at the upstream gateway. Configure the agent launcher to read `PIPELOCK_MCP_CONFIG`, or configure the MCP client directly from `PIPELOCK_MCP_PROXY_URL`.

The NetworkPolicy limits the agent pod to DNS plus the Pipelock HTTP and MCP proxy ports, so direct HTTP egress to the upstream MCP gateway is not part of the generated agent boundary.

### CronJob with kustomize output

```bash
pipelock init sidecar --inject-spec cronjob.yaml --emit kustomize --output ./overlay
```

### Machine-readable output

```bash
pipelock init sidecar --inject-spec deployment.yaml --dry-run --json
```

## Agent Identity

Requests are attributed to a default agent identity derived from the workload:

- `deployment/my-agent` for a Deployment named `my-agent`
- `statefulset/my-db` for a StatefulSet named `my-db`

Override with `--agent-identity`. The identity is written into the generated pipelock config as `default_agent_identity` and appears in audit logs, receipts, and metrics instead of `anonymous`.

The generated companion config also sets `bind_default_agent_identity: true`, which makes the deployment single-workload and operator-bound: caller-supplied `X-Pipelock-Agent` headers and `?agent=` query parameters are ignored.

Companion-mode precedence: context override (unused in this topology) > `default_agent_identity` config > `anonymous`.

## Verification

The verify phase is static. For emitted `patch` and `kustomize` output, it checks the generated companion resources and boundary settings:

- proxy-only writable state with a read-only root filesystem
- forward proxy mode enabled
- cluster-reachable proxy listeners
- optional MCP listener, mounted MCP client config, and NetworkPolicy ports when `--mcp-upstream` is set
- agent NetworkPolicy allows DNS plus the pipelock proxy port only
- proxy NetworkPolicy allows agent ingress and standard web egress

For `helm-values`, the CLI checks the generated config, emitted NetworkPolicies and disruption budget, and optional MCP client wiring. It doesn't render the selected Helm chart, so it reports `Verify: skipped` (`skipped: true`, `healthy: false`, `reachable: false` in JSON). This is an unknown chart result even when those checks pass. A failed config or emitted-policy check still fails the command.

Render an exact chart version with the generated values before installing that same version. Inspect the rendered Deployment, Service and ConfigMaps for the expected selectors, listeners, security settings and proxy-only writable state. The default state wiring uses `HOME=/var/lib/pipelock/home` from the first `envFrom` ConfigMap and a writable private-home mount at `/var/lib/pipelock/home`. Cookie state uses `$HOME/.local/state`; other HOME-based metadata can also write within that private home. An operator HOME or XDG override needs its corresponding storage. Earlier chart versions may have no default writable state even with newly generated values. Static checks don't establish cluster reachability or a healthy deployment.

The canary phase runs locally against the generated config to confirm DLP blocks a synthetic secret. It validates generated policy coverage, not the live cluster deployment.

## NetworkPolicy Semantics

The enforcement claim for this command depends on Kubernetes NetworkPolicy egress enforcement being active in your cluster. If your CNI does not enforce egress policies, the generated manifests still configure the companion proxy correctly, but the cluster will not provide the intended direct-egress boundary.

### Verify per-pod ingress restrictions on your CNI

NetworkPolicies are additive: the effective permission set is the union of every policy selecting a pod, and there is no deny rule. A narrow policy therefore cannot override a broad one. If some other policy in the namespace already permits the traffic, the narrow policy changes nothing, and it will still be accepted by the API server and still read correctly in `kubectl get networkpolicy -o yaml`.

A CNI can also fail to apply a policy the way the API accepts it. On one cluster running k3s v1.33.6+k3s1 with flannel and the embedded kube-router NetworkPolicy controller, a namespace-wide policy that selects every pod with `podSelector: {}` **and** declares both `Ingress` and `Egress` in the same object was observed defeating a more specific per-pod **ingress** policy in that namespace, so the narrow policy enforced nothing at all. Splitting the namespace-wide policy into two objects, one `Ingress`-only and one `Egress`-only with identical rules, restored the expected behaviour; a policy selecting a specific pod carried both directions safely. This resembles older reports against k3s and kube-router such as [k3s-io/k3s#2390](https://github.com/k3s-io/k3s/issues/2390). Do not assume the problem is limited to that stack, and do not assume your own stack is affected — the point is to test rather than infer.

The generated bundle's proxy NetworkPolicy is a per-pod ingress policy: it permits agent pods to reach the proxy. Where such a restriction is not enforced, more pods in the namespace than intended can reach the proxy listener. That widens who may send traffic *through* pipelock rather than creating a path *around* it, since the agent-side boundary is a separate egress policy. Note that pipelock ignores caller-supplied identity headers, so traffic from an unintended pod is attributed to the workload the proxy is bound to — treat it as an evidence-attribution concern as well as an access one.

The same testing advice applies to egress. On the cluster above, a per-pod egress restriction continued to enforce under the conditions that broke ingress, but that is one observation on one CNI, and Kubernetes gives no signal for when a policy change has finished being applied, so it is not a guarantee for your cluster.

Do not take any of this on trust. Prove each restriction with a **positive control followed by a negative test** — the positive control matters, because a failed connection from an excluded pod proves nothing if the listener, IP, or port were wrong to begin with:

```bash
# 1. POSITIVE CONTROL: a pod the policy permits must SUCCEED.
#    If this fails, your target details are wrong and the test below is meaningless.
kubectl exec -n <namespace> <permitted-agent-pod> -- \
  timeout 5 nc -z -w4 <pipelock-proxy-pod-ip> 8888

# 2. NEGATIVE TEST: a pod the policy excludes must FAIL.
#    Success here means the restriction is not being enforced.
kubectl exec -n <namespace> <excluded-pod> -- \
  timeout 5 nc -z -w4 <pipelock-proxy-pod-ip> 8888
```

Step 2 may fail as a connection timeout or as `connection refused`, depending on whether your CNI drops or rejects; either is a pass once step 1 has succeeded. Both commands need `timeout` and an `nc` supporting `-z` in the pod image.

For existing workloads, roll the companion proxy out first and wait for ready endpoints before patching the agent workload. The Helm bundle output includes that order explicitly to avoid a fail-closed brownout while the proxy Deployment is still starting.

Within a cluster that enforces egress NetworkPolicies, the agent pods are limited to:

- DNS
- The pipelock companion Service on port `8888`
- The pipelock companion Service on port `8889` when `--mcp-upstream` is set

Direct `80/443` web egress is reserved for the pipelock companion pods, not the agent workload.

DNS egress is intentionally left unrestricted at the NetworkPolicy layer for cluster portability. This command does not block DNS tunneling by policy alone.

`--mcp-upstream` does not rewrite arbitrary application MCP client settings by itself. It creates the enforced cluster path and exposes two launcher inputs: `PIPELOCK_MCP_CONFIG=/etc/pipelock/mcp/mcp.json` and `PIPELOCK_MCP_PROXY_URL=http://<proxy-service>:8889`. The agent image, launcher, or config must consume one of those values for MCP traffic to traverse Pipelock.

The proxy NetworkPolicy egress rule for the upstream port has no destination selector. Vanilla Kubernetes NetworkPolicies cannot express "only this hostname." If the upstream port is shared with unrelated services in any namespace the proxy can reach, the rule technically allows the proxy to talk to them too. For tighter scoping, edit the generated `proxy-network-policy.yaml` to add a `to:` clause matching the upstream namespace and pod labels.

## Idempotency

The workload annotations preserve the generated proxy identity on reruns. Without `--force`, an already-patched input leaves existing output untouched and reports verification skipped because those files weren't checked. A changed MCP contract, such as enabling or disabling `--mcp-upstream`, causes emission instead of a no-op.

Use `--force` with either the patched or original manifest to regenerate companion output, including state wiring added after the earlier generation. This overwrites manual output edits; review them first. `--dry-run` writes nothing and skips verification and canary even with `--force`. A forced `helm-values` rerun still leaves chart verification unknown: the selected chart version supplies the Deployment, so render and inspect that version before upgrading.

Re-running against a manifest previously generated with `--mcp-upstream`, but without the flag this time, scrubs the prior `PIPELOCK_MCP_PROXY_URL` and `PIPELOCK_MCP_CONFIG` env entries, the generated MCP ConfigMap mount, and the MCP contract annotations so the agent does not advertise a contract the regenerated Service no longer fulfills.
