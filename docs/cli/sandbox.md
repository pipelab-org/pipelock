# pipelock sandbox

`pipelock sandbox` runs one command with Linux filesystem and network restrictions. It starts its own scanning proxy and needs no running Pipelock service. Landlock is required. A network namespace requires unprivileged user namespaces; seccomp is available on `linux/amd64`. See the [sandbox guide](../guides/sandbox.md) for launch posture and kernel details.

```sh
pipelock sandbox --dry-run -- python agent.py
pipelock sandbox --workspace /path/to/project -- python agent.py
pipelock sandbox --env API_KEY -- python agent.py
```

The `--` separator and command are required, including for a dry run. Arguments after it go to the command.

## Flags

| Flag | Behavior |
|---|---|
| `--workspace DIR` | Writable workspace and working directory. Defaults to `sandbox.workspace` in the config, then the current directory. |
| `-c, --config FILE` | Load scanner and sandbox settings from a config file. Without one, use defaults. |
| `--strict` | Require all layers and descendant cleanup, mount private `/dev/shm`, and block `clone3`. Incompatible with best effort. |
| `--best-effort` | Authorize an advisory network fallback if namespaces aren't available. Requires a reason and expiry; Landlock remains mandatory. |
| `--best-effort-reason TEXT` | Reason for the command-line override. |
| `--best-effort-expiry DURATION_OR_TIME` | Admission expiry as a duration or RFC3339 timestamp. It doesn't stop an already running child. |
| `--env KEY` or `--env KEY=VALUE` | Pass an inherited value or an explicit value; repeatable. An unset bare name is omitted. Some names are refused. |
| `--dry-run` | Check capabilities and configuration without launching. Exit 0 means capabilities OK, 1 degraded, and 2 unavailable. |
| `--json` | Print the dry-run result as JSON. |
| `-h, --help` | Show command help. |
| `--home DIR` | Global Pipelock home; defaults to `PIPELOCK_HOME` or `~/.pipelock`. |

Put all three best-effort fields in the same source: command-line flags or config. Later launches need a valid authorization. See [best-effort admission](../guides/sandbox.md#advisory-network-override) for config expiry limits.

## Preflight and launch outcomes

Dry-run checks capabilities, workspace policy, environment arguments, and override fields. `CAPABILITIES_OK` is a probe, not proof the child applied the layers. Host policy can still prevent a real launch; Ubuntu's AppArmor user-namespace restriction is one example. Check the launch status line for the child's outcome.

| Outcome | Meaning |
|---|---|
| `FULL` | Landlock, seccomp, and the network namespace applied. |
| `PARTIAL` | Landlock and the network namespace applied, but seccomp is unavailable, as on `linux/arm64`. |
| `ADVISORY-OVERRIDE` | An authorized fallback ran without the network namespace. Direct egress can bypass Pipelock. A seccomp warning can appear alongside it. |
| `REFUSED` | A required layer wasn't applied and the target didn't start. |

Strict mode also requires descendant cleanup and refuses missing Unix socket isolation. On non-strict launches, a cleanup warning means a detached descendant can outlive the session. See [outcomes](../guides/sandbox.md#outcomes) for the exact kernel-dependent limits.

## Files and environment

The workspace is writable, including its contents. System runtime paths are readable under the default policy; other host files, including the ordinary home directory, aren't generally available. Configured `sandbox.fs.allow_read` and `sandbox.fs.allow_write` add grants. A read-only path nested under a writable grant remains writable. Choose the workspace and grants carefully: the child can access their contents with the granted rights.

The child gets a temporary synthetic `HOME`, XDG directories, `TMPDIR`, `PATH`, and `PWD`. Only `USER`, `LANG`, `LC_ALL`, `TERM`, and `TZ` are inherited by default. `--env` can add ordinary values; pass secrets by name instead of putting values in shell history or process arguments. Code-loading names, `CDPATH`, and names ending in `_PROXY` are refused. The [environment restrictions](../guides/sandbox.md#child-environment-restrictions) describe the checks.

## Network and developer tools

With a network namespace, the child has isolated networking and reaches the embedded scanning proxy through a bridge. HTTP and HTTPS clients must use the supplied proxy settings. Direct external connections and host loopback services aren't available through the isolated network. HTTPS CONNECT bodies remain encrypted unless TLS interception is configured and the client trusts its CA. Sandbox doesn't install CA overrides for the child.

On Landlock ABI 9 or newer, the proxy socket is allowed and other host pathname Unix sockets are denied, even inside the workspace. ABI 6 scopes abstract sockets and signals. On older `linux/amd64` kernels, seccomp blocks new Unix sockets and datagram socketpairs; it also blocks `recvmsg` and `recvmmsg`. Connected stream and sequenced-packet socketpairs remain available. On older `linux/arm64`, the partial launch lacks the pathname socket boundary; below ABI 6 it also lacks abstract socket isolation. Inherited descriptors aren't revoked. See [outcomes](../guides/sandbox.md#outcomes) for the fallback's application compatibility limits.

These boundaries affect common workflows:

- SSH agent and Docker daemon sockets normally aren't reachable, and SSH keys in the ordinary home aren't granted. SSH also doesn't use the HTTP proxy settings.
- An editor's host socket or local server isn't normally reachable from the isolated network. Editor integrations that depend on them can fail.
- Existing agent logins and caches in the ordinary home aren't inherited. A login may need a reachable callback and writable credentials; the synthetic home is temporary. Explicit environment credentials or filesystem grants expose those values to the child.

In an authorized best-effort fallback without a network namespace, HTTP(S) proxy variables steer cooperative clients, but direct traffic can bypass scanning. Other filesystem and socket restrictions still apply.

## Troubleshooting

| Symptom | Check |
|---|---|
| Namespace unavailable or launch refused after a successful preflight | Check user-namespace and container restrictions. On Ubuntu, see the [AppArmor guidance](../guides/sandbox.md#ubuntu-and-apparmor-user-namespace-restriction). Use an authorized best-effort override only if its direct-egress exposure is acceptable. |
| Landlock unavailable | Use a kernel with Landlock enabled. Best effort doesn't waive Landlock. |
| `EXDEV` on a move or hard link | Older kernels or kernels without the reported Landlock erratum 3 fix deny cross-directory operations. See [workspace renames](../guides/sandbox.md#workspace-renames-and-hard-links). |
| Command or login can't find files | Check the workspace, synthetic home, explicit environment, and configured filesystem grants. |
| Local socket or server fails | Check the network and Unix socket limits above; older kernels can also block `recvmsg`. |
| Strict launch refused on arm64 | Seccomp isn't built for that architecture, so strict mode can't satisfy its requirements. |

## Choosing a launcher

[`sandbox`](sandbox.md) isolates one Linux command with its own proxy and filtered environment. [`contain`](../contain-cli.md) manages host-level Linux containment and its operator lifecycle. [`exec`](exec.md) launches a cooperative client against a running proxy using environment settings; the client can ignore them. Each has different prerequisites and coverage limits.
