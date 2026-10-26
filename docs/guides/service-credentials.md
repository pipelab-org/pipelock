# Kill-switch service credentials

`kill_switch.api_token_file` reads an operator API bearer token without putting
its value in YAML or a service environment variable. Ordinary paths resolve
relative to the config file. A systemd credential uses this literal reference:

```yaml
kill_switch:
  api_token_file: "$CREDENTIALS_DIRECTORY/admin-token"
```

Pair it with an existing encrypted credential source in a service drop-in:

```ini
[Service]
LoadCredentialEncrypted=admin-token:/etc/credstore.encrypted/admin-token
```

The credential ID must match. Pipelock expands only the literal
`$CREDENTIALS_DIRECTORY/` prefix; it doesn't expand arbitrary environment
variables. systemd supplies that directory for each service invocation. See
[systemd.exec: Credentials](https://www.freedesktop.org/software/systemd/man/latest/systemd.exec.html#Credentials).

The file must be regular, at most 1 MiB (systemd's credential-set ceiling), and
contain a nonempty visible-ASCII token without spaces. One final LF or CRLF is
accepted. Use mode `0600`, or `0640` with a service-readable group; group writes
and world access are refused. The shared secure-file reader accepts Secret-volume
symlinks only when their target stays inside the secret directory.

`api_token` and `api_token_file` are mutually exclusive. The existing nonempty
`PIPELOCK_KILLSWITCH_API_TOKEN` override wins over a valid file, but a configured
missing, unreadable, empty, or malformed file still rejects startup or reload.
There's no fallback to an old file value or an inline token when file loading fails.

A successful config load stores a private token snapshot. Ordinary file rotation
takes effect after SIGHUP or a config-file reload; token-file changes alone aren't
watched. A failed reload retains the previously accepted token and kill-switch
activation state. Removing the file setting and all other token inputs disables
the API. Encrypted systemd credentials are materialized per service invocation:
replacing their encrypted source requires a service restart to change the running
service's credential. SIGHUP reads its current invocation's credential, which
systemd exposes read-only.

## Service validation and migration

The service configuration check accepts exactly one matching `LoadCredential` or
`LoadCredentialEncrypted` with an absolute regular source file. It requires root
and systemd 254 or newer. Credential IDs use ASCII letters, digits, dots, hyphens,
and underscores. Credential sources, binary paths, and config directories used
by this check must be clean absolute paths without whitespace, quotes,
specifiers, glob characters, colons, or backslashes. Sockets, directory imports,
credential-store searches, other credential IDs, `SetCredential*`, and
`ImportCredential` remain unsupported. Opaque credential-source observation uses
the service checker's existing 64 KiB file bound; larger source files are refused.

For this case the check launches a bounded transient validation service under the
observed static service identity. PID 1 materializes a fresh credential from the
observed source; the check never borrows a running service's credential directory.
The selected executable inode is bound read-only into the validation service.
Candidate YAML travels on stdin, token values stay out of command arguments,
validator output is discarded, and core dumps are disabled. Source rotation or
service-definition changes during the check cause refusal. This validates config
inputs, not the target service's full mount namespace or runtime health.

An `ExecStartPre` shell that converts a credential into an `EnvironmentFile` must
be migrated before the normal installer preflight can accept the service.
Pipelock refuses that hook and `ExecCondition`; it never executes them to predict
a future environment. The refusal happens before replacing the service binary,
writing a unit, restarting the proxy, or changing firewall rules.

Prepare a migration packet containing the candidate YAML with the native file
reference, the matching credential directive with the same encrypted source, and
the proposed removal of the token-export hook and its generated environment-file
reference. Keep unrelated environment settings and drop-ins. Back up the current
config and affected drop-ins, including their modes and ownership, before an
operator applies the packet. Keep the encrypted source unchanged.

This installer doesn't automatically rewrite arbitrary shell hooks or drop-ins.
Have an operator review the packet before applying it. After loading the proposed
unit definitions, run the selected binary's `check --service pipelock --config`
against the absolute candidate config path, then run the normal installer. Don't
restart the target service if either check refuses. If validation fails, restore
the backed-up config and drop-ins and reload the service definitions; don't replace
the encrypted source or revoke the accepted token as part of rollback. The running
service keeps its prior invocation until an explicitly requested restart.
