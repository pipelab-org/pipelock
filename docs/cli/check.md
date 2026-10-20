# `pipelock check`

Validate a config file with `pipelock check --config pipelock.yaml`. Add `--url` to test a URL against that config's scanner. Add `--require-build-compatibility` to reject configuration that the selected binary can't enforce.

## Validate for the local service

On Linux with systemd, validate a candidate using the configuration environment of the local system `pipelock.service`:

```bash
sudo pipelock check --config /etc/pipelock/pipelock.yaml --service pipelock
```

This mode reads the manager's environment and the loaded unit's effective `Environment`, ordered `EnvironmentFiles`, and `UnsetEnvironment` properties. Systemd resolves drop-in ordering, resets, and unit specifiers. Environment-file values stay literal; the checker doesn't expand shell expressions. Later files override earlier assignments, and unsets apply last. An optional missing file is allowed. An existing optional file that can't be read or parsed causes refusal.

The validator receives only environment variables consumed by config, license, and signing-path readers, including `HOME` and `PIPELOCK_HOME`. It doesn't inherit the invoking shell's environment or pass loader variables to the selected binary. It runs as the static service user with its primary and supplementary groups. Root can switch to that identity; an unprivileged caller must already have that identity and those groups. Candidate bytes arrive over stdin, and relative companion files resolve from the candidate's directory. The selected executable must be a regular file rather than a symlink.

Success prints `Config validation: OK (valid for pipelock.service configuration environment)`. This checks configuration inputs on the host. It doesn't recreate the service's mount namespace or certify file accessibility inside its sandbox. The service must still start successfully. The unit properties, environment files, identity, and candidate config are observed again after validation; changes cause refusal and require a retry.

Only `pipelock` and `pipelock.service` are supported. This mode requires a config file path and can't be combined with `--url`. It refuses stale or transient units, nonempty `PassEnvironment`, PAM, dynamic users, credential directives, pre-start or condition commands, root images/directories, custom working directories, primary-group overrides that differ from the account's primary group, and environment-file globs. Successful introspection and the running manager's version determine which newer directives an older manager supports. Present properties require successful typed reads; missing baseline properties cause refusal. Systemd 255 without an explicit `User=` also causes refusal when its login-environment property is ambiguous. Run `systemctl daemon-reload` after editing unit definitions before checking again.

Each observation and input file has a local 64 KiB resource limit. Child output is withheld because config errors can quote secrets. To inspect ordinary config diagnostics separately, use `pipelock check --config /etc/pipelock/pipelock.yaml` in an environment you control; its output can contain configuration values.

`contain install` uses the same validator for its early config preflight. On a first install with no loaded unit, that check uses the manager baseline and planned service identity. After writing the prospective unit and reloading systemd, install validates again against that loaded unit before starting or restarting the service. A failed prospective check rolls back the attempted install.
