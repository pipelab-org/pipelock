#!/usr/bin/env bash
# Copyright 2026 Pipelock contributors
# SPDX-License-Identifier: Apache-2.0

verify_accepts_and_rejects() {
	local label="$1"
	local receipt="$2"
	local payload_tampered="$3"
	local signature_tampered="$4"
	local public_key="$5"
	shift 5
	if ! "$@" "$receipt" --key "$public_key" >/dev/null; then
		printf 'release verifier install gate: %s rejected the candidate receipt\n' "$label" >&2
		return 1
	fi
	if "$@" "$payload_tampered" --key "$public_key" >/dev/null 2>&1; then
		printf 'release verifier install gate: %s ACCEPTED the payload-tampered candidate receipt\n' "$label" >&2
		return 1
	fi
	if "$@" "$signature_tampered" --key "$public_key" >/dev/null 2>&1; then
		printf 'release verifier install gate: %s ACCEPTED the signature-tampered candidate receipt\n' "$label" >&2
		return 1
	fi
	printf '  [ok] %s accepts candidate receipt and rejects payload/signature tampering\n' "$label"
}

require_npm_attestations() {
	local npm_version
	if ! npm_version="$(npm --version)"; then
		printf 'release verifier install gate: could not read npm version\n' >&2
		return 1
	fi
	# npm/cli v11.12.0 added audit --include-attestations (npm/cli#9049).
	python3 - "$npm_version" <<'PY'
import re
import sys

version = sys.argv[1]
if not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", version):
    raise SystemExit(f"release verifier install gate: cannot parse npm version {version!r}")
if tuple(map(int, version.split("."))) < (11, 12, 0):
    raise SystemExit(f"release verifier install gate: npm {version} is too old; need npm >= 11.12.0 for verified attestation output; use a newer Node.js/npm toolchain")
PY
}

verify_npm_provenance() {
	python3 - "$@" <<'PY'
import base64
import json
import sys

version, integrity, source_ref, source_commit, repository, report_path = sys.argv[1:]
# npm's --include-attestations report contains the bundles it verified, unlike
# a separate registry response fetched after signature auditing.
with open(report_path, encoding="utf-8") as fh:
    report = json.load(fh)
if report.get("invalid") or report.get("missing"):
    raise SystemExit("npm signature audit has invalid or missing signatures")
verified = [package for package in report.get("verified", [])
            if package.get("name") == "@pipelock/verifier-ts"
            and package.get("version") == version]
if len(verified) != 1:
    raise SystemExit(f"expected one verified npm package, found {len(verified)}")
attestations = verified[0].get("attestationBundles", [])
statements = []
for attestation in attestations:
    envelope = attestation.get("bundle", {}).get("dsseEnvelope", {})
    payload = envelope.get("payload")
    if payload:
        statements.append(json.loads(base64.b64decode(payload)))
matches = [statement for statement in statements if statement.get("predicateType") == "https://slsa.dev/provenance/v1"]
if len(matches) != 1:
    raise SystemExit(f"expected one npm SLSA provenance statement, found {len(matches)}")
statement = matches[0]
expected_digest = base64.b64decode(integrity.removeprefix("sha512-")).hex()
subject = statement.get("subject", [])
if len(subject) != 1 or subject[0].get("name") != f"pkg:npm/%40pipelock/verifier-ts@{version}" or subject[0].get("digest", {}).get("sha512") != expected_digest:
    raise SystemExit("npm provenance subject does not bind the pinned package digest")
definition = statement.get("predicate", {}).get("buildDefinition", {})
workflow = definition.get("externalParameters", {}).get("workflow", {})
expected_workflow = {
    "ref": f"refs/tags/{source_ref}",
    "repository": f"https://github.com/{repository}",
    "path": ".github/workflows/publish-verifiers.yaml",
}
if workflow != expected_workflow:
    raise SystemExit(f"npm provenance workflow mismatch: {workflow!r}")
dependencies = definition.get("resolvedDependencies", [])
if not any(
    dependency.get("uri") == f"git+https://github.com/{repository}@refs/tags/{source_ref}"
    and dependency.get("digest", {}).get("gitCommit") == source_commit
    for dependency in dependencies
):
    raise SystemExit("npm provenance does not bind the pinned source commit")
PY
}

verify_tagged_verifier_repository() {
	python3 - "$@" <<'PY'
import json
import subprocess
import sys
import tomllib

root, commit, repository = sys.argv[1:]
ts = json.loads(subprocess.check_output([
    "git", "-C", root, "show", f"{commit}:sdk/verifiers/ts/package.json",
], text=True))
rust = tomllib.loads(subprocess.check_output([
    "git", "-C", root, "show", f"{commit}:sdk/verifiers/rust/Cargo.toml",
], text=True))
if ts.get("repository", {}).get("url") != f"git+https://github.com/{repository}.git" or rust.get("package", {}).get("repository") != f"https://github.com/{repository}":
    raise SystemExit("tagged verifier package repository does not match publisher")
PY
}
