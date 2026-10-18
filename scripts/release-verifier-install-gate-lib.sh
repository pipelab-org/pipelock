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

verify_npm_provenance() {
	python3 - "$@" <<'PY'
import base64
import json
import sys

version, integrity, source_ref, source_commit, repository, attestation_path = sys.argv[1:]
with open(attestation_path, encoding="utf-8") as fh:
    attestations = json.load(fh).get("attestations", [])
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
