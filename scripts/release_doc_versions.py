#!/usr/bin/env python3
# Copyright 2026 Pipelock contributors
# SPDX-License-Identifier: Apache-2.0

"""Reject stale current-release references in Pipelock operator documentation.

Release surfaces and their inclusion or exclusion reasons live in
release/surfaces.json. Historical evidence keeps its measured version; current
operator instructions follow the chart appVersion.
"""

from __future__ import annotations

import argparse
import fnmatch
import hashlib
import json
import re
import shlex
import subprocess
import sys
import tomllib
from pathlib import Path


RELEASE_TAG_RE = re.compile(
    r"^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)"
    r"(?:-((?:0|[1-9][0-9]*|[0-9]*[A-Za-z-][0-9A-Za-z-]*)"
    r"(?:\.(?:0|[1-9][0-9]*|[0-9]*[A-Za-z-][0-9A-Za-z-]*))*))?$"
)
VERSION_RE = re.compile(
    r"v?(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)"
    r"(?:-(?:0|[1-9][0-9]*|[0-9]*[A-Za-z-][0-9A-Za-z-]*)"
    r"(?:\.(?:0|[1-9][0-9]*|[0-9]*[A-Za-z-][0-9A-Za-z-]*))*)?"
)

SURFACE_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    (
        "git clone release branch",
        re.compile(
            r"git\s+clone(?=[^\n]*https://github\.com/(?:luckyPipewrench|pipelab-org)/pipelock(?:\.git)?(?![A-Za-z0-9_.-]))"
            r"[^\n]*?(?:--branch(?:=|\s+)|-b\s+)(?P<version>[^\s]+)"
        ),
    ),
    (
        "Docker image tag",
        re.compile(
            r"ghcr\.io/(?:luckypipewrench|pipelab-org)/pipelock(?:-init|-license-service)?:(?P<version>[0-9A-Za-z._+-]+)"
        ),
    ),
    (
        "Helm chart version",
        re.compile(
            r"helm\s+(?:install|upgrade|pull)\b[^\n]*?"
            r"oci://ghcr\.io/(?:luckypipewrench|pipelab-org)/charts/pipelock[^\n]*?"
            r"--version\s+(?P<version>[0-9A-Za-z._+-]+)"
        ),
    ),
    (
        "GitHub Action tag",
        re.compile(r"uses:\s*(?:luckyPipewrench|pipelab-org)/pipelock(?:/[^@\s]+)?@(?P<version>v?[0-9][^\s`\"']*)"),
    ),
    (
        "release archive URL",
        re.compile(
            r"https://github\.com/(?:luckyPipewrench|pipelab-org)/pipelock/releases/download/"
            r"(?P<tag>[^/\s`\"']+)/pipelock(?:-verifier)?_(?P<version>[^/_\s`\"']+)"
            r"_(?:linux|darwin|windows)_"
        ),
    ),
    (
        "release archive filename",
        re.compile(r"\bpipelock(?:-verifier)?_(?P<version>[^/_\s`\"']+)_(?:linux|darwin|windows)_"),
    ),
    (
        "GitHub Action version comment",
        re.compile(
            r"uses:\s*(?:luckyPipewrench|pipelab-org)/pipelock(?:/[^@\s]+)?@"
            r"[0-9a-fA-F]{40}\s+#\s*(?P<version>v?[^\s]+)"
        ),
    ),
)

HEALTH_VERSION = re.compile(
    r'"version"\s*:\s*"(?P<version>[^"\s]+)"'
)

REQUIRED_SURFACES = (
    "git clone release branch",
    "Docker image tag",
    "Helm chart version",
    "release archive URL",
    "GitHub Action version comment",
    "health response version",
)


def _docs_files(root: Path) -> list[Path]:
    candidates = [root / "README.md"]
    for directory in (root / "docs", root / "examples", root / ".github" / "workflows"):
        if directory.is_dir():
            candidates.extend(path for path in directory.rglob("*") if path.is_file())
    candidates.append(root / "action.yml")

    files: list[Path] = []
    for path in candidates:
        if not path.is_file():
            continue
        relative = path.relative_to(root).as_posix()
        lowered = relative.lower()
        if path.name.lower().startswith("changelog") or path.name.lower() == "changes.md":
            continue
        if "/benchmark" in lowered or lowered.startswith("benchmarks/"):
            continue
        if path.suffix.lower() not in {".md", ".yml", ".yaml", ".sh", ".json", ".toml"}:
            continue
        files.append(path)
    return sorted(set(files))


def check_document_versions(root: Path, release_tag: str) -> list[str]:
    if not RELEASE_TAG_RE.fullmatch(release_tag):
        return [
            f"release-doc-version: malformed release tag {release_tag!r}; "
            "expected vMAJOR.MINOR.PATCH[-prerelease]"
        ]

    expected_bare = release_tag[1:]
    observed: dict[str, int] = {surface: 0 for surface in REQUIRED_SURFACES}
    issues: list[str] = []

    for path in _docs_files(root):
        relative = path.relative_to(root).as_posix()
        try:
            lines = path.read_text(encoding="utf-8").splitlines()
        except (OSError, UnicodeError) as error:
            return [f"release-doc-version: cannot read {relative}: {error}"]

        logical_lines: list[tuple[int, str]] = []
        pending = ""
        first_line = 1
        for number, line in enumerate(lines, start=1):
            if not pending:
                first_line = number
            pending += line.rstrip().removesuffix("\\") + " "
            if line.rstrip().endswith("\\"):
                continue
            logical_lines.append((first_line, pending))
            pending = ""
        if pending:
            logical_lines.append((first_line, pending))

        # Folded YAML joins ordinary equally-indented lines, but preserves
        # blank and more-indented lines. Keep physical lines too, so malformed
        # or unsupported scalar shapes cannot conceal an already-visible pin.
        for index, source in enumerate(lines):
            header = re.match(r"^(\s*)(?:-\s+)?[\w-]+:\s*>[+-]?[1-9]?[+-]?\s*(?:#.*)?$", source)
            if not header:
                continue
            header_indent = len(header.group(1))
            block: list[tuple[int, str]] = []
            for offset, body in enumerate(lines[index + 1:], start=index + 2):
                if body.strip() and len(body) - len(body.lstrip()) <= header_indent:
                    break
                block.append((offset, body))
            indent = min((len(body) - len(body.lstrip()) for _, body in block if body.strip()), default=0)
            folded = ""
            first = index + 2
            for number, body in block:
                if not body.strip() or len(body) - len(body.lstrip()) > indent:
                    if folded:
                        logical_lines.append((first, folded))
                    folded = ""
                    logical_lines.append((number, body))
                    continue
                if not folded:
                    first = number
                folded += body.strip() + " "
            if folded:
                logical_lines.append((first, folded))

        for number, line in logical_lines:
            references: list[tuple[str, str, bool | None]] = []
            for command in re.finditer(r"\bgh\s+release\s+download\s+([^;|&\n]+)", line):
                try:
                    arguments = shlex.split(command.group(1), comments=True)
                except ValueError:
                    issues.append(f"{relative}:{number}: malformed release download command")
                    continue
                skip_value = False
                for argument in arguments:
                    if skip_value:
                        skip_value = False
                        continue
                    if argument in {"--repo", "-R", "--pattern", "-p", "--dir", "-D", "--archive", "-A"}:
                        skip_value = True
                        continue
                    if argument.startswith("-"):
                        if argument not in {"--", "--clobber", "--skip-existing"} and not any(
                            argument.startswith(option + "=") for option in {"--repo", "--pattern", "--dir", "--archive"}
                        ) and not argument.startswith(("-R", "-p", "-D", "-A")):
                            issues.append(f"{relative}:{number}: unsupported release download option {argument!r}")
                        continue
                    references.append(("release download command", argument.removesuffix("."), True))
                    break
            for surface, pattern in SURFACE_PATTERNS:
                for match in pattern.finditer(line):
                    if surface == "release archive URL":
                        references.append((surface, match.group("tag"), True))
                    references.append((surface, match.group("version").removesuffix("."), surface in {"git clone release branch", "GitHub Action version comment", "GitHub Action tag", "release download command"}))

            if relative == "docs/guides/health.md":
                for match in HEALTH_VERSION.finditer(line):
                    references.append(("health response version", match.group("version"), None))

            for surface, reference, prefixed in references:
                reference = reference.strip("\"'`").removesuffix(".")
                if surface == "GitHub Action tag" and re.fullmatch(r"[0-9a-fA-F]{40}", reference):
                    continue
                # Generic placeholders and intentional floating tags such as
                # `latest` are not current-version pins. A numeric-looking
                # malformed value remains recognized and fails closed.
                if not re.match(r"^[vV0-9]", reference):
                    continue
                observed[surface] = observed.get(surface, 0) + 1
                # A recognized numeric reference with malformed SemVer must
                # fail instead of disappearing from the version comparison.
                if not VERSION_RE.fullmatch(reference):
                    issues.append(
                        f"{relative}:{number}: {surface} has malformed version {reference!r}; "
                        f"expected {release_tag}"
                    )
                    continue
                if prefixed is not None and reference.startswith("v") != prefixed:
                    issues.append(f"{relative}:{number}: {surface} has incorrect v prefix {reference!r}; expected {release_tag if prefixed else expected_bare}")
                    continue
                normalized = reference[1:] if reference.startswith("v") else reference
                if normalized != expected_bare:
                    issues.append(
                        f"{relative}:{number}: {surface} pins {reference!r}, "
                        f"expected {release_tag if reference.startswith('v') else expected_bare}"
                    )

    for surface, count in observed.items():
        if count == 0:
            issues.append(f"missing required current-release surface: {surface}")

    return issues


REGISTRY = "release/surfaces.json"
# SemVer candidates, including malformed numeric pins caught by the existing
# installation recognizers. A final prose period is not part of a version.
DISCOVER_VERSION = re.compile(
    r"(?<![A-Za-z0-9.])v?[0-9]+\.[0-9]+\.[0-9]+"
    r"(?:-[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?(?![A-Za-z0-9]|\.[0-9])"
)
# These are the public count phrases used by the README and operator docs,
# not a claim to recognize arbitrary numerical assertions in natural language.
DISCOVER_FIGURE = re.compile(
    r"(?<![\w.%])[0-9][0-9,]*(?:\.[0-9]+)?\+?(?=%|\s+(?:(?:built-in|"
    r"credential|prompt-injection|and|state/control|poisoning|category-axis|DLP|"
    r"regex|attack|unit|integration|end-to-end|direct|YAML|config|response|chain|"
    r"security|state/control-poisoning|preset)\s+)*(?:patterns|tests|cases|categories|dependencies|presets|files|requests)\b)"
)


def _inside(root: Path, relative: str) -> Path:
    path = root / relative
    if Path(relative).is_absolute() or not path.resolve().is_relative_to(root.resolve()):
        raise ValueError(f"registry path escapes repository: {relative}")
    return path


def _load_registry(root: Path) -> dict:
    def unique_keys(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError(f"duplicate registry key: {key}")
            result[key] = value
        return result

    registry = json.loads(_inside(root, REGISTRY).read_text(encoding="utf-8"), object_pairs_hook=unique_keys)
    if not isinstance(registry, dict) or type(registry.get("schema_version")) is not int or registry["schema_version"] != 1:
        raise ValueError("unsupported release surface registry schema")
    for name, kind in (("sources", dict), ("scan", dict), ("surfaces", list), ("external", list)):
        if not isinstance(registry.get(name), kind) or not registry[name]:
            raise ValueError(f"registry must declare nonempty {name}")
    return registry


def _source_values(root: Path, registry: dict, release_tag: str | None) -> dict[str, str]:
    values = {}
    for name, source in registry["sources"].items():
        text = _inside(root, source["path"]).read_text(encoding="utf-8")
        if "json" in source:
            value = json.loads(text)
            for key in source["json"]:
                value = value[key]
        elif "toml" in source:
            value = tomllib.loads(text)
            for key in source["toml"]:
                value = value[key]
        else:
            matches = list(re.finditer(source["pattern"], text, re.MULTILINE))
            if len(matches) != 1:
                raise ValueError(f"source {name} must match exactly once")
            value = matches[0].group("value")
        if not isinstance(value, str) or not VERSION_RE.fullmatch(value):
            raise ValueError(f"source {name} has malformed version {value!r}")
        values[name] = value
    if release_tag is not None:
        values["product"] = release_tag[1:]
    return values


def _canonical_stats(root: Path) -> dict[str, str]:
    # Use the existing runtime-derived stats contract instead of counting Go
    # source with a second implementation. Keep the test process exit status;
    # make stats pipes through grep, which cannot establish that it passed.
    result = subprocess.run(
        ["go", "test", "-count=1", "-run", "^TestCanonicalStats$", "-v", "./internal/config/"],
        cwd=root, capture_output=True, text=True, timeout=120,
    )
    if result.returncode != 0 or "--- PASS: TestCanonicalStats" not in result.stdout:
        raise ValueError("canonical stats test did not pass: " + result.stdout + result.stderr)
    labels = ("DLP patterns", "Response patterns", "Chain patterns", "Preset files", "Direct deps")
    values = {}
    for label in labels:
        matches = re.findall(re.escape(label) + r":\s+([0-9]+)\b", result.stdout)
        if len(matches) != 1:
            raise ValueError(f"canonical stats missing or repeated: {label}")
        values[f"stats:{label}"] = matches[0]
    return values


def check_registry(root: Path, registry: dict, values: dict[str, str]) -> list[str]:
    issues = []
    contents: dict[str, str] = {}
    covered: dict[str, set[tuple[int, int]]] = {}
    if any(entry["expected"].startswith("stats:") for entry in registry["surfaces"]):
        values.update(_canonical_stats(root))
    identifiers = set()
    for entry in registry["surfaces"]:
        identifier, relative = entry["id"], entry["path"]
        if identifier in identifiers or not entry["reason"].strip():
            raise ValueError(f"duplicate surface id or missing reason: {identifier}")
        identifiers.add(identifier)
        if entry.get("format") not in (None, "number", "version", "sha256"):
            raise ValueError(f"unsupported surface format: {identifier}")
        if not isinstance(entry["expected"], str) or not entry["expected"]:
            raise ValueError(f"surface {identifier} needs an expected value or source")
        if type(entry["count"]) is not int or entry["count"] < 1:
            raise ValueError(f"surface {identifier} needs a positive occurrence count")
        if relative not in contents:
            contents[relative] = _inside(root, relative).read_text(encoding="utf-8")
        text = contents[relative]
        pattern = re.compile(entry["pattern"], re.MULTILINE)
        if "value" not in pattern.groupindex:
            raise ValueError(f"surface {identifier} needs a named value capture")
        spans = covered.setdefault(relative, set())
        # Specific historical exceptions precede a file's current-release rule.
        # Every numeric token is assigned once, and count checks catch removals
        # and additional references even when they carry the correct value.
        matches = [match for match in pattern.finditer(text) if match.span("value") not in spans]
        if len(matches) != entry["count"]:
            issues.append(f"{relative}: {identifier} matched {len(matches)} times, expected {entry['count']}; update the release surface inventory")
        if entry["expected"].startswith("stats:") and entry["expected"] not in values:
            raise ValueError(f"unknown canonical stat: {entry['expected']}")
        expected = values.get(entry["expected"], entry["expected"])
        if entry["expected"].startswith("source:"):
            key = entry["expected"].removeprefix("source:")
            expected = values[key]
        for match in matches:
            spans.add(match.span("value"))
            actual = match.group("value")
            if entry.get("format") == "sha256":
                actual = hashlib.sha256(actual.encode("utf-8")).hexdigest()
            if entry.get("format") == "version":
                actual = actual.removeprefix("v")
            if actual != expected:
                number = text.count("\n", 0, match.start("value")) + 1
                issues.append(f"{relative}:{number}: {identifier} has {actual!r}, expected {expected!r} ({entry['reason']})")

    scan = registry["scan"]
    files = set()
    for relative in scan["roots"]:
        path = _inside(root, relative)
        if not path.exists():
            raise ValueError(f"inventory scan root is missing: {relative}")
        files.update([path] if path.is_file() else path.rglob("*"))
    for path in sorted(files):
        if not path.is_file() or path.suffix not in scan["suffixes"]:
            continue
        relative = path.relative_to(root).as_posix()
        if any(fnmatch.fnmatchcase(relative, item["glob"]) for item in scan["exclude"]):
            continue
        text = contents.get(relative)
        if text is None:
            text = _inside(root, relative).read_text(encoding="utf-8")
        spans = covered.get(relative, set())
        for pattern in (DISCOVER_VERSION, DISCOVER_FIGURE):
            for match in pattern.finditer(text):
                if not any(start <= match.start() and match.end() <= end for start, end in spans):
                    number = text.count("\n", 0, match.start()) + 1
                    issues.append(f"{relative}:{number}: unregistered release/public-number surface {match.group()!r}; add its source or historical exclusion to {REGISTRY}")
    for item in scan["exclude"]:
        if not item["reason"].strip():
            raise ValueError("inventory exclusion needs a reason")
    for item in registry["external"]:
        if not all(item.get(key) for key in ("id", "owner", "url", "reason")):
            raise ValueError("external surface needs id, owner, url and reason")
    return issues


def check(root: Path, release_tag: str | None = None) -> list[str]:
    if release_tag is not None and not RELEASE_TAG_RE.fullmatch(release_tag):
        return [f"release-doc-version: malformed release tag {release_tag!r}; expected vMAJOR.MINOR.PATCH[-prerelease]"]
    try:
        registry = _load_registry(root)
        values = _source_values(root, registry, release_tag)
        tag = release_tag or "v" + values["product"]
        issues = check_document_versions(root, tag)
        issues.extend(check_registry(root, registry, values))
        return issues
    except (OSError, UnicodeError, ValueError, KeyError, IndexError, TypeError, AttributeError, re.error, subprocess.SubprocessError) as error:
        return [f"release-doc-version: invalid or unreadable surface inventory: {error}"]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("repository", type=Path)
    parser.add_argument("release_tag", nargs="?", help="defaults to the registered chart appVersion")
    parser.add_argument("--print-product-version", action="store_true", help="print only the product version after all checks pass")
    args = parser.parse_args(argv)

    issues = check(args.repository.resolve(), args.release_tag)
    if issues:
        print("release-doc-version: FAILED", file=sys.stderr)
        for issue in issues:
            print(f"  [FAIL] {issue}", file=sys.stderr)
        return 1
    if args.print_product_version:
        print(_source_values(args.repository.resolve(), _load_registry(args.repository.resolve()), args.release_tag)["product"])
    else:
        print(f"release-doc-version: OK ({args.release_tag or 'registered source versions'}; {REGISTRY})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
