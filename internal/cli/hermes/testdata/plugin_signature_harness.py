#!/usr/bin/env python3
# Copyright 2026 Pipelock contributors
# SPDX-License-Identifier: Apache-2.0

"""Signature regression harness for the pipelock Hermes plugin.

Drives every hook the plugin registers exactly the way Hermes' real dispatcher
does -- ``cb(**kwargs)`` (hermes_cli/plugins.py invoke_hook) -- using the kwarg
set verified against the real Hermes call sites in hermes_agent 0.13.0 and
0.14.0 (identical between the two):

  pre_tool_call          hermes_cli/plugins.py  get_pre_tool_call_block_message()
  transform_tool_result  model_tools.py         tool-dispatch seam
  on_session_start       run_agent.py           run_conversation() new-session
  on_session_end         run_agent.py           run_conversation() teardown
  pre_gateway_dispatch   gateway/run.py          inbound dispatch guard

Why this matters: Hermes wraps each ``cb(**kwargs)`` in a bare ``except
Exception`` that only logs a warning. A hook whose signature rejects a kwarg
Hermes passes raises TypeError, Hermes swallows it, and the scan silently never
runs -- the agent proceeds UNSCANNED (fail-open). This harness turns that
silent runtime failure into a loud CI failure.

Usage: python3 plugin_signature_harness.py <installed-plugin-dir>
Exit 0 = every hook accepts the contract. Non-zero = drift; the message names
the offending hook.
"""

import importlib.util
import io
import json
import logging
import os
import sys
from types import SimpleNamespace
from unittest.mock import patch

# The harness may inspect the source template; never add artifacts to its embed.
sys.dont_write_bytecode = True


class _Event:
    """Minimal stand-in for Hermes' MessageEvent (pre_gateway_dispatch reads
    .text and .sender via getattr)."""

    text = "hello from the gateway"
    sender = "user-123"


# The verified kwarg set Hermes passes to each hook. Keep in sync with the
# Hermes call sites cited in the module docstring; the live-Hermes e2e test
# (Step B) is the durable guard against upstream renames this harness can't see.
HERMES_KWARGS = {
    "pre_tool_call": dict(
        tool_name="terminal",
        args={"command": "echo hi"},
        task_id="task-1",
        session_id="sess-1",
        tool_call_id="call-1",
    ),
    "transform_tool_result": dict(
        tool_name="terminal",
        args={"command": "echo hi"},
        result='{"output": "hi"}',
        task_id="task-1",
        session_id="sess-1",
        tool_call_id="call-1",
        duration_ms=42,
    ),
    "on_session_start": dict(session_id="sess-1", model="gpt-4", platform="cli"),
    "on_session_end": dict(
        session_id="sess-1",
        completed=True,
        interrupted=False,
        model="gpt-4",
        platform="cli",
    ),
    "pre_gateway_dispatch": dict(event=_Event(), gateway=None, session_store=None),
}
EXPECTED_HOOKS = set(HERMES_KWARGS)


class _RecordingCtx:
    """Captures register_hook() calls the way Hermes' PluginContext would."""

    def __init__(self):
        self.hooks = {}

    def register_hook(self, name, cb):
        self.hooks.setdefault(name, []).append(cb)


def _load_plugin(plugin_dir):
    path = os.path.join(plugin_dir, "plugin.py")
    spec = importlib.util.spec_from_file_location("pipelock_plugin_under_test", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _check_transform_contract(mod):
    """Exercise the shipped payload and the actual subprocess decision parser."""
    replacement = "safe [pipelock:masked:aws-access-id] remainder"
    valid = {"decision": "transform", "result": replacement, "reason": "AWS Access ID masked"}
    malformed = [
        {"decision": "transform"},
        {"decision": "transform", "reason": "masked"},
        {"decision": "transform", "result": replacement},
        {"decision": "transform", "result": replacement, "reason": ""},
        *({"decision": "transform", "result": value, "reason": "masked"}
          for value in (None, 1, False, [], {})),
        *({"decision": "transform", "result": replacement, "reason": value}
          for value in (None, 1, False, [], {})),
        {"decision": "unknown"},
        {"reason": "missing decision"},
        {"decision": None},
        {"decision": "block", "reason": {}},
    ]
    invocations = [
        (mod._transform_tool_result, {"result": "original"}, replacement, str),
        (mod._pre_gateway_dispatch, {"event": _Event()},
         {"action": "rewrite", "text": replacement}, dict),
    ]
    for hook, kwargs, expected, expected_type in invocations:
        for response in [valid, *malformed, {}, {"decision": "allow"}]:
            captured = []
            def run(argv, **options):
                captured.append(json.loads(options["input"]))
                return SimpleNamespace(returncode=0, stdout=json.dumps(response).encode(), stderr=b"")
            with patch.object(mod, "_resolve_pipelock", return_value="/synthetic/pipelock"), patch.object(
                mod, "_resolve_config", return_value=None
            ), patch.object(mod.subprocess, "run", side_effect=run):
                got = hook(**kwargs)
            assert captured[0]["capabilities"] == ["transform"], captured
            assert isinstance(captured[0]["tool_input"], str), captured
            if response == valid:
                assert isinstance(got, expected_type) and got == expected, got
            elif response in ({}, {"decision": "allow"}):
                assert got is None, got
            elif expected_type is str:
                assert isinstance(got, str) and "blocked" in got and got != "original", got
            else:
                assert isinstance(got, dict) and got.get("action") == "skip", got

        failures = [
            {"side_effect": mod.subprocess.TimeoutExpired("pipelock", 30)},
            {"side_effect": OSError("cannot start")},
            {"return_value": SimpleNamespace(returncode=1, stdout=json.dumps(valid).encode(), stderr=b"failed")},
            *({"return_value": SimpleNamespace(returncode=0, stdout=output, stderr=b"")}
              for output in (b"", b"not json", b"[]", b"null", b"[" * 2000 + b"0" + b"]" * 2000)),
        ]
        for failure in failures:
            with patch.object(mod, "_resolve_pipelock", return_value="/synthetic/pipelock"), patch.object(
                mod, "_resolve_config", return_value=None
            ), patch.object(mod.subprocess, "run", **failure):
                got = hook(**kwargs)
            assert (isinstance(got, str) and "blocked" in got) if expected_type is str else got.get("action") == "skip", got

    # A structured result must not advertise or accept a string transform.
    captured = []
    def structured_run(argv, **options):
        captured.append(json.loads(options["input"]))
        return SimpleNamespace(returncode=0, stdout=json.dumps(valid).encode(), stderr=b"")
    with patch.object(mod, "_resolve_pipelock", return_value="/synthetic/pipelock"), patch.object(
        mod, "_resolve_config", return_value=None
    ), patch.object(mod.subprocess, "run", side_effect=structured_run):
        got = mod._transform_tool_result(result={"output": "original"})
        outbound = mod._pre_tool_call(args="original")
    assert captured[0]["capabilities"] == [] and isinstance(got, str) and "blocked" in got, got
    assert "capabilities" not in captured[1] and outbound["action"] == "block", outbound


def main():
    if len(sys.argv) != 2:
        print("usage: plugin_signature_harness.py <plugin-dir>", file=sys.stderr)
        return 2
    plugin_dir = sys.argv[1]

    # Point PIPELOCK_BIN at a path that is not a file so _resolve_pipelock()
    # returns None and the hooks never spawn a subprocess. We are testing the
    # signature boundary, not scan behavior, so this keeps the harness hermetic
    # and fast.
    os.environ["PIPELOCK_BIN"] = "/nonexistent/pipelock-signature-harness"

    mod = _load_plugin(plugin_dir)
    ctx = _RecordingCtx()
    mod.register(ctx)

    registered = set(ctx.hooks)
    if registered != EXPECTED_HOOKS:
        print(
            "FAIL: registered hooks {} != expected {}".format(
                sorted(registered), sorted(EXPECTED_HOOKS)
            ),
            file=sys.stderr,
        )
        return 1

    for name, kwargs in HERMES_KWARGS.items():
        for cb in ctx.hooks[name]:
            try:
                cb(**kwargs)
            except TypeError as exc:
                print(
                    "FAIL: hook {} rejected Hermes kwargs {}: {}".format(
                        name, sorted(kwargs), exc
                    ),
                    file=sys.stderr,
                )
                return 1
            except Exception as exc:  # noqa: BLE001 - any escape is a real bug
                print(
                    "FAIL: hook {} raised {}: {}".format(
                        name, type(exc).__name__, exc
                    ),
                    file=sys.stderr,
                )
                return 1

    # Success must retain the hook's operator record without changing allow.
    record = "pipelock: warning: number-only JSON card run detected (action=warn)"
    logs = io.StringIO()
    logger = logging.getLogger(mod.__name__)
    handler = logging.StreamHandler(logs)
    logger.addHandler(handler)
    try:
        for stderr in (b"", record.encode("utf-8")):
            logs.truncate(0)
            logs.seek(0)
            with patch.object(mod, "_resolve_pipelock", return_value="/synthetic/pipelock"), patch.object(
                mod, "_resolve_config", return_value=None
            ), patch.object(mod.subprocess, "run", return_value=SimpleNamespace(
                returncode=0, stdout=b"{}", stderr=stderr
            )):
                decision = mod._invoke({"hook_event_name": "transform_tool_result"})
            if decision != {} or (stderr and logs.getvalue().count(record) != 1) or (not stderr and logs.getvalue()):
                print("FAIL: successful hook warning was lost or altered allow", file=sys.stderr)
                return 1
    finally:
        logger.removeHandler(handler)

    _check_transform_contract(mod)

    captured = []
    mod._invoke = lambda payload: captured.append(payload) or {"decision": "allow"}
    ctx.hooks["transform_tool_result"][0](
        tool_name="terminal",
        args={"command": "rg Memory Persistence Directive"},
        result={"output": "safe diagnostic result"},
    )
    if captured[-1]["tool_input"] != {"output": "safe diagnostic result"}:
        print(
            "FAIL: transform_tool_result must scan only the returned result",
            file=sys.stderr,
        )
        return 1

    print("OK: all hooks accept the Hermes kwarg contract")
    return 0


if __name__ == "__main__":
    sys.exit(main())
