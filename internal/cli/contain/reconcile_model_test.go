// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package contain

import (
	"context"
	"fmt"
	"os"
	"strings"
	"testing"
)

// nftListingForTest supplies handles the real -a query always returns. It
// leaves existing handles intact, including deliberately malformed fixtures.
func nftListingForTest(body string) string {
	body = strings.ReplaceAll(body, "chain output_filter { type", "chain output_filter {\n type")
	var lines []string
	handle := 1000
	for _, rule := range nftRulesWithHandles(body) {
		if rule.handle >= handle {
			handle = rule.handle + 1
		}
	}
	for _, raw := range strings.Split(body, "\n") {
		line := strings.TrimSpace(raw)
		fields := nftLineFields(line)
		if len(fields) > 0 && !strings.Contains(line, "# handle") {
			switch fields[0] {
			case "meta", "ip", "ip6", "accept", "return", "jump", "goto", "queue", "counter":
				line += fmt.Sprintf(" # handle %d", handle)
				handle++
			}
		}
		lines = append(lines, line)
	}
	return strings.Join(lines, "\n")
}

func applyNFTScriptForTest(live, script string) (string, error) {
	start := strings.Index(script, "# Pipelock containment ruleset")
	if start < 0 {
		return "", fmt.Errorf("missing canonical nft body in transaction")
	}
	survivors, err := applyNFTDeletionsForTest(nftListingForTest(live), script[:start])
	if err != nil {
		return "", err
	}
	return strings.Join(append(survivors, nftListingFromRulesBodyForTest(script[start:], 10000)), "\n"), nil
}

// Existing reload orchestration tests inject command failures. Model a
// successful batch as a real commit so post-apply observation tests execution,
// rather than repeatedly returning a frozen pre-apply fixture.
func reloadNFTForTest(t *testing.T, ctx context.Context, env *nftReloadEnv) error {
	t.Helper()
	run, write := env.runCmd, env.writeFile
	var live, script string
	applied := false
	env.writeFile = func(path string, data []byte, mode os.FileMode) error {
		if path == env.rulesPath+".reload" {
			script = string(data)
		}
		return write(path, data, mode)
	}
	env.runCmd = func(ctx context.Context, name string, args ...string) (string, int, error) {
		out, code, err := run(ctx, name, args...)
		if len(args) >= 4 && strings.Join(args[:4], " ") == "-n -a list chain" {
			if applied {
				return live, 0, nil
			}
			live = nftListingForTest(out)
			return live, code, err
		}
		if len(args) == 2 && args[0] == "-f" && code == 0 && err == nil {
			live, err = applyNFTScriptForTest(live, script)
			applied = err == nil
		}
		return out, code, err
	}
	defer func() { env.runCmd, env.writeFile = run, write }()
	return reloadNFTRules(ctx, env)
}

// Compatibility adapters keep the renderer boundary fixtures on the shared
// planner. Production has no independent shape-based reload or no-op matcher.
func renderNFTManagedChainReloadScript(live, body, table, chain string, operator, proxy, agent int, _ bool, prior ...nftRulesHeaderUIDs) string {
	return planNFTReconciliation(nftReconcilePolicy{
		rules: body, table: table, chain: chain,
		uids: nftRulesHeaderUIDs{operatorUID: operator, proxyUID: proxy, agentUID: agent}, prior: prior,
	}, nftReconcileObservation{live: nftListingForTest(live)}).script
}

func legacyManagedNFTRuleBlockHandles(live string, operator, proxy, agent int) []int {
	rules := nftRulesWithHandles(live)
	var handles []int
	for i := 0; i < len(rules); {
		if marker, reserved := nftRuleOwnership(rules[i].line); reserved && strings.HasPrefix(marker, nftOwnershipPrefix+"v1:") {
			handles = append(handles, rules[i].handle)
			i++
			continue
		}
		length := completeLegacyNFTBlockLength(rules, i, nftRulesHeaderUIDs{operatorUID: operator, proxyUID: proxy, agentUID: agent})
		if length == 0 {
			i++
			continue
		}
		for _, rule := range rules[i : i+length] {
			handles = append(handles, rule.handle)
		}
		i += length
	}
	return handles
}

func managedNFTBlockLength(rules []nftRuleWithHandle, at, operator, proxy, agent int) int {
	return completeLegacyNFTBlockLength(rules, at, nftRulesHeaderUIDs{operatorUID: operator, proxyUID: proxy, agentUID: agent})
}

func liveNFTContainmentMatches(live, chain string, operator, proxy, agent, port int) bool {
	policy := nftReconcilePolicy{
		rules: renderNFTRules(operator, proxy, agent, port, defaultNFTTable, chain), table: defaultNFTTable, chain: chain,
		uids: nftRulesHeaderUIDs{operatorUID: operator, proxyUID: proxy, agentUID: agent, proxyPort: port},
	}
	plan := planNFTReconciliation(policy, nftReconcileObservation{live: live})
	return plan.err() == nil && !plan.kernelChanged
}

func reloadNFTManagedChain(ctx context.Context, env *installEnv, body string, operator, proxy, agent int, prior ...nftRulesHeaderUIDs) error {
	live, code, err := env.runCmd(ctx, nftExecutable(env), "-n", "-a", "list", "chain", "inet", env.nftTableOrDefault(), env.nftChainOrDefault())
	if err != nil || code != 0 {
		return fmt.Errorf("list nft managed chain for reload exit=%d: %w", code, err)
	}
	policy := nftReconcilePolicy{rules: body, table: env.nftTableOrDefault(), chain: env.nftChainOrDefault(), uids: nftRulesHeaderUIDs{operatorUID: operator, proxyUID: proxy, agentUID: agent}, prior: prior}
	_, err = executeNFTPlan(ctx, nftPlanExecutor{nftExecutable(env), env.nftRulesPath, env.runCmd, env.writeFile, env.removeFile, env.readFile}, policy, planNFTReconciliation(policy, nftReconcileObservation{live: live}))
	return err
}
