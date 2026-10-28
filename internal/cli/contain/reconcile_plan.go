// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package contain

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"slices"
	"strconv"
	"strings"
)

// nft(8), RULES, specifies the rule comment attribute and handle-based
// deletion. These versioned comments reserve ownership, not packet semantics.
// The role vocabulary follows renderNFTRulesWithServices. Unknown versions or
// roles are conflicts: an older binary must not claim a newer rule contract.
const nftOwnershipPrefix = "pipelock:contain:"

var nftManagedRoles = []string{
	"listener-guard", "operator", "proxy", "proxy-loopback", "dns-udp", "dns-tcp", "agent-drop",
}

type nftReconcilePolicy struct {
	rules        string
	uids         nftRulesHeaderUIDs
	prior        []nftRulesHeaderUIDs
	table, chain string
	doorways     []string
	files        []reconcileManagedFile
}

type reconcileManagedFile struct {
	path string
	body string
	mode os.FileMode
}

type nftReconcileObservation struct {
	persisted, live string
	doorways        []string
	files           map[string]reconcileObservedFile
}

type nftReconcilePlan struct {
	rules, script              string
	fileChanged, kernelChanged bool
	removed                    int
	conflicts                  []string
	foreign                    []nftRuleWithHandle
	closeDoorways              []string
	hadChain                   bool
	writePaths                 map[string]bool
}

func (p nftReconcilePlan) err() error {
	if len(p.conflicts) == 0 {
		return nil
	}
	return fmt.Errorf("nft reconciliation conflict: %s", strings.Join(p.conflicts, "; "))
}

// planNFTReconciliation is pure. It never promotes a fragment into ownership.
// Only explicit markers and the complete ordered legacy renderer contract
// authorize deletion. Persistence is an observation, not proof of live state.
func planNFTReconciliation(policy nftReconcilePolicy, observation nftReconcileObservation) nftReconcilePlan {
	p := nftReconcilePlan{rules: policy.rules, fileChanged: observation.persisted != policy.rules, hadChain: observation.live != "", writePaths: make(map[string]bool)}
	for _, file := range policy.files {
		observed, ok := observation.files[file.path]
		if !ok || observed.err != nil || string(observed.data) != file.body {
			p.writePaths[file.path] = true
		}
	}
	for _, unit := range observation.doorways {
		if !slices.Contains(policy.doorways, unit) && !slices.Contains(p.closeDoorways, unit) {
			p.closeDoorways = append(p.closeDoorways, unit)
		}
	}
	slices.Sort(p.closeDoorways)
	// nft(8), --handle: each rule in a list query has a handle. A partial
	// observation cannot authorize an exact no-op or handle-based replacement.
	for _, line := range strings.Split(observation.live, "\n") {
		fields := nftLineFields(line)
		if len(fields) == 0 || slices.Contains([]string{"table", "chain", "type", "}"}, fields[0]) {
			continue
		}
		if !nftHandlePattern.MatchString(line) {
			p.conflicts = append(p.conflicts, fmt.Sprintf("rule handle missing (%s); inspect `nft -n -a list chain inet %s %s` and restore a complete observation before retrying", strings.TrimSpace(line), policy.table, policy.chain))
		}
	}
	if strings.Contains(observation.live, "table ") {
		lines, err := attributedNFTChainLines(observation.live, policy.chain)
		if err != nil {
			p.conflicts = append(p.conflicts, err.Error())
		} else if !nftChainLinesHaveManagedOutputBaseChain(lines) {
			p.conflicts = append(p.conflicts, "managed chain output hook differs from the installed contract; inspect the chain and rerun `pipelock contain install` after resolving the collision")
		}
	}
	rules := nftRulesWithHandles(observation.live)
	seenHandles := make(map[int]bool)
	for _, rule := range rules {
		if seenHandles[rule.handle] {
			p.conflicts = append(p.conflicts, nftRuleConflict(policy, rule, "duplicate handle in nft observation"))
		}
		seenHandles[rule.handle] = true
	}
	managed := make(map[int]bool)
	var got []string
	for _, rule := range rules {
		marker, reserved := nftRuleOwnership(rule.line)
		if !reserved {
			continue
		}
		role, current := strings.CutPrefix(marker, nftOwnershipPrefix+"v1:")
		if !current || !slices.Contains(nftManagedRoles, role) {
			p.conflicts = append(p.conflicts, nftRuleConflict(policy, rule, "unknown ownership marker"))
			continue
		}
		managed[rule.handle] = true
		got = append(got, canonicalManagedNFTLine(rule.line))
	}
	legacy := false
	for _, uids := range append([]nftRulesHeaderUIDs{policy.uids}, policy.prior...) {
		for i := 0; i < len(rules); {
			length := completeLegacyNFTBlockLength(rules, i, uids)
			if length == 0 {
				i++
				continue
			}
			legacy = true
			for _, rule := range rules[i : i+length] {
				managed[rule.handle] = true
			}
			i += length
		}
	}
	for _, rule := range rules {
		if managed[rule.handle] {
			continue
		}
		p.foreign = append(p.foreign, rule)
		for _, uids := range append([]nftRulesHeaderUIDs{policy.uids}, policy.prior...) {
			if ambiguousNFTRule(rule.line, uids) {
				p.conflicts = append(p.conflicts, nftRuleConflict(policy, rule, "unowned rule overlaps the managed boundary but is not a complete ordered legacy block"))
				break
			}
		}
	}
	if len(rules) > 0 && len(managed) == 0 && len(p.conflicts) == 0 {
		p.conflicts = append(p.conflicts, fmt.Sprintf("existing nft chain inet %s %s is not attributable to Pipelock; preserve its rules and choose an unused managed chain with `pipelock contain install`", policy.table, policy.chain))
	}
	p.kernelChanged = legacy || !slices.Equal(got, managedNFTLinesFromRulesBody(policy.rules))
	// Replacing the managed block appends it after preserved foreign rules.
	// Use the existing listener-guard contract (chainLinesHaveAgentListenerGuard
	// and acceptMayReachAgentListener) to refuse a move that would put an
	// unowned accept ahead of that guard. An exact, already guarded state does
	// not need a replacement and retains its current ordering.
	for _, desired := range managedNFTLinesFromRulesBody(policy.rules) {
		if !lineHasAgentListenerGuardForProxy(desired, policy.uids.proxyUID) {
			continue
		}
		fields := nftLineFields(desired)
		listener := net.JoinHostPort(fields[9], fields[12])
		if !p.kernelChanged && chainLinesHaveAgentListenerGuard(strings.Split(observation.live, "\n"), listener, policy.uids.proxyUID) {
			continue
		}
		for _, rule := range p.foreign {
			if lineHasAnyToken(rule.line, "accept") && acceptMayReachAgentListener(nftLineFields(rule.line), fields[9], fields[12]) {
				p.conflicts = append(p.conflicts, nftRuleConflict(policy, rule, "preserving this unowned accept before the replacement block would bypass the managed listener guard"))
			}
		}
	}
	if !p.kernelChanged || p.err() != nil {
		return p
	}
	var script strings.Builder
	for _, rule := range rules {
		if managed[rule.handle] {
			_, _ = fmt.Fprintf(&script, "delete rule inet %s %s handle %d\n", policy.table, policy.chain, rule.handle)
			p.removed++
		}
	}
	script.WriteString(policy.rules)
	p.script = script.String()
	return p
}

func nftRuleOwnership(line string) (string, bool) {
	fields := nftLineFields(line)
	if len(fields) < 2 || fields[len(fields)-2] != "comment" {
		return "", false
	}
	marker, err := strconv.Unquote(fields[len(fields)-1])
	return marker, err == nil && strings.HasPrefix(marker, nftOwnershipPrefix)
}

func nftRuleConflict(policy nftReconcilePolicy, rule nftRuleWithHandle, reason string) string {
	return fmt.Sprintf("handle %d (%s): %s; inspect `nft -n -a list chain inet %s %s`, then remove only the confirmed obsolete rule with `nft delete rule inet %s %s handle %d` and rerun `pipelock contain reload-nft-rules`", rule.handle, rule.line, reason, policy.table, policy.chain, policy.table, policy.chain, rule.handle)
}

// The migration bound is the existing renderer contract: optional listener
// guard, operator/proxy accepts, proxy-loopback allow, complete service pairs
// (or the old all-forward form), then both DNS drops and the catch-all drop.
// Comments from any owner make this an unowned operator block, not legacy.
func completeLegacyNFTBlockLength(rules []nftRuleWithHandle, start int, uids nftRulesHeaderUIDs) int {
	i := start
	if i < len(rules) && lineHasAgentListenerGuardForProxy(rules[i].line, uids.proxyUID) {
		i++
	}
	if i+2 >= len(rules) || !lineHasTerminalSkuidVerdict(rules[i].line, uids.operatorUID, "accept") ||
		!lineHasTerminalSkuidVerdict(rules[i+1].line, uids.proxyUID, "accept") ||
		!lineHasAgentLoopbackAllowAnyPortAnyHost(rules[i+2].line, uids.agentUID) {
		return 0
	}
	tail := i + 3
	paired, forwardOnly := false, false
	for tail < len(rules) && lineHasAgentLoopbackAllowAnyPortAnyHost(rules[tail].line, uids.agentUID) {
		host, port, forward := agentLoopbackAllowHostPort(rules[tail].line, uids.agentUID, false)
		if tail+1 < len(rules) && forward && (lineHasAgentLoopbackReplyForHost(rules[tail+1].line, uids.agentUID, host, port) ||
			lineHasLegacyAgentLoopbackReplyForHost(rules[tail+1].line, uids.agentUID, host, port)) {
			paired = true
			tail += 2
		} else {
			forwardOnly = true
			tail++
		}
	}
	if paired && forwardOnly {
		return 0
	}
	for tail < len(rules) && lineIsLegacyOwnedLoopbackRule(rules[tail].line, uids.agentUID) {
		tail++
	}
	if tail+2 >= len(rules) || !lineHasManagedDNSDrop(rules[tail].line, uids.agentUID, "udp") ||
		!lineHasManagedDNSDrop(rules[tail+1].line, uids.agentUID, "tcp") ||
		!lineHasManagedCatchAllDrop(rules[tail+2].line, uids.agentUID) {
		return 0
	}
	for _, rule := range rules[start : tail+3] {
		if slices.Contains(nftLineFields(rule.line), "comment") {
			return 0
		}
	}
	return tail + 3 - start
}

func ambiguousNFTRule(line string, uids nftRulesHeaderUIDs) bool {
	if _, reserved := nftRuleOwnership(line); reserved {
		return false // Already reported by the ownership decoder.
	}
	if lineHasTerminalSkuidVerdict(line, uids.operatorUID, "accept") ||
		lineHasTerminalSkuidVerdict(line, uids.proxyUID, "accept") ||
		lineHasAgentListenerGuardForProxy(line, uids.proxyUID) ||
		lineIsLegacyOwnedLoopbackRule(line, uids.agentUID) {
		return true
	}
	fields := nftLineFields(line)
	if len(fields) >= 3 && fields[0] == "meta" && fields[1] == "skuid" && fields[2] == strconv.Itoa(uids.agentUID) &&
		lineHasAnyToken(line, "accept", "drop", "reject", "return", "jump", "goto", "queue") {
		return true
	}
	return chainLinesHaveUnsafeVerdictBeforeAgentDrop([]string{line}, containmentUIDs{
		operatorUID: uids.operatorUID, operatorKnown: true, proxyUID: uids.proxyUID, agentUID: uids.agentUID,
	}, uids.proxyPort)
}

// checkNFTReconciliationResult uses the same planner after a kernel commit.
// nft(8)'s atomic batch can commit even if its caller loses the acknowledgement;
// retry therefore observes state rather than trusting a previous exit status.
func checkNFTReconciliationResult(policy nftReconcilePolicy, before nftReconcilePlan, live string) error {
	after := planNFTReconciliation(policy, nftReconcileObservation{persisted: policy.rules, live: live})
	if err := after.err(); err != nil {
		return err
	}
	if after.kernelChanged {
		return fmt.Errorf("post-apply nft observation does not match the planned owned rules; rerun `pipelock contain reload-nft-rules`")
	}
	if !sameForeignNFTRules(before.foreign, after.foreign) {
		return fmt.Errorf("post-apply nft observation changed foreign rules; inspect the live chain before retrying")
	}
	return nil
}

func sameForeignNFTRules(before, after []nftRuleWithHandle) bool {
	if len(before) != len(after) {
		return false
	}
	for i, rule := range before {
		// nft list expands live packet/byte counters; those can advance while
		// observing an untouched rule. Handles, order and expressions must stay.
		if rule.handle != after[i].handle || canonicalManagedNFTLine(rule.line) != canonicalManagedNFTLine(after[i].line) {
			return false
		}
	}
	return true
}

type nftPlanExecutor struct {
	nftPath, rulesPath string
	run                runCommand
	write              func(string, []byte, os.FileMode) error
	remove             func(string) error
	read               func(string) ([]byte, error)
}

// executeNFTPlan validates one atomic batch and always observes after an apply
// attempt, including a failed acknowledgement. It never guesses that a failed
// client command means the kernel did not commit.
func executeNFTPlan(ctx context.Context, executor nftPlanExecutor, policy nftReconcilePolicy, plan nftReconcilePlan) (bool, error) {
	if err := plan.err(); err != nil {
		return false, err
	}
	if !plan.kernelChanged {
		return false, nil
	}
	path := executor.rulesPath + ".reload"
	if err := executor.write(path, []byte(plan.script), modeConfigSecret); err != nil {
		return false, fmt.Errorf("write nft managed chain reload file %s: %w", path, err)
	}
	defer func() { _ = executor.remove(path) }()
	if err := runNFTPlanCommand(ctx, executor, "validate nft managed chain reload", "-c", "-f", path); err != nil {
		return false, err
	}
	applyErr := runNFTPlanCommand(ctx, executor, "reload nft managed chain", "-f", path)
	fileErr := observePersistedNFTPlan(executor.read, executor.rulesPath, plan.rules)
	live, code, err := executor.run(ctx, executor.nftPath, "-n", "-a", "list", "chain", "inet", policy.table, policy.chain)
	if err != nil {
		return true, errors.Join(applyErr, fileErr, fmt.Errorf("post-apply nft observation: %w", err))
	}
	if code != 0 {
		mutated := true
		if applyErr != nil && !plan.hadChain && nftOutputConfirmsAbsent(live) {
			mutated = false
		}
		return mutated, errors.Join(applyErr, fileErr, fmt.Errorf("post-apply nft observation exit=%d: %s", code, oneLine(live)))
	}
	return true, errors.Join(applyErr, fileErr, checkNFTReconciliationResult(policy, plan, live))
}

func observePersistedNFTPlan(read func(string) ([]byte, error), path, want string) error {
	data, err := read(path)
	if err != nil {
		return fmt.Errorf("post-apply persisted nft observation: %w", err)
	}
	if string(data) != want {
		return fmt.Errorf("post-apply persisted nft rules do not match the plan; rerun `pipelock contain reload-nft-rules`")
	}
	return nil
}

func runNFTPlanCommand(ctx context.Context, executor nftPlanExecutor, operation string, args ...string) error {
	out, code, err := executor.run(ctx, executor.nftPath, args...)
	if err != nil {
		return fmt.Errorf("%s: %w", operation, err)
	}
	if code != 0 {
		return fmt.Errorf("%s exit=%d: %s", operation, code, oneLine(out))
	}
	return nil
}
