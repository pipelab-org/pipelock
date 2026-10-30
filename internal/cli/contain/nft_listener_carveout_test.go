// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package contain

import (
	"fmt"
	"strings"
	"testing"
)

func TestReloadListenerGuardPreservesEarlierForeignCarveOut(t *testing.T) {
	const foreign = `meta skuid 966 ip daddr 127.0.0.1 tcp dport 9077 accept # handle 10`
	current := renderNFTRulesWithServices(nftRuleOptions{OperatorUID: loopbackTestOperatorUID, ProxyUID: loopbackTestProxyUID, AgentUID: loopbackTestAgentUID, ProxyPort: loopbackTestProxyPort, Table: defaultNFTTable, Chain: defaultNFTChain, AgentListener: "127.0.0.1:8889"})
	live := foreign + "\n" + nftListingFromRulesBodyForTest(current, 20)
	plan := planNFTReconciliation(nftReconcilePolicy{
		rules: strings.Replace(current, "tcp dport 8889", "tcp dport 8890", 1), table: defaultNFTTable, chain: defaultNFTChain,
		uids: nftRulesHeaderUIDs{operatorUID: loopbackTestOperatorUID, proxyUID: loopbackTestProxyUID, agentUID: loopbackTestAgentUID, proxyPort: loopbackTestProxyPort},
	}, nftReconcileObservation{live: live})
	// A standalone unowned accept is preserved as a conflict; it cannot be
	// adopted merely because a complete owned block follows it.
	if plan.err() == nil || !strings.Contains(plan.err().Error(), "handle 10") || plan.script != "" {
		t.Fatalf("foreign carve-out was adopted or deleted: %+v", plan)
	}
}

// After a UID change the live managed block was rendered with the UIDs the
// replaced rules file recorded. Reload must remove that whole block, guard
// included, when given those prior UIDs, and still leave a foreign rule alone.
func TestReloadReplacesManagedBlockAfterUIDChange(t *testing.T) {
	const foreign = `meta skuid 12345 drop # handle 10`
	prior := nftRulesHeaderUIDs{operatorUID: loopbackTestOperatorUID, proxyUID: loopbackTestProxyUID + 50, agentUID: loopbackTestAgentUID + 50, proxyPort: loopbackTestProxyPort}
	old := renderNFTRulesWithServices(nftRuleOptions{OperatorUID: prior.operatorUID, ProxyUID: prior.proxyUID, AgentUID: prior.agentUID, ProxyPort: loopbackTestProxyPort, Table: defaultNFTTable, Chain: defaultNFTChain, AgentListener: "127.0.0.1:8889"})
	current := renderNFTRulesWithServices(nftRuleOptions{OperatorUID: loopbackTestOperatorUID, ProxyUID: loopbackTestProxyUID, AgentUID: loopbackTestAgentUID, ProxyPort: loopbackTestProxyPort, Table: defaultNFTTable, Chain: defaultNFTChain, AgentListener: "127.0.0.1:8889"})
	oldListing := nftListingFromRulesBodyForTest(old, 20)
	oldHandles := nftRulesWithHandles(oldListing)
	if len(oldHandles) < 5 || !strings.Contains(oldListing, "pipelock_agent_listener_blocked") {
		t.Fatalf("fixture lacks a full old block with its guard:\n%s", oldListing)
	}
	live := foreign + "\n" + oldListing

	script := renderNFTManagedChainReloadScript(live, current, defaultNFTTable, defaultNFTChain, loopbackTestOperatorUID, loopbackTestProxyUID, loopbackTestAgentUID, false, prior)
	for _, rule := range oldHandles {
		if !strings.Contains(script, fmt.Sprintf("delete rule inet %s %s handle %d\n", defaultNFTTable, defaultNFTChain, rule.handle)) {
			t.Fatalf("old managed rule %q (handle %d) was not removed:\n%s", rule.line, rule.handle, script)
		}
	}
	if strings.Contains(script, "handle 10\n") {
		t.Fatalf("foreign carve-out deleted:\n%s", script)
	}
}
