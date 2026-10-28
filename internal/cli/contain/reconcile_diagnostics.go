// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package contain

import (
	"errors"
	"fmt"
	"os"
	"strings"
)

const nftReloadRemedy = "run `pipelock contain reload-nft-rules`"

// predictNFTReconciliation uses the executor's planner. Reload cannot restore
// an unreadable header or change installed identities/ports; those require
// install. Never recommend a reload using the probe's overridden port.
func predictNFTReconciliation(env *probeEnv, live string, current containmentUIDs) (nftReconcilePlan, string, error) {
	persisted, err := env.readFile(env.nftRulesPath)
	if err != nil {
		return nftReconcilePlan{}, installRemedyForPort(env.port), fmt.Errorf("read managed nft rules for reconciliation: %w", err)
	}
	header, ok, err := parseNFTRulesHeaderUIDs(persisted)
	if err != nil || !ok {
		return nftReconcilePlan{}, installRemedyForPort(env.port), errors.New("managed nft uid header cannot authorize reconciliation")
	}
	if header.proxyUID != current.proxyUID || header.agentUID != current.agentUID || header.proxyPort != env.port ||
		(current.operatorKnown && header.operatorUID != current.operatorUID) {
		return nftReconcilePlan{}, installRemedyForPort(env.port), errors.New("managed nft identities or proxy port differ from the requested boundary")
	}
	data, err := env.readFile(env.configPath)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nftReconcilePlan{}, doorwayInspectionRemedy, fmt.Errorf("read managed listener config: %w", err)
	}
	if errors.Is(err, os.ErrNotExist) && strings.Contains(string(persisted), "pipelock_agent_listener_blocked") {
		return nftReconcilePlan{}, installRemedyForPort(env.port), errors.New("managed listener config is missing; reload preserves the existing guard")
	}
	listener, err := agentListenerFromConfigBytes(data)
	if err != nil {
		return nftReconcilePlan{}, doorwayInspectionRemedy, fmt.Errorf("parse managed listener config: %w", err)
	}
	policy := nftReconcilePolicy{
		uids: header, table: env.nftTable, chain: env.nftChain,
		rules: renderNFTRulesWithServices(nftRuleOptions{
			OperatorUID: header.operatorUID, ProxyUID: header.proxyUID,
			AgentUID: header.agentUID, ProxyPort: header.proxyPort, Table: env.nftTable, Chain: env.nftChain, AgentListener: listener,
		}),
	}
	plan := planNFTReconciliation(policy, nftReconcileObservation{persisted: string(persisted), live: live})
	if err := plan.err(); err != nil {
		return plan, err.Error(), err
	}
	return plan, nftReloadRemedy, nil
}
