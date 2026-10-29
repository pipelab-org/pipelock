// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package contain

import (
	"context"
	"strings"
	"testing"
)

func TestValidateSelfManagedNFTRules(t *testing.T) {
	t.Parallel()

	const operatorUID, proxyUID, agentUID, proxyPort = 0, 0, 10001, 8888
	canonical := nftListingForTest(renderNFTRules(operatorUID, proxyUID, agentUID, proxyPort, defaultNFTTable, defaultNFTChain))
	if err := validateSelfManagedNFTRules(canonical, operatorUID, proxyUID, agentUID, proxyPort); err != nil {
		t.Fatalf("canonical rules rejected: %v", err)
	}
	readback := strings.ReplaceAll(canonical, "counter ", "counter packets 0 bytes 0 ")
	readback = strings.ReplaceAll(readback, " accept\n", " accept # handle 10\n")
	readback = strings.ReplaceAll(readback, " drop\n", " drop # handle 11\n")
	if err := validateSelfManagedNFTRules(readback, operatorUID, proxyUID, agentUID, proxyPort); err != nil {
		t.Fatalf("nft-style readback rejected: %v", err)
	}

	nonDefault := nftListingForTest(renderNFTRules(1000, 1001, agentUID, proxyPort, defaultNFTTable, defaultNFTChain))
	if err := validateSelfManagedNFTRules(nonDefault, 1000, 1001, agentUID, proxyPort); err != nil {
		t.Fatalf("non-default operator/proxy UIDs rejected: %v", err)
	}
	if err := validateSelfManagedNFTRules(canonical, 1000, 1001, agentUID, proxyPort); err == nil {
		t.Fatal("root/root chain accepted for non-root operator/proxy UIDs")
	}

	t.Run("wrong proxy port", func(t *testing.T) {
		t.Parallel()
		if err := validateSelfManagedNFTRules(canonical, operatorUID, proxyUID, agentUID, 8899); err == nil {
			t.Fatal("wrong proxy port accepted")
		}
	})
	t.Run("tcp-only drop", func(t *testing.T) {
		t.Parallel()
		weakened := strings.Replace(canonical,
			"meta skuid 10001 counter log prefix \"pipelock-contain class=not_routing_through_pipelock \" drop",
			"meta skuid 10001 meta l4proto tcp counter drop", 1)
		if err := validateSelfManagedNFTRules(weakened, operatorUID, proxyUID, agentUID, proxyPort); err == nil {
			t.Fatal("TCP-only catch-all accepted")
		}
	})
	t.Run("previous renderer output", func(t *testing.T) {
		t.Parallel()
		previous := canonical
		for _, role := range nftManagedRoles {
			previous = strings.ReplaceAll(previous, ` comment "pipelock:contain:v1:`+role+`"`, "")
		}
		if previous == canonical {
			t.Fatal("fixture carries no ownership comments")
		}
		if err := validateSelfManagedNFTRules(previous, operatorUID, proxyUID, agentUID, proxyPort); err != nil {
			t.Fatalf("previous renderer output rejected: %v", err)
		}
		weakened := strings.Replace(previous,
			"meta skuid 10001 counter log prefix \"pipelock-contain class=not_routing_through_pipelock \" drop",
			"meta skuid 10001 meta l4proto tcp counter drop", 1)
		if err := validateSelfManagedNFTRules(weakened, operatorUID, proxyUID, agentUID, proxyPort); err == nil {
			t.Fatal("weakened previous renderer output accepted")
		}
		lines := strings.Split(previous, "\n")
		for i, line := range lines {
			if strings.Contains(line, "meta skuid") {
				lines = append(lines[:i+1], lines[i:]...)
				break
			}
		}
		if err := validateSelfManagedNFTRules(strings.Join(lines, "\n"), operatorUID, proxyUID, agentUID, proxyPort); err == nil {
			t.Fatal("previous renderer output with a duplicated rule accepted")
		}
	})
	t.Run("IPv4-only table", func(t *testing.T) {
		t.Parallel()
		weakened := strings.Replace(canonical, "table inet ", "table ip ", 1)
		if err := validateSelfManagedNFTRules(weakened, operatorUID, proxyUID, agentUID, proxyPort); err == nil {
			t.Fatal("IPv4-only table accepted")
		}
	})
}

func TestVerifySelfManagedNFTRules_CanceledContextFailsClosed(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := VerifySelfManagedNFTRules(ctx, 0, 0, 10001, 8888); err == nil {
		t.Fatal("canceled live nft verification accepted")
	}
}
