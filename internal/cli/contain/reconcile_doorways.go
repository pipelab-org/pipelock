// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package contain

import (
	"context"
	"io"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

// Keep the OS adapter separate from policy observation and planning. Tests
// supply the same installer interface backed by fake nft/systemd operations.
func configureNFTReloadDoorways(env *nftReloadEnv, installFactory func(io.Writer) *installEnv) {
	listener := ""
	env.listenerSnapshot = &listener
	env.reconcileForwarders = func(ctx context.Context, port int, services []config.ContainmentLoopbackService) error {
		installed := installFactory(io.Discard)
		installed.proxyPort = port
		if port == 0 {
			return revokeKnownLoopbackDoorways(ctx, installed)
		}
		_, err := runSteps(ctx, installed, io.Discard, []step{stepInstallNetworkNamespacePolicy(&services, &listener)})
		return err
	}
	env.reconcilePublished = func(ctx context.Context, services []config.ContainmentPublishedService) error {
		installed := installFactory(io.Discard)
		_, err := runSteps(ctx, installed, io.Discard, []step{stepInstallPublishedServices(&services)})
		return err
	}
}
