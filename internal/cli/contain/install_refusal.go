// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package contain

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

// A refused install cannot grant access, but it must still close access that
// either the current or prospective policy revokes. Observation is repeated
// under the normal install/reload lock; the initial read only avoids creating
// a lock directory on hosts with no known doorways.
func revokeInstallRefusalDoorways(ctx context.Context, env *installEnv, configPath string) error {
	loopback, published, err := installRefusalDoorwayPlan(env, configPath)
	if len(loopback)+len(published) == 0 {
		return err
	}
	// runSteps checks cancellation before each step. Revocation must reach
	// its per-command bounded contexts even if the refused nft probe was
	// canceled, rather than skipping every stop before those contexts exist.
	return runInstallSteps(context.WithoutCancel(ctx), env, []step{{
		name: "revoke-refused-install-doorways",
		desc: "close revoked doorways after a refused nft preflight",
		apply: func(ctx context.Context, env *installEnv) (bool, error) {
			loopback, published, planErr := installRefusalDoorwayPlan(env, configPath)
			if len(loopback)+len(published) == 0 {
				return false, planErr
			}
			// Early nft refusal precedes the ordinary binary preflight. Pin
			// cleanup to the exact root-owned executable we checked, so PATH
			// resolution cannot select a different program at execution time.
			lookPath := env.lookPath
			if lookPath == nil {
				lookPath = exec.LookPath
			}
			path, lookupErr := lookPath("systemctl")
			if lookupErr != nil {
				return false, errors.Join(planErr, fmt.Errorf("locate doorway revocation systemctl: %w", lookupErr))
			}
			if err := expectPrivilegedExecutablePath(env.stat, "systemctl", path); err != nil {
				return false, errors.Join(planErr, err)
			}
			cleanup := *env
			cleanup.runCmd = func(ctx context.Context, name string, args ...string) (string, int, error) {
				if name == "systemctl" {
					name = path
				}
				return env.runCmd(ctx, name, args...)
			}
			// Attempt both classes even when one stop fails. Never roll back
			// revocation by restarting a grant after another cleanup error.
			return true, errors.Join(planErr, closeLoopbackDoorways(ctx, &cleanup, loopback), closePublishedDoorways(ctx, &cleanup, published))
		},
	}})
}

func installRefusalDoorwayPlan(env *installEnv, configPath string) ([]string, []string, error) {
	observed := *env
	observed.readFile, _ = snapshotReconcileReads(env.readFile)
	loopbackInv, loopbackErr := readLoopbackForwarderInventory(&observed)
	publishedInv, publishedErr := readPublishedServiceRecords(&observed)
	published, observationErr := observePublishedDoorways(&observed, publishedInv)
	var errs []error
	errs = append(errs, loopbackErr, publishedErr, observationErr)
	var desiredLoopback, desiredPublished []string
	paths := []string{managedPipelockConfigPath(env)}
	if configPath != paths[0] {
		paths = append(paths, configPath)
	}
	policyTime := time.Now()
	for i, path := range paths {
		loopback, publication, err := installRefusalDesiredDoorways(&observed, path, policyTime, publishedInv)
		errs = append(errs, err)
		if i == 0 {
			desiredLoopback, desiredPublished = loopback, publication
			continue
		}
		// A prospective extension has not been installed. Keep only
		// doorways still authorized by both policies at this instant.
		desiredLoopback = slices.DeleteFunc(desiredLoopback, func(unit string) bool { return !slices.Contains(loopback, unit) })
		desiredPublished = slices.DeleteFunc(desiredPublished, func(unit string) bool { return !slices.Contains(publication, unit) })
	}
	wanted := make(map[string]bool, len(desiredLoopback))
	for _, unit := range desiredLoopback {
		wanted[unit] = true
	}
	loopback := staleLoopbackUnits(&observed, filepath.Dir(env.proxyForwarderSocketPath), loopbackInv, wanted)
	if observed.readDir != nil {
		if _, err := observed.readDir(filepath.Dir(env.proxyForwarderSocketPath)); err != nil && !errors.Is(err, os.ErrNotExist) {
			errs = append(errs, fmt.Errorf("observe managed loopback units: %w", err))
		}
	}
	plan := planNFTReconciliation(nftReconcilePolicy{doorways: desiredPublished}, nftReconcileObservation{doorways: published})
	return loopback, plan.closeDoorways, errors.Join(errs...)
}

func installRefusalDesiredDoorways(env *installEnv, path string, policyTime time.Time, observed publishedServiceRecordSet) ([]string, []string, error) {
	data, err := env.readFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil, nil
		}
		return nil, nil, fmt.Errorf("read doorway revocation policy %s: %w", path, err)
	}
	loopback, loopbackErr := parseContainmentLoopbackServicesFromConfigBytes(data, env.proxyPort, policyTime)
	publication, publishedErr := parseContainmentPublishedServicesFromConfigBytes(data, env.proxyPort, policyTime)
	var loopbackUnits, publishedUnits []string
	for _, service := range loopback {
		loopbackUnits = append(loopbackUnits, loopbackForwarderUnitBase(service.Host, service.Port))
	}
	for _, service := range publication {
		// The unit name comes from the service name. An operator change
		// leaves that name in place while the previous operator still owns
		// the socket, so the name alone is not authorization to keep it.
		if recordedPublishedOperatorDiffers(observed, service) {
			continue
		}
		for _, file := range publishedServiceFiles(filepath.Dir(env.proxyForwarderSocketPath), env.pipelockTarget, env.proxyUserName, service) {
			publishedUnits = append(publishedUnits, filepath.Base(file.path))
		}
	}
	return loopbackUnits, publishedUnits, errors.Join(loopbackErr, publishedErr)
}

func recordedPublishedOperatorDiffers(observed publishedServiceRecordSet, service config.ContainmentPublishedService) bool {
	for _, record := range observed.Services {
		if record.Name == service.Name {
			return record.OperatorUser != service.OperatorUser
		}
	}
	return false
}
