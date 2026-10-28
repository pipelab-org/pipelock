// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package contain

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

// Failure recovery trusts the existing canonical inventory contract, or exact
// renderer equality for directory-discovered units. Names and descriptions
// alone never authorize stopping a foreign unit. Keep the original read error
// even when the independent directory observation recovers every owned unit.
func revokeKnownLoopbackDoorways(ctx context.Context, env *installEnv) error {
	inv, inventoryErr := readLoopbackForwarderInventory(env)
	unitDir := filepath.Dir(env.proxyForwarderSocketPath)
	units := staleLoopbackUnits(env, unitDir, inv, nil)
	var errs []error
	errs = append(errs, inventoryErr)
	if env.readDir != nil {
		if _, err := env.readDir(unitDir); err != nil && !errors.Is(err, os.ErrNotExist) {
			errs = append(errs, fmt.Errorf("observe managed loopback units: %w", err))
		}
	}
	plan := planNFTReconciliation(nftReconcilePolicy{}, nftReconcileObservation{doorways: units})
	return errors.Join(errors.Join(errs...), closeLoopbackDoorways(ctx, env, plan.closeDoorways))
}

func closeLoopbackDoorways(ctx context.Context, env *installEnv, units []string) error {
	var errs []error
	for _, unit := range units {
		for _, suffix := range []string{"-netns.service", ".socket", ".service"} {
			args := []string{"disable", "--now", unit + suffix}
			if suffix == ".service" {
				args = []string{"stop", unit + suffix}
			}
			if err := runSystemctlCleanupUnit(ctx, env, args...); err != nil {
				errs = append(errs, fmt.Errorf("revoke loopback doorway %s%s: %w", unit, suffix, err))
			}
		}
	}
	return errors.Join(errors.Join(errs...), observeClosedLoopbackDoorways(ctx, env, units))
}

func revokeKnownPublishedDoorways(ctx context.Context, env *installEnv) error {
	inv, inventoryErr := readPublishedServiceRecords(env)
	units, observationErr := observePublishedDoorways(env, inv)
	plan := planNFTReconciliation(nftReconcilePolicy{}, nftReconcileObservation{doorways: units})
	return errors.Join(inventoryErr, observationErr, closePublishedDoorways(ctx, env, plan.closeDoorways))
}

func observePublishedDoorways(env *installEnv, inv publishedServiceRecordSet) ([]string, error) {
	var units []string
	for _, record := range inv.Services {
		units = append(units, publishedRecordUnitNames(record)...)
	}
	var observationErr error
	unitDir := filepath.Dir(env.proxyForwarderSocketPath)
	if env.readDir != nil {
		entries, err := env.readDir(unitDir)
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			observationErr = fmt.Errorf("observe published doorway units: %w", err)
		}
		for _, entry := range entries {
			if !entry.IsDir() && isManagedPublishedUnit(env, unitDir, entry.Name()) {
				units = append(units, entry.Name())
			}
		}
	}
	return units, observationErr
}

func closePublishedDoorways(ctx context.Context, env *installEnv, units []string) error {
	var errs []error
	// Close every listener before stopping any relay. systemd.socket(5):
	// stopping a socket alone doesn't terminate an already activated service.
	for _, socket := range []bool{true, false} {
		for _, unit := range units {
			if strings.HasSuffix(unit, ".socket") != socket {
				continue
			}
			args := []string{"stop", unit}
			if socket {
				args = []string{"disable", "--now", unit}
			}
			if err := runSystemctlCleanupUnit(ctx, env, args...); err != nil {
				errs = append(errs, fmt.Errorf("revoke published doorway %s: %w", unit, err))
			}
		}
	}
	return errors.Join(errors.Join(errs...), observeRevokedDoorways(ctx, env, units))
}

// Recover only the parameters the published-service renderers actually emit,
// then compare the whole file. This is the same bounded migration technique as
// isLegacyManagedProxyRelay, not a general systemd parser or a name heuristic.
func isManagedPublishedUnit(env *installEnv, dir, unit string) bool {
	name, ok := strings.CutPrefix(unit, "pipelock-published-")
	if !ok {
		return false
	}
	base, suffix, ok := strings.Cut(name, ".")
	if !ok || (suffix != "socket" && suffix != "service") {
		return false
	}
	base, tcp := strings.CutSuffix(base, "-tcp")
	if !config.ValidPublishedServiceName(base) {
		return false
	}
	body, err := env.readFile(filepath.Join(dir, unit))
	if err != nil {
		return false
	}
	service := config.ContainmentPublishedService{Name: base}
	if suffix == "socket" {
		listen, err := singleListenStream(string(body))
		if err != nil {
			return false
		}
		if tcp {
			service.HostListen = listen
			if string(body) == renderPublishedTCPSocketUnit(service) {
				return true
			}
		}
		service.HostSocket = listen
		for _, line := range strings.Split(string(body), "\n") {
			if value, found := strings.CutPrefix(line, "SocketUser="); found {
				service.OperatorUser = value
			}
		}
		return string(body) == renderPublishedSocketUnit(service)
	}
	prefix := "ExecStart=" + env.pipelockTarget + " contain netns-forward --systemd-listener --target-tcp "
	for _, line := range strings.Split(string(body), "\n") {
		if target, found := strings.CutPrefix(line, prefix); found {
			host, portText, err := net.SplitHostPort(target)
			port, portErr := strconv.Atoi(portText)
			if err != nil || portErr != nil || validatePort(port) != nil {
				return false
			}
			if ip := net.ParseIP(host); ip == nil || !ip.IsLoopback() {
				return false
			}
			service.AgentHost, service.AgentPort = host, port
		}
	}
	return service.AgentPort != 0 && string(body) == renderPublishedForwarderUnit(env.pipelockTarget, env.proxyUserName, service)
}

func observeClosedLoopbackDoorways(ctx context.Context, env *installEnv, units []string) error {
	var names []string
	for _, unit := range units {
		for _, suffix := range []string{"-netns.service", ".socket", ".service"} {
			names = append(names, unit+suffix)
		}
	}
	return observeRevokedDoorways(ctx, env, names)
}

// systemctl(1) show provides machine-readable unit properties; ActiveState is
// documented by systemd.unit(5). A successful stop acknowledgement alone does
// not prove a revoked listener or established relay is no longer active.
func observeRevokedDoorways(ctx context.Context, env *installEnv, units []string) error {
	var errs []error
	for _, unit := range units {
		out, code, err := env.runCmd(ctx, "systemctl", "show", "--property=ActiveState", "--value", unit)
		if err != nil {
			errs = append(errs, fmt.Errorf("observe revoked doorway %s: %w", unit, err))
			continue
		}
		state := strings.TrimSpace(out)
		if code != 0 || (state != "inactive" && state != "failed") {
			errs = append(errs, fmt.Errorf("post-apply revoked doorway %s has ActiveState=%q exit=%d; inspect the unit and rerun `pipelock contain reload-nft-rules`", unit, state, code))
		}
	}
	return errors.Join(errs...)
}
