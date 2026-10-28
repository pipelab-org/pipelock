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
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/luckyPipewrench/pipelock/internal/cliutil"
	"github.com/luckyPipewrench/pipelock/internal/config"
)

var nftHandlePattern = regexp.MustCompile(`\s+# handle ([1-9][0-9]*)\s*$`)

// nftReloadEnv isolates the boot-time reconciler from the installer so tests
// can exercise its emitted nft transaction without changing a host ruleset.
type nftReloadEnv struct {
	nftPath           string
	rulesPath         string
	configPath        string
	reconcileLockPath string
	table             string
	chain             string
	runCmd            runCommand
	readFile          func(string) ([]byte, error)
	writeFile         func(string, []byte, os.FileMode) error
	removeFile        func(string) error
	now               func() time.Time
	listenerSnapshot  *string
	// warn reports a non-fatal reconciliation problem (a dropped declared
	// loopback service) to the operator. Every boot/manual reload runs
	// unattended via systemd, so this writes to stderr -- captured by the
	// journal -- rather than returning an error that would abort the reload
	// and leave the agent's egress boundary un-reconciled at all.
	warn func(string)
	// report records the successful reconciliation outcome. It is deliberately
	// separate from warn: a manual reload that made no change is still useful
	// evidence, while warnings describe a safe degradation in the declared
	// loopback-service set.
	report func(string)
	// lockFn wraps the config-snapshot -> kernel-apply -> persist critical
	// section in an exclusive lock, shared with `contain install`'s own nft
	// step, so the two can never interleave on the same managed config and
	// nft state. Defaults to the real flock-based withContainmentReconcileLock;
	// tests substitute a fake to deterministically force an interleaving
	// window without depending on OS scheduling.
	lockFn func(lockPath string, fn func() error) error
	// pauseAfterSnapshot, if set, runs after the declared loopback services
	// have been read from the managed config and BEFORE the kernel
	// transaction is built -- while lockFn's critical section is still
	// held. Test-only: lets a race test deterministically widen the window
	// between snapshot and apply to prove a concurrent `contain install`
	// blocks on the shared lock instead of interleaving.
	pauseAfterSnapshot  func()
	reconcileForwarders func(context.Context, int, []config.ContainmentLoopbackService) error
	// reconcilePublished closes, opens, or re-renders published agent
	// services. Reload always runs it so an expired or removed publication
	// is closed without another contain install.
	reconcilePublished func(context.Context, []config.ContainmentPublishedService) error
}

var (
	newNFTReloadEnv           = defaultNFTReloadEnv
	requireNFTReloadPrivilege = requireContainPrivilege
)

func defaultNFTReloadEnv() *nftReloadEnv {
	platform := detectContainPlatform(os.ReadFile, os.Stat, exec.LookPath)
	env := &nftReloadEnv{
		nftPath:           platform.nftPath,
		rulesPath:         defaultNFTRulesPath,
		configPath:        filepath.Join(defaultConfigDir, "pipelock.yaml"),
		reconcileLockPath: containmentReconcileLockPathFor(defaultNFTRulesPath),
		table:             defaultNFTTable,
		chain:             defaultNFTChain,
		runCmd:            realRunCommand,
		readFile:          os.ReadFile,
		// writeFileAtomic (temp file + fsync + rename + directory fsync in
		// the same directory) is the same primitive `contain install`
		// already uses for every managed file write. A crash mid-write can
		// therefore never leave the persisted rules file empty or partial:
		// either the previous content survives untouched, or the new
		// content is fully present.
		writeFile:  writeFileAtomic,
		removeFile: os.Remove,
		now:        time.Now,
		warn: func(msg string) {
			_, _ = fmt.Fprintln(os.Stderr, "WARNING: "+msg)
		},
		lockFn: withContainmentReconcileLock,
	}
	configureNFTReloadDoorways(env, defaultInstallEnv)
	return env
}

func reloadNFTRulesCmd() *cobra.Command {
	return &cobra.Command{
		Use:           "reload-nft-rules",
		Short:         "Reload managed nft containment rules without duplicating them",
		Hidden:        true,
		SilenceUsage:  true,
		SilenceErrors: true,
		Args:          cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if err := requireNFTReloadPrivilege("reload-nft-rules"); err != nil {
				return cliutil.ExitCodeError(cliutil.ExitConfig, err)
			}
			env := newNFTReloadEnv()
			env.report = func(message string) {
				_, _ = fmt.Fprintln(cmd.OutOrStdout(), message)
			}
			if err := reloadNFTRules(cmd.Context(), env); err != nil {
				return cliutil.ExitCodeError(cliutil.ExitGeneral, err)
			}
			return nil
		},
	}
}

func reloadNFTRules(ctx context.Context, env *nftReloadEnv) error {
	if env.reconcileLockPath == "" {
		// A test env that never set a lock path is not exercising locking;
		// production always sets defaultContainmentReconcileLockPath.
		return reloadNFTRulesLocked(ctx, env)
	}
	lockFn := env.lockFn
	if lockFn == nil {
		lockFn = withContainmentReconcileLock
	}
	// The whole critical section -- reading the current persisted rules,
	// snapshotting the managed config's declared loopback services,
	// applying the kernel transaction, and persisting the result -- runs
	// under one exclusive lock shared with `contain install`'s own nft
	// step (see withContainmentReconcileLock). Without it, an install that
	// promotes a new managed config while a reload is mid-flight on the
	// OLD config can have the reload's later write silently restore an
	// entry the install just revoked.
	return lockFn(env.reconcileLockPath, func() error {
		return reloadNFTRulesLocked(ctx, env)
	})
}

func reloadNFTRulesLocked(ctx context.Context, env *nftReloadEnv) (result error) {
	// Snapshot the managed config once. All readers below see these same bytes
	// and time, even if another process replaces the file during reconciliation.
	data, readErr := env.readFile(env.configPath)
	snapshot := *env
	snapshot.readFile = func(string) ([]byte, error) { return data, readErr }
	now := time.Now()
	if env.now != nil {
		now = env.now()
	}
	snapshot.now = func() time.Time { return now }
	persisted, err := env.readFile(env.rulesPath)
	if err != nil {
		return errors.Join(fmt.Errorf("read nft rules %s: %w", env.rulesPath, err), reconcileNamespaceDoorways(ctx, env, 0, nil, nil))
	}
	header, ok, err := parseNFTRulesHeaderUIDs(persisted)
	if err != nil || !ok {
		if err == nil {
			err = errors.New("missing the managed uid header (empty or corrupt persisted rules file)")
		}
		return errors.Join(fmt.Errorf("parse nft rules header %s: %w; rerun `pipelock contain install` to restore it", env.rulesPath, err), reconcileNamespaceDoorways(ctx, env, 0, nil, nil))
	}
	loopbackServices := reconcileDeclaredContainmentLoopbackServicesForReload(&snapshot, header.proxyPort)
	publishedServices := reconcileDeclaredContainmentPublishedServicesForReload(&snapshot, header.proxyPort)
	agentListener := ""
	var listenerProblem error
	if env.configPath != "" {
		switch {
		case errors.Is(readErr, os.ErrNotExist) && strings.Contains(string(persisted), "pipelock_agent_listener_blocked"):
			listenerProblem = fmt.Errorf("managed listener config %s is missing; refusing to remove the existing listener guard", env.configPath)
		case readErr != nil && !errors.Is(readErr, os.ErrNotExist):
			listenerProblem = fmt.Errorf("read managed listener config %s: %w", env.configPath, readErr)
		default:
			var parseErr error
			agentListener, parseErr = agentListenerFromConfigBytes(data)
			if parseErr != nil {
				listenerProblem = fmt.Errorf("parse managed listener config: %w", parseErr)
			}
		}
	}
	if env.listenerSnapshot != nil {
		*env.listenerSnapshot = agentListener
	}
	doorwayPort := header.proxyPort
	if listenerProblem != nil {
		doorwayPort = 0
		loopbackServices = nil
		publishedServices = nil
	}
	// Revocation precedes every nft failure and never retargets an unreadable
	// listener policy. Zero port selects cleanup without opening a proxy doorway.
	doorwayErr := reconcileNamespaceDoorways(ctx, env, doorwayPort, loopbackServices, publishedServices)
	defer func() { result = errors.Join(result, doorwayErr) }()
	if listenerProblem != nil {
		return listenerProblem
	}
	if env.pauseAfterSnapshot != nil {
		env.pauseAfterSnapshot()
	}
	rules := []byte(renderNFTRulesWithServices(nftRuleOptions{
		OperatorUID:      header.operatorUID,
		ProxyUID:         header.proxyUID,
		AgentUID:         header.agentUID,
		ProxyPort:        header.proxyPort,
		Table:            env.table,
		Chain:            env.chain,
		LoopbackServices: loopbackServices,
		AgentListener:    agentListener,
	}))

	policy := nftReconcilePolicy{rules: string(rules), uids: header, table: env.table, chain: env.chain}
	out, code, err := env.runCmd(ctx, env.nftPath, "-n", "-a", "list", "chain", "inet", env.table, env.chain)
	if err != nil {
		return fmt.Errorf("list nft managed chain: %w", err)
	}
	if code != 0 && strings.Contains(out, "No such file or directory") {
		// A missing chain is the normal first-boot state. Loading the canonical
		// file is sufficient and preserves nft's own error handling for any
		// other missing-table situation.
		out = ""
	} else if code != 0 {
		return fmt.Errorf("list nft managed chain exit=%d: %s", code, oneLine(out))
	}
	plan := planNFTReconciliation(policy, nftReconcileObservation{persisted: string(persisted), live: out})
	if err := plan.err(); err != nil {
		return err
	}
	if plan.fileChanged {
		if err := env.writeFile(env.rulesPath, rules, modeConfigSecret); err != nil {
			return fmt.Errorf("persist reconciled nft rules %s: %w", env.rulesPath, err)
		}
	}
	if plan.fileChanged && !plan.kernelChanged {
		if err := observePersistedNFTPlan(env.readFile, env.rulesPath, plan.rules); err != nil {
			return err
		}
	}
	if !plan.kernelChanged {
		if doorwayErr == nil && env.report != nil {
			env.report(nftReloadOutcome(plan.fileChanged, 0, false, false))
		}
		return nil
	}
	_, err = executeNFTPlan(ctx, nftPlanExecutor{env.nftPath, env.rulesPath, env.runCmd, env.writeFile, env.removeFile, env.readFile}, policy, plan)
	if err != nil {
		return err
	}
	if doorwayErr == nil && env.report != nil {
		env.report(nftReloadOutcome(plan.fileChanged, plan.removed, out == "", true))
	}
	return nil
}

// reconcileNamespaceDoorways reconciles both declared doorway kinds and
// attempts each even when the other fails: a failing loopback forwarder must
// not keep an expired publication open, and the reverse.
func reconcileNamespaceDoorways(ctx context.Context, env *nftReloadEnv, proxyPort int, loopback []config.ContainmentLoopbackService, published []config.ContainmentPublishedService) error {
	var errs []error
	if env.reconcileForwarders != nil {
		if err := env.reconcileForwarders(ctx, proxyPort, loopback); err != nil {
			errs = append(errs, fmt.Errorf("namespace loopback forwarders failed to reconcile: %w", err))
		}
	}
	if env.reconcilePublished != nil {
		if err := env.reconcilePublished(ctx, published); err != nil {
			errs = append(errs, fmt.Errorf("published services failed to reconcile: %w", err))
		}
	}
	return errors.Join(errs...)
}

// nftReloadOutcome describes what reconciliation did. appliedRules records
// whether the canonical rules were actually loaded into the kernel, and it is
// the only input that may report no change: a chain holding nothing but foreign
// rules changes no file and removes no managed handle, yet gains the entire
// managed block. Deriving "no change" from the other inputs reported an applied
// reload as a no-op, which tells an operator their reconciliation did nothing
// at the moment it did the most.
func nftReloadOutcome(fileChanged bool, removedRules int, loadedMissingChain, appliedRules bool) string {
	if !appliedRules {
		if fileChanged {
			return "containment nft rules reconciled: updated persisted rules; live owned rules already match"
		}
		return "containment nft rules already reconciled, no change"
	}
	if loadedMissingChain {
		return "containment nft rules reconciled: loaded managed rules into a missing chain"
	}
	changes := make([]string, 0, 2)
	if removedRules > 0 {
		changes = append(changes, fmt.Sprintf("removed %d managed rule(s)", removedRules))
	}
	if fileChanged {
		changes = append(changes, "updated persisted rules")
	}
	if len(changes) == 0 {
		changes = append(changes, "loaded managed rules into a chain that carried none")
	}
	return "containment nft rules reconciled: " + strings.Join(changes, "; ")
}

func managedNFTLinesFromRulesBody(rulesBody string) []string {
	lines := make([]string, 0)
	for _, line := range strings.Split(rulesBody, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "meta ") {
			lines = append(lines, canonicalManagedNFTLine(line))
		}
	}
	return lines
}

func canonicalManagedNFTLine(line string) string {
	fields := nftLineFields(line)
	canonical := make([]string, 0, len(fields))
	for i := 0; i < len(fields); i++ {
		if fields[i] == "counter" && i+4 < len(fields) && fields[i+1] == "packets" && isNonNegativeInteger(fields[i+2]) && fields[i+3] == "bytes" && isNonNegativeInteger(fields[i+4]) {
			canonical = append(canonical, fields[i])
			i += 4
			continue
		}
		if fields[i] == "0x2" && i > 0 && fields[i-1] == "state" {
			canonical = append(canonical, "established")
			continue
		}
		if fields[i] == "1" && i > 0 && fields[i-1] == "direction" {
			canonical = append(canonical, "reply")
			continue
		}
		canonical = append(canonical, fields[i])
	}
	return strings.Join(canonical, " ")
}

// reconcileDeclaredContainmentLoopbackServicesForReload resolves the
// declared loopback services whose namespace forwarders this reload should
// reconcile, from the managed config rather than stale runtime state. On any
// failure to read, parse, or validate the declaration -- unreadable managed
// config, malformed YAML, or a malformed, duplicate, or proxy-port entry -- it
// fails closed by returning zero declared services (the agent stays contained
// and only loses the extra declared service) and reports why via env.warn,
// rather than silently keeping whatever was last rendered.
//
// An expired entry is a lapsed grant, not a malformed file: only that entry is
// dropped (and named via env.warn), so its unexpired siblings keep their
// forwarders.
func reconcileDeclaredContainmentLoopbackServicesForReload(env *nftReloadEnv, proxyPort int) []config.ContainmentLoopbackService {
	now := time.Now
	if env.now != nil {
		now = env.now
	}
	data, err := env.readFile(env.configPath)
	if err != nil {
		if os.IsNotExist(err) {
			// A genuinely absent managed config is not itself an error --
			// Pipelock may be reloading before contain install has ever
			// staged one -- but it is not silent either: an operator who
			// expects a declared service reachable needs to know reload
			// found no config to read it from, not only that the config was
			// malformed once it existed.
			if env.warn != nil {
				env.warn(fmt.Sprintf("containment: managed config %s not found; reloading without any declared loopback services; run `pipelock contain install` to restore it", env.configPath))
			}
			return nil
		}
		if env.warn != nil {
			env.warn(fmt.Sprintf("containment: managed config %s is unreadable (%v); reloading without any declared loopback services until it is readable again — run `pipelock contain reload-nft-rules` after fixing it", env.configPath, err))
		}
		return nil
	}
	declared, lapsed, err := parseContainmentLoopbackServicesWithLapsed(data, proxyPort, now())
	if err != nil {
		if env.warn != nil {
			env.warn(fmt.Sprintf("containment: managed config %s declares containment.loopback_services that Pipelock cannot honor (%v); reloading without any declared loopback services until it is fixed — remove or re-approve the offending entry, then run `pipelock contain reload-nft-rules`", env.configPath, err))
		}
		return nil
	}
	warnLapsedContainmentGrants(env.warn, env.configPath, lapsed)
	return declared
}

// warnLapsedContainmentGrants names every expired grant a reconciliation
// dropped, so an operator can see exactly which declaration ended and that its
// siblings were kept.
func warnLapsedContainmentGrants(warn func(string), configPath string, lapsed []config.LapsedContainmentGrant) {
	if warn == nil {
		return
	}
	for _, grant := range lapsed {
		warn(fmt.Sprintf("containment: %s in %s has expired and was dropped; its doorway is closed while unexpired %s stay in place — renew or remove the entry in the config, then run `pipelock contain reload-nft-rules`", grant.Message, configPath, grant.Kind))
	}
}

// legacyOwnedLoopbackMarkRuleHandles finds only the superseded cgroup-mark
// rules. They can remain after an interrupted upgrade whose receiver chain was
// already removed, and are no longer meaningful under the namespace boundary.
func legacyOwnedLoopbackMarkRuleHandles(live string, agentUID int) []int {
	var handles []int
	for _, rule := range nftRulesWithHandles(live) {
		if !lineIsLegacyOwnedLoopbackRule(rule.line, agentUID) {
			continue
		}
		handles = append(handles, rule.handle)
	}
	return handles
}

// lineIsLegacyOwnedLoopbackRule matches any of the four rules the cgroup
// loopback design rendered: the IPv4 and IPv6 marking accepts, and the two
// established accepts keyed on that mark.
func lineIsLegacyOwnedLoopbackRule(line string, agentUID int) bool {
	return lineHasLegacyOwnedLoopbackMark(line, agentUID) || lineHasLegacyOwnedLoopbackEstablished(line)
}

// lineHasLegacyOwnedLoopbackEstablished matches
// `ct mark <mark> ct state established oifname "lo" socket cgroupv2 level 1
// "<slice>" ct direction original|reply accept`, in named or numeric form.
func lineHasLegacyOwnedLoopbackEstablished(line string) bool {
	fields := nftLineFields(line)
	want := []string{"ct", "mark", legacyOwnedLoopbackMark, "ct", "state", "", "oifname", `"lo"`, "socket", "cgroupv2", "level", "1", `"` + legacyOwnedLoopbackSlice + `"`, "ct", "direction", "", "accept"}
	if len(fields) != len(want) {
		return false
	}
	for i, token := range want {
		if token != "" && fields[i] != token {
			return false
		}
	}
	state, direction := fields[5], fields[15]
	return (state == "established" || state == "0x2") &&
		(direction == "original" || direction == "reply" || direction == "0" || direction == "1")
}

func lineHasLegacyOwnedLoopbackMark(line string, agentUID int) bool {
	fields := nftLineFields(line)
	if len(fields) != 21 || fields[0] != "meta" || fields[1] != "skuid" || fields[2] != strconv.Itoa(agentUID) ||
		fields[3] != "oifname" || fields[4] != `"lo"` || fields[6] != "daddr" ||
		(fields[5] != "ip" && fields[5] != "ip6") ||
		(fields[5] == "ip" && fields[7] != "127.0.0.1") ||
		(fields[5] == "ip6" && fields[7] != "::1") {
		return false
	}
	want := []string{"socket", "cgroupv2", "level", "1", `"` + legacyOwnedLoopbackSlice + `"`, "ct", "state"}
	for i, token := range want {
		if fields[i+8] != token {
			return false
		}
	}
	// `nft -n` prints conntrack state as its bitmask: new is 0x8 (invalid 0x1,
	// established 0x2, related 0x4). The reload reads the chain with -n, so the
	// numeric form is the one that decides whether these rules are removed.
	return (fields[15] == "new" || fields[15] == "0x8") &&
		fields[16] == "ct" && fields[17] == "mark" && fields[18] == "set" &&
		fields[19] == legacyOwnedLoopbackMark && fields[20] == "accept"
}

type nftRuleWithHandle struct {
	line   string
	handle int
}

func lineHasAgentListenerGuardForProxy(line string, proxyUID int) bool {
	fields := nftLineFields(line)
	if len(fields) < 15 || !slices.Equal(fields[:7], []string{"meta", "skuid", "!=", "{", "0,", strconv.Itoa(proxyUID), "}"}) {
		return false
	}
	return lineHasAgentListenerGuardSuffix(fields[7:])
}

func lineHasAgentListenerGuardSuffix(fields []string) bool {
	if len(fields) < 8 || (fields[0] != "ip" && fields[0] != "ip6") || fields[1] != "daddr" ||
		fields[3] != "tcp" || fields[4] != "dport" {
		return false
	}
	port, err := strconv.Atoi(fields[5])
	if err != nil || port < 1 || port > 65535 {
		return false
	}
	return fieldsHaveNFTCounterLogDrop(fields[6:], "pipelock_agent_listener_blocked ")
}

// lineHasLegacyAgentLoopbackReplyForHost recognizes the reply shape emitted
// before declared-service replies matched their source address. It is used only
// by partial-block recovery so reload can remove a malformed managed block;
// verification never treats this legacy rule as a healthy declared reply.
func lineHasLegacyAgentLoopbackReplyForHost(line string, agentUID int, host string, port int) bool {
	fields := nftLineFields(line)
	daddrKeyword := []string{"ip", "daddr"}
	if host == "::1" {
		daddrKeyword = []string{"ip6", "daddr"}
	}
	want := append([]string{"meta", "skuid", strconv.Itoa(agentUID), "oifname", `"lo"`}, daddrKeyword...)
	want = append(want, host, "tcp", "sport", strconv.Itoa(port), "ct", "state")
	if len(fields) < len(want)+5 {
		return false
	}
	for i, field := range want {
		if fields[i] != field {
			return false
		}
	}
	tail := fields[len(want):]
	if !nftEstablishedState(tail[0]) || tail[1] != "ct" || tail[2] != "direction" || !nftReplyDirection(tail[3]) || tail[4] != "accept" {
		return false
	}
	return nftRuleTailIsCommentOnly(tail[5:])
}

func nftRulesWithHandles(live string) []nftRuleWithHandle {
	rules := make([]nftRuleWithHandle, 0)
	for _, raw := range strings.Split(live, "\n") {
		match := nftHandlePattern.FindStringSubmatch(raw)
		if len(match) != 2 {
			continue
		}
		handle, err := strconv.Atoi(match[1])
		if err != nil {
			continue
		}
		line := strings.TrimSpace(strings.TrimSuffix(raw, match[0]))
		fields := nftLineFields(line)
		if len(fields) > 0 && (fields[0] == "chain" || fields[0] == "table") {
			continue
		}
		if line != "" {
			rules = append(rules, nftRuleWithHandle{line: line, handle: handle})
		}
	}
	return rules
}

func lineHasManagedDNSDrop(line string, agentUID int, protocol string) bool {
	fields := nftLineFields(line)
	prefix := []string{"meta", "skuid", strconv.Itoa(agentUID), protocol, "dport", "53"}
	if len(fields) < len(prefix)+4 {
		return false
	}
	for i, want := range prefix {
		if fields[i] != want {
			return false
		}
	}
	return fieldsHaveNFTCounterLogDrop(fields[len(prefix):], nftLogPrefix(EgressClassDirectDNS)+" ")
}

func lineHasManagedCatchAllDrop(line string, agentUID int) bool {
	fields := nftLineFields(line)
	prefix := []string{"meta", "skuid", strconv.Itoa(agentUID)}
	if len(fields) < len(prefix)+4 {
		return false
	}
	for i, want := range prefix {
		if fields[i] != want {
			return false
		}
	}
	return fieldsHaveNFTCounterLogDrop(fields[len(prefix):], nftLogPrefix(EgressClassNotRoutingThroughPipelock)+" ")
}

func fieldsHaveNFTCounterLogDrop(fields []string, prefix string) bool {
	if len(fields) < 5 || fields[0] != "counter" {
		return false
	}
	i := 1
	if i+3 < len(fields) && fields[i] == "packets" && isNonNegativeInteger(fields[i+1]) && fields[i+2] == "bytes" && isNonNegativeInteger(fields[i+3]) {
		i += 4
	}
	if i+3 >= len(fields) || fields[i] != "log" || fields[i+1] != "prefix" || fields[i+2] != strconv.Quote(prefix) || fields[i+3] != "drop" {
		return false
	}
	return nftRuleTailIsCommentOnly(fields[i+4:])
}

func isNonNegativeInteger(value string) bool {
	_, err := strconv.ParseUint(value, 10, 64)
	return err == nil
}
