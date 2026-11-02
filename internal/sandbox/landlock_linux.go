// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build linux && !mcp_hardening_test

package sandbox

import (
	"fmt"

	"github.com/landlock-lsm/go-landlock/landlock"
	llsys "github.com/landlock-lsm/go-landlock/landlock/syscall"
)

// ApplyLandlock restricts the calling process's filesystem access according
// to the given policy. This is permanent and inherited by all children.
//
// Uses BestEffort mode: on older kernels, the ruleset is automatically
// downgraded to the supported ABI level. Returns the active ABI version
// and any error. If Landlock is completely unavailable, returns
// ErrUnavailable.
func ApplyLandlock(policy Policy, proxySocket ...string) (LayerStatus, error) {
	status := LayerStatus{Name: LayerLandlock}

	abi, err := llsys.LandlockGetABIVersion()
	if err != nil {
		status.Reason = fmt.Sprintf("landlock not available: %v", err)
		return status, fmt.Errorf("%w: %w", ErrUnavailable, err)
	}
	if abi < 1 {
		status.Reason = "landlock ABI version 0 (not supported)"
		return status, fmt.Errorf("%w: ABI version 0", ErrUnavailable)
	}
	status.Version = min(abi, 9) // V9.BestEffort applies no rights newer than V9.

	// Build path rules from policy. BestEffort automatically downgrades
	// access rights the kernel doesn't support. IgnoreIfMissing skips
	// paths that don't exist on this distro (e.g., /lib64/, /etc/pki/).
	// REFER is granted only when the kernel reports Landlock erratum 3
	// (disconnected directory handling) fixed. Without that fix a rename or
	// link through a bind mount can widen access and bypass REFER limits
	// (Documentation/userspace-api/landlock.rst, "Errata"). Kernels without
	// the fix, or that cannot report errata, keep the pre-REFER behavior:
	// cross-directory renames and links fail with EXDEV.
	rules, refer := buildRulesWithErrata(policy, abi, landlockErrata)
	if abi >= 9 && len(proxySocket) > 0 && proxySocket[0] != "" {
		// Admit the exact parent doorway inode, never its directory. Ordinary
		// filesystem grants do not authorize connections to host sockets.
		rules = append(rules, landlock.ROFiles(proxySocket[0]).WithResolveUnix())
	}

	if err := landlock.V9.BestEffort().RestrictPaths(rules...); err != nil {
		status.Reason = fmt.Sprintf("restrict failed: %v", err)
		return status, fmt.Errorf("applying landlock: %w", err)
	}
	if abi >= 6 {
		// REFER is exceptional: even a scope-only ruleset denies it unless
		// explicitly granted. Keep IPC in a separate layer, but permit the
		// same writable hierarchies as the filesystem layer. See
		// Documentation/userspace-api/landlock.rst, "Filesystem flags"
		// and "Layers of file path access rights".
		ipc := landlock.Config{
			HandledAccessFS: landlock.AccessFSSet(llsys.AccessFSRefer),
			Scoped:          landlock.V6.Scoped,
		}
		var referRules []landlock.Rule
		if refer && len(policy.AllowRWDirs) > 0 {
			referRules = append(referRules, landlock.PathAccess(llsys.AccessFSRefer, policy.AllowRWDirs...).IgnoreIfMissing())
		}
		if err := ipc.Restrict(referRules...); err != nil {
			status.Reason = fmt.Sprintf("IPC scope failed: %v", err)
			return status, fmt.Errorf("applying landlock IPC scope: %w", err)
		}
	}

	status.Active = true
	return status, nil
}

// buildRulesWithErrata selects the same REFER gate as Guard before building
// filesystem rules. Its decision also controls the separate IPC layer's grants.
func buildRulesWithErrata(policy Policy, abi int, errata func() (int, error)) ([]landlock.Rule, bool) {
	refer := referAllowed(abi, errata)
	referABI := 1
	if refer {
		referABI = abi
	}
	return buildRules(policy, referABI), refer
}

// buildRules constructs landlock.Rule entries from the sandbox policy.
// Uses IgnoreIfMissing() so distro-specific paths (e.g., /lib64/, /etc/pki/)
// don't cause errors when absent.
func buildRules(policy Policy, abi int) []landlock.Rule {
	var rules []landlock.Rule

	// Read-only directories.
	if len(policy.AllowReadDirs) > 0 {
		rules = append(rules, landlock.RODirs(policy.AllowReadDirs...).IgnoreIfMissing())
	}

	// Read-only individual files.
	if len(policy.AllowReadFiles) > 0 {
		rules = append(rules, landlock.ROFiles(policy.AllowReadFiles...).IgnoreIfMissing())
	}

	// Read-write directories.
	if len(policy.AllowRWDirs) > 0 {
		rule := landlock.RWDirs(policy.AllowRWDirs...).IgnoreIfMissing()
		// Asking for REFER on ABI 1 would make BestEffort drop enforcement.
		// ABI 1 retains its cross-directory rename/link denial.
		if abi >= 2 {
			rule = rule.WithRefer()
		}
		rules = append(rules, rule)
	}

	// Read-write individual files (e.g., /dev/null, /dev/urandom).
	if len(policy.AllowRWFiles) > 0 {
		rules = append(rules, landlock.RWFiles(policy.AllowRWFiles...).IgnoreIfMissing())
	}

	return rules
}
