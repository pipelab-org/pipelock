// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package contain

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

const defaultDisplayTmpfilesPath = "/etc/tmpfiles.d/pipelock-agent-display.conf"

// systemd tmpfiles.d(5): d creates a directory without removing its contents;
// mode, user and group apply at boot before systemd-tmpfiles-setup.service ends.
func renderDisplayRuntimeRule(socket string) []byte {
	return []byte(displayUnitMarker + "\nd " + filepath.Dir(displayRFBPath(socket)) + " 0730 root " + viewerUserName + " - -\n")
}

func displayRuntimeRulePath(path string) string {
	if path == "" {
		return defaultDisplayTmpfilesPath
	}
	return path
}

func readDisplayRuntimeRule(stat func(string) (os.FileInfo, error), read func(string) ([]byte, error), path string) ([]byte, bool, error) {
	info, err := stat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, fmt.Errorf("stat display tmpfiles rule: %w", err)
	}
	if !info.Mode().IsRegular() || info.Mode() != 0o600 {
		return nil, false, fmt.Errorf("display tmpfiles rule %s must be a regular root:root file with mode 0600; repair or move aside the unsafe rule before rerunning contain install", path)
	}
	uid, uidOK := fileOwnerUID(info)
	gid, gidOK := fileOwnerGID(info)
	if !uidOK || !gidOK || uid != 0 || gid != 0 {
		return nil, false, fmt.Errorf("display tmpfiles rule %s must be owned by root:root; repair or move aside the unsafe rule before rerunning contain install", path)
	}
	body, err := read(path)
	if err != nil {
		return nil, false, fmt.Errorf("read display tmpfiles rule: %w", err)
	}
	if !strings.HasPrefix(string(body), displayUnitMarker+"\n") {
		return nil, false, fmt.Errorf("display tmpfiles rule %s is not Pipelock-managed", path)
	}
	return body, true, nil
}

func checkDisplayRuntimeRule(stat func(string) (os.FileInfo, error), read func(string) ([]byte, error), path, socket string) error {
	path = displayRuntimeRulePath(path)
	body, exists, err := readDisplayRuntimeRule(stat, read, path)
	if err != nil {
		return err
	}
	if !exists || !bytes.Equal(body, renderDisplayRuntimeRule(socket)) {
		return fmt.Errorf("display tmpfiles rule %s is missing or differs from the managed rule; rerun contain install", path)
	}
	return nil
}

// Validate the whole root-controlled hierarchy before writing or invoking
// tmpfiles. Do not let tmpfiles repair ownership of an attacker-owned path.
func checkDisplayRuntimeParents(env *installEnv, path string) error {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return fmt.Errorf("display tmpfiles path %s must be absolute and clean", path)
	}
	for current := filepath.Dir(path); ; current = filepath.Dir(current) {
		info, err := env.lstat(current)
		if errors.Is(err, os.ErrNotExist) {
			// Only the immediate tmpfiles.d directory may be absent.
			if current != filepath.Dir(path) {
				return fmt.Errorf("display tmpfiles parent %s missing", current)
			}
		} else if err != nil {
			return err
		} else if uid, ok := fileOwnerUID(info); !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || !ok || uid != 0 || info.Mode().Perm()&0o022 != 0 {
			return fmt.Errorf("display tmpfiles parent %s is not a root-controlled directory", current)
		}
		if current == string(os.PathSeparator) {
			return nil
		}
	}
}

func removeDisplayRuntimeRule(env *installEnv) error {
	path := displayRuntimeRulePath(env.displayTmpfilesPath)
	_, exists, err := readDisplayRuntimeRule(env.lstat, env.readFile, path)
	if err != nil || !exists {
		return err
	}
	if err := checkDisplayRuntimeParents(env, path); err != nil {
		return err
	}
	return env.removeFile(path)
}

// The runtime rule and display are one install transaction: rollback restores
// prior rule bytes before an old display can restart. A removed or drifted
// managed rule is still prior state, even when it differs from today's render.
func stepProvisionDisplay() step {
	runtime, display := stepProvisionDisplayRuntime(), stepProvisionAgentDisplay()
	var runtimeChanged, displayChanged bool
	return step{
		name: display.name,
		desc: "provision the optional agent display and its boot-time runtime directory",
		apply: func(ctx context.Context, env *installEnv) (bool, error) {
			runtimeChanged, displayChanged = false, false
			env.prevDisplayStateKnown = false
			var err error
			runtimeChanged, err = runtime.apply(ctx, env)
			if err != nil {
				return runtimeChanged, err
			}
			displayChanged, err = display.apply(ctx, env)
			return runtimeChanged || displayChanged, err
		},
		undo: func(ctx context.Context, env *installEnv) error {
			if displayChanged {
				if err := runSystemctlCleanupUnit(ctx, env, "stop", filepath.Base(env.displayUnitPath)); err != nil {
					return err
				}
			}
			if runtimeChanged {
				if err := runtime.undo(ctx, env); err != nil {
					restoreErr := fmt.Errorf("restore display runtime before restarting display: %w", err)
					// A confirmed fresh display has no prior service to restart.
					// Remove its new unit even when runtime cleanup is refused.
					if displayChanged && env.prevDisplayStateKnown && !env.prevDisplayUnitExisted && !env.prevDisplayActive {
						return errors.Join(restoreErr, display.undo(ctx, env))
					}
					return restoreErr
				}
			}
			if displayChanged {
				return display.undo(ctx, env)
			}
			return nil
		},
	}
}

// Runtime prerequisites remain inspectable while the display is stopped and
// its socket is absent. Only a verified rule may recreate an absent directory.
func checkDisplayRuntime(stat func(string) (os.FileInfo, error), read func(string) ([]byte, error), lookup lookupUserFunc, rule, socket string) doctorResult {
	socket = displayRFBPath(socket)
	rule = displayRuntimeRulePath(rule)
	_, dirErr := stat(filepath.Dir(socket))
	missing := errors.Is(dirErr, os.ErrNotExist)
	if !missing {
		if err := checkRFBRuntimeDirectory(stat, lookup, socket); err != nil {
			return fail(classInfra, err.Error(), displayRuntimeRepair(socket))
		}
	}
	if err := checkDisplayRuntimeRule(stat, read, rule, socket); err != nil {
		return fail(classInfra, err.Error(), "restore a regular root:root 0600 managed rule at "+rule+"; rerun contain install")
	}
	if missing {
		return fail(classInfra, "RFB runtime directory is missing", "run systemd-tmpfiles --create "+rule+"; then restart the display service")
	}
	return pass("RFB runtime directory and managed rule are valid")
}

func displayRuntimeRepair(socket string) string {
	return "inspect " + filepath.Dir(displayRFBPath(socket)) + ", move it aside if its contents are untrusted, then rerun contain install"
}

func stepProvisionDisplayRuntime() step {
	var previous []byte
	var existed, changed, runtimeCreated, priorManagedXvnc bool
	return step{
		name: "provision-display-runtime",
		desc: "persist the root-owned Xvnc runtime directory across reboot",
		apply: func(ctx context.Context, env *installEnv) (bool, error) {
			changed = false
			runtimeCreated = false
			priorManagedXvnc = false
			cfg, err := loadContainmentDisplay(env)
			if err != nil {
				return false, err
			}
			path := displayRuntimeRulePath(env.displayTmpfilesPath)
			previous, existed, err = readDisplayRuntimeRule(env.lstat, env.readFile, path)
			if err != nil {
				return false, err
			}
			if existed {
				if err := checkDisplayRuntimeParents(env, path); err != nil {
					return false, err
				}
			}
			if !cfg.IsEnabled(xvfbInstalled(env)) || cfg.EffectiveBackend() != "xvnc" {
				if existed {
					err = env.removeFile(path)
					changed = err == nil
				}
				return changed, err
			}
			if err := checkDisplayRuntimeParents(env, path); err != nil {
				return false, err
			}
			runtime := filepath.Dir(displayRFBPath(env.rfbSocketPath))
			if err := checkDisplayRuntimeParents(env, runtime); err != nil {
				return false, err
			}
			if err := rejectSymlinkParents(env, filepath.Join(runtime, "rfb.sock")); err != nil {
				return false, err
			}
			_, runtimeErr := env.lstat(runtime)
			if err := runtimeErr; !errors.Is(err, os.ErrNotExist) {
				if err != nil {
					return false, err
				}
				if err := checkRFBRuntimeDirectory(env.lstat, env.lookupUser, displayRFBPath(env.rfbSocketPath)); err != nil {
					return false, fmt.Errorf("%w; %s", err, displayRuntimeRepair(env.rfbSocketPath))
				}
			}
			body := renderDisplayRuntimeRule(env.rfbSocketPath)
			if !existed || !bytes.Equal(previous, body) {
				if err := env.mkdirAll(filepath.Dir(path), 0o750); err != nil {
					return false, err
				}
				if err := env.writeFile(path, body, 0o600); err != nil {
					return false, err
				}
				changed = true
				if err := env.ownLeafNoFollow(path, 0o600, 0, 0); err != nil {
					return true, err
				}
			}
			runtimeCreated = errors.Is(runtimeErr, os.ErrNotExist)
			if runtimeCreated {
				// renderAgentDisplayUnit's managed marker and RFB argument identify
				// an old Xvnc display whose restored unit still needs this bind source.
				oldUnit, readErr := env.readFile(env.displayUnitPath)
				priorManagedXvnc = readErr == nil && strings.HasPrefix(string(oldUnit), displayUnitMarker+"\n") && strings.Contains(string(oldUnit), " -rfbunixpath "+displayRFBPath(env.rfbSocketPath)+" ")
			}
			if err := runOrErr(ctx, env, "systemd-tmpfiles", "--create", path); err != nil {
				return changed || runtimeCreated, err
			}
			return changed || runtimeCreated, checkRFBRuntimeDirectory(env.lstat, env.lookupUser, displayRFBPath(env.rfbSocketPath))
		},
		undo: func(ctx context.Context, env *installEnv) error {
			var cleanupErr error
			// Retain a validated recreated bind source when rollback restores a
			// previously active managed Xvnc. Fresh installs still remove their dir.
			if runtimeCreated {
				if priorManagedXvnc && env.prevDisplayStateKnown && env.prevDisplayActive {
					cleanupErr = checkRFBRuntimeDirectory(env.lstat, env.lookupUser, displayRFBPath(env.rfbSocketPath))
				} else {
					cleanupErr = removeEmptyDisplayRuntime(ctx, env)
				}
			}
			if !changed {
				return cleanupErr
			}
			path := displayRuntimeRulePath(env.displayTmpfilesPath)
			if !existed {
				return errors.Join(cleanupErr, removeDisplayRuntimeRule(env))
			}
			if err := env.writeFile(path, previous, 0o600); err != nil {
				return errors.Join(cleanupErr, err)
			}
			return errors.Join(cleanupErr, env.ownLeafNoFollow(path, 0o600, 0, 0))
		},
	}
}

// Only remove an empty directory created by this attempt or identified by its
// managed rule or the recorded viewer account being removed. systemctl(1) defines inactive as stopped and failed as its
// failed equivalent; every other state preserves the directory.
func removeEmptyDisplayRuntime(ctx context.Context, env *installEnv) error {
	runtime := filepath.Dir(displayRFBPath(env.rfbSocketPath))
	if _, err := env.lstat(runtime); errors.Is(err, os.ErrNotExist) {
		return nil
	} else if err != nil {
		return err
	}
	unit := filepath.Base(env.displayUnitPath)
	out, code, err := env.runCmd(ctx, "systemctl", "is-active", unit)
	state := strings.TrimSpace(out)
	if err != nil || (state != "inactive" && state != "failed" && !systemctlReportsUnitAbsent(out, unit)) {
		return fmt.Errorf("preserve display runtime directory: %s is not confirmed stopped (exit %d): %w", unit, code, errors.Join(err, fmt.Errorf("state %q", state)))
	}
	if err := checkDisplayRuntimeParents(env, runtime); err != nil {
		return err
	}
	if err := checkRFBRuntimeDirectory(env.lstat, env.lookupUser, displayRFBPath(env.rfbSocketPath)); err != nil {
		return err
	}
	entries, err := env.readDir(runtime)
	if err != nil {
		return err
	}
	if len(entries) != 0 {
		return fmt.Errorf("preserve nonempty display runtime directory %s; inspect its contents before removal", runtime)
	}
	return env.removeFile(runtime)
}
