// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package contain

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
)

// systemd.exec(5), Credentials, defines /run/credentials/UNITNAME for system
// services. systemd v257 namespace.c:2675-2701 masks the parent with a private
// read-only tmpfs and binds only the invoking unit's store. exec-credential.c
// and shared/mount-util.c create a read-only tmpfs/ramfs containing regular files.
func checkSystemdCredentials(env netnsAssertEnv, mounts map[string]runtimeMount, hostDevices map[string]bool) (string, error) {
	// These services are operator-written, not named by contain install. The
	// kernel's unified cgroup path supplies identity for both the root pre-start
	// signer and the unprivileged launcher. Never trust CREDENTIALS_DIRECTORY or
	// a caller-supplied unit name. A hidden/legacy identity refuses this exception.
	unit := processSystemdUnit(env.readFile, "/proc/self/cgroup")
	if !strings.HasSuffix(unit, ".service") || unit == ".service" || strings.ContainsAny(unit, "/\x00\r\n\t ") {
		return "", unexpectedRuntimeExposure(systemdCredentialsPath, "credentials require a visible service unit identity in /proc/self/cgroup")
	}
	path := systemdCredentialsPath + "/" + unit
	parent, ok := mounts[systemdCredentialsPath]
	if !ok || parent.filesystem != "tmpfs" || parent.root != "/" || !slices.Contains(parent.options, "ro") || hostDevices[parent.device] {
		return "", unexpectedRuntimeExposure(systemdCredentialsPath, "credentials parent must be a private read-only tmpfs mask rooted at /")
	}
	mount, ok := mounts[path]
	if !ok || mount.root != "/" || (mount.filesystem != "tmpfs" && mount.filesystem != "ramfs") || !slices.Contains(mount.options, "ro") || mount.device == parent.device {
		return "", unexpectedRuntimeExposure(path, "this unit's credentials must have their own read-only tmpfs or ramfs mount rooted at /")
	}
	if env.lstat == nil {
		return "", fmt.Errorf("%w: credential stat reader is unavailable", errRuntimeMountEvidenceUnavailable)
	}
	for _, dir := range []string{systemdCredentialsPath, path} {
		info, err := env.lstat(dir)
		if err != nil {
			return "", fmt.Errorf("%w: inspect credentials directory %s: %w", errRuntimeMountEvidenceUnavailable, dir, err)
		}
		uid, known := fileOwnerUID(info)
		// tmpfs ACLs can grant the service access while retaining root ownership;
		// their mask may set group read/search bits. Ownership-fallback stores are
		// deliberately unsupported. The parent is systemd's mode=0755 mask.
		if !known || uid != 0 || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o022 != 0 {
			return "", unexpectedRuntimeExposure(dir, "credentials directories must be root-owned directories without group or other write permission")
		}
	}
	if err := checkRuntimeDirectoryEntry(env, systemdCredentialsPath, unit, true); err != nil {
		return "", err
	}
	entries, err := env.readDir(path)
	if err != nil {
		return "", fmt.Errorf("%w: inspect credentials contents %s: %w", errRuntimeMountEvidenceUnavailable, path, err)
	}
	for _, entry := range entries {
		file := filepath.Join(path, entry.Name())
		info, err := env.lstat(file)
		if err != nil {
			return "", fmt.Errorf("%w: inspect credential %s: %w", errRuntimeMountEvidenceUnavailable, file, err)
		}
		uid, known := fileOwnerUID(info)
		if !known || uid != 0 || !info.Mode().IsRegular() || info.Mode().Perm()&0o022 != 0 {
			return "", unexpectedRuntimeExposure(file, "credentials must be root-owned regular files without group or other write permission")
		}
	}
	return path, nil
}
