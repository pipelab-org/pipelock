// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package contain

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/license"
)

// writePath is one location the managed service writes. value is the
// configured field; path is the write itself, which may be derived from value
// (a sidecar, lock, or parent directory).
type writePath struct {
	field, value, path string
	recorder           bool
}

// describe names the configured value and, when different, the derived write
// so a refusal points the operator at the field they can change.
func (p writePath) describe() string {
	if p.path == p.value {
		return fmt.Sprintf("%q", p.value)
	}
	return fmt.Sprintf("%q (writes %q)", p.value, p.path)
}

// requireContainWritePaths mirrors the writers reachable from managedServiceArgv.
// ReadWritePaths permits only dataDir; the recursive evidence ACL additionally
// requires the recorder to stay at its fixed managed location.
func requireContainWritePaths(env *installEnv, cfg *config.Config, configPath string, dryRun bool) error {
	var paths []writePath
	add := func(field, value, path string) {
		if path != "" {
			paths = append(paths, writePath{field: field, value: value, path: path})
		}
	}
	addFile := func(field, value, path string) {
		if path != "" {
			add(field, value, path)
			// Atomic replacement and sidecar creation write in the parent even
			// when an existing leaf symlink resolves into the data directory.
			add(field, value, filepath.Dir(path))
		}
	}
	if cfg.FlightRecorder.Enabled && cfg.FlightRecorder.Dir != "" {
		paths = append(paths, writePath{field: "flight_recorder.dir", value: cfg.FlightRecorder.Dir, path: cfg.FlightRecorder.Dir, recorder: true})
		// anchor.AppendLocal creates the parent and a "<local_log>.lock" sibling.
		if localLog := strings.TrimSpace(cfg.FlightRecorder.Anchor.LocalLog); localLog != "" {
			addFile("flight_recorder.anchor.local_log", localLog, localLog)
			addFile("flight_recorder.anchor.local_log", localLog, filepath.Clean(localLog)+".lock")
		}
	}
	if cfg.Logging.Output == "file" || cfg.Logging.Output == "both" {
		path := cfg.Logging.File
		if path != "" && !filepath.IsAbs(path) {
			path = filepath.Join(filepath.Dir(managedPipelockConfigPath(env)), path)
		}
		add("logging.file", cfg.Logging.File, path)
	}
	add("rules.rules_dir", cfg.Rules.RulesDir, cfg.Rules.RulesDir)
	if cfg.BehavioralBaseline.Enabled && cfg.BehavioralBaseline.ProfileDir != "" {
		dir := cfg.BehavioralBaseline.ProfileDir
		add("behavioral_baseline.profile_dir", dir, dir)
		key := filepath.Clean(dir) + ".integrity.key"
		addFile("behavioral_baseline.profile_dir", dir, key)
		addFile("behavioral_baseline.profile_dir", dir, key+".generation")
		addFile("behavioral_baseline.profile_dir", dir, key+".generation.lock")
	}
	if cfg.LearnLock.Enabled {
		add("learn_lock.store_dir", cfg.LearnLock.StoreDir, cfg.LearnLock.StoreDir)
	}
	if cfg.Conductor.Enabled {
		add("conductor.bundle_cache_dir", cfg.Conductor.BundleCacheDir, cfg.Conductor.BundleCacheDir)
		add("conductor.durable_audit_queue_dir", cfg.Conductor.DurableAuditQueueDir, cfg.Conductor.DurableAuditQueueDir)
	}
	if cfg.Emit.Forwarder.URL != "" {
		spool := cfg.Emit.Forwarder.SpoolFile
		addFile("emit.forwarder.spool_file", spool, spool)
		if spool != "" {
			addFile("emit.forwarder.spool_file", spool, spool+".lock")
		}
		addFile("emit.forwarder.cursor_file", cfg.Emit.Forwarder.CursorFile, cfg.Emit.Forwarder.CursorFile)
	}
	if cfg.DashboardSnapshot.EnabledWithRecorderDir(cfg.FlightRecorder.Dir) {
		snapshot := cfg.DashboardSnapshot.PathWithRecorderDir(cfg.FlightRecorder.Dir)
		addFile("dashboard_snapshot.path", snapshot, snapshot)
	}
	// Every CRL load advances an anti-rollback high-water beside the CRL: a
	// sidecar, its lock, and a protected state directory. A licensed service
	// whose CRL sits in a read-only directory fails its license check closed.
	// Checked whenever a CRL is configured, which covers every license source.
	if crl := strings.TrimSpace(cfg.LicenseCRLFile); crl != "" {
		highWater := license.CRLHighWaterPath(crl)
		addFile("license_crl_file", crl, highWater)
		addFile("license_crl_file", crl, highWater+".lock")
		addFile("license_crl_file", crl, license.CRLHighWaterAnchorPath(crl))
	}
	for _, p := range paths {
		// A system service without WorkingDirectory runs from /. Only logging.file
		// is resolved relative to the config by config.Load.
		path := p.path
		if !filepath.IsAbs(path) {
			path = filepath.Join(string(os.PathSeparator), path)
		}
		root, err := resolveContainWritePath(env, env.dataDir)
		var resolved string
		if err == nil {
			resolved, err = resolveContainWritePath(env, path)
		}
		if err != nil {
			if dryRun && errors.Is(err, os.ErrPermission) {
				_, _ = fmt.Fprintf(env.out, "  [DEFERRED] %s: cannot resolve %s without privilege; the privileged install must re-check this write path.\n", p.field, p.describe())
				continue
			}
			remedy := ""
			if p.recorder {
				remedy = "; set flight_recorder.dir: " + env.recorderDir() + " and ensure its existing ancestors resolve"
			}
			return fmt.Errorf("contain install config preflight failed for %s: %s %s: resolve write path: %w%s; refusing install", configPath, p.field, p.describe(), err, remedy)
		}
		if p.recorder {
			if resolved != filepath.Join(root, "recorder") {
				return fmt.Errorf("contain install config preflight failed for %s: %s %q must use the fixed managed recorder directory; set flight_recorder.dir: %s and rerun contain install; refusing install", configPath, p.field, p.path, env.recorderDir())
			}
		} else if !pathWithin(root, resolved) {
			return fmt.Errorf("contain install config preflight failed for %s: %s %s is outside the managed writable data directory %s; set %s so that it and every path the service derives from it stay inside %s, then rerun contain install; refusing install", configPath, p.field, p.describe(), env.dataDir, p.field, env.dataDir)
		}
		// Recursive evidence ACLs also grant read access to existing files on
		// reinstall. Keep private state out even when its initial mode is 0600.
		if evidenceDir := evidenceDirContaining(env, root, resolved); evidenceDir != "" {
			allowed := p.recorder
			switch p.field {
			case "flight_recorder.anchor.local_log", "dashboard_snapshot.path":
				allowed = evidenceDir == env.recorderDir()
			case "logging.file":
				allowed = evidenceDir == env.logsDir()
			}
			if !allowed {
				return fmt.Errorf("contain install config preflight failed for %s: %s %s resolves inside operator-readable evidence directory %s; set %s so that it and every path the service derives from it stay inside %s but outside %s and %s, then rerun contain install; refusing install", configPath, p.field, p.describe(), evidenceDir, p.field, env.dataDir, env.logsDir(), env.recorderDir())
			}
		}
	}
	return requirePrivateMaterialOutsideEvidence(env, cfg, configPath, dryRun)
}

// requirePrivateMaterialOutsideEvidence keeps keys, tokens, and other private
// material the service only reads out of the operator evidence ACL. Such paths
// may live outside the data directory; only residence in logs or recorder is
// refused. The inventory is the same one that hides private paths from the agent.
func requirePrivateMaterialOutsideEvidence(env *installEnv, cfg *config.Config, configPath string, dryRun bool) error {
	root, err := resolveContainWritePath(env, env.dataDir)
	if err != nil {
		root = filepath.Clean(env.dataDir)
	}
	for _, secret := range configuredSecrets(cfg, filepath.Dir(managedPipelockConfigPath(env))) {
		if secret.evidence {
			continue
		}
		path := secret.path
		if !filepath.IsAbs(path) {
			path = filepath.Join(string(os.PathSeparator), path)
		}
		resolved, err := resolveContainWritePath(env, path)
		if err != nil {
			// Unresolvable material is judged by its lexical location. That
			// still refuses a path written inside an evidence directory.
			resolved = filepath.Clean(path)
			if dryRun && errors.Is(err, os.ErrPermission) && evidenceDirContaining(env, root, resolved) == "" {
				_, _ = fmt.Fprintf(env.out, "  [DEFERRED] %s: cannot resolve %q without privilege; the privileged install must re-check that it stays outside the evidence directories.\n", secret.field, secret.path)
				continue
			}
		}
		if evidenceDir := evidenceDirContaining(env, root, resolved); evidenceDir != "" {
			return fmt.Errorf("contain install config preflight failed for %s: %s %q resolves inside operator-readable evidence directory %s; move this private material outside %s and %s and set %s to the new location, then rerun contain install; refusing install", configPath, secret.field, secret.path, evidenceDir, env.logsDir(), env.recorderDir(), secret.field)
		}
	}
	return nil
}

// evidenceDirContaining names the evidence directory that receives the
// recursive operator ACL and contains resolved, or returns "". root is the
// resolved data directory; the configured spelling is also checked so a
// lexical fallback path under a symlinked data directory still matches.
func evidenceDirContaining(env *installEnv, root, resolved string) string {
	for _, evidenceDir := range env.evidenceACLDirs() {
		if pathWithin(filepath.Join(root, filepath.Base(evidenceDir)), resolved) || pathWithin(evidenceDir, resolved) {
			return evidenceDir
		}
	}
	return ""
}

// resolveContainWritePath resolves existing ancestors while allowing a missing
// suffix that the service will create. Lstat distinguishes missing paths from
// dangling symlinks: an existing symlink must resolve successfully.
func resolveContainWritePath(env *installEnv, path string) (string, error) {
	clean, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	ancestor := clean
	for {
		_, err := env.lstat(ancestor)
		if err == nil {
			resolved, err := filepath.EvalSymlinks(ancestor)
			if err != nil {
				return "", err
			}
			suffix, err := filepath.Rel(ancestor, clean)
			if err != nil {
				return "", err
			}
			return filepath.Join(resolved, suffix), nil
		}
		if !errors.Is(err, os.ErrNotExist) {
			return "", err
		}
		parent := filepath.Dir(ancestor)
		if parent == ancestor {
			return "", err
		}
		ancestor = parent
	}
}
