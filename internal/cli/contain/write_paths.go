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
)

// requireContainWritePaths mirrors the writers reachable from managedServiceArgv.
// ReadWritePaths permits only dataDir; the recursive evidence ACL additionally
// requires the recorder to stay at its fixed managed location.
func requireContainWritePaths(env *installEnv, cfg *config.Config, configPath string, dryRun bool) error {
	type writePath struct {
		field, path string
		recorder    bool
	}
	var paths []writePath
	add := func(field, path string) {
		if path != "" {
			paths = append(paths, writePath{field: field, path: path})
		}
	}
	addFile := func(field, path string) {
		if path != "" {
			add(field, path)
			// Atomic replacement and sidecar creation write in the parent even
			// when an existing leaf symlink resolves into the data directory.
			add(field, filepath.Dir(path))
		}
	}
	if cfg.FlightRecorder.Enabled && cfg.FlightRecorder.Dir != "" {
		paths = append(paths, writePath{"flight_recorder.dir", cfg.FlightRecorder.Dir, true})
		add("flight_recorder.anchor.local_log", strings.TrimSpace(cfg.FlightRecorder.Anchor.LocalLog))
	}
	if cfg.Logging.Output == "file" || cfg.Logging.Output == "both" {
		path := cfg.Logging.File
		if path != "" && !filepath.IsAbs(path) {
			path = filepath.Join(filepath.Dir(managedPipelockConfigPath(env)), path)
		}
		add("logging.file", path)
	}
	add("rules.rules_dir", cfg.Rules.RulesDir)
	if cfg.BehavioralBaseline.Enabled && cfg.BehavioralBaseline.ProfileDir != "" {
		add("behavioral_baseline.profile_dir", cfg.BehavioralBaseline.ProfileDir)
		key := filepath.Clean(cfg.BehavioralBaseline.ProfileDir) + ".integrity.key"
		addFile("behavioral_baseline.profile_dir", key)
		addFile("behavioral_baseline.profile_dir", key+".generation")
		addFile("behavioral_baseline.profile_dir", key+".generation.lock")
	}
	if cfg.LearnLock.Enabled {
		add("learn_lock.store_dir", cfg.LearnLock.StoreDir)
	}
	if cfg.Conductor.Enabled {
		add("conductor.bundle_cache_dir", cfg.Conductor.BundleCacheDir)
		add("conductor.durable_audit_queue_dir", cfg.Conductor.DurableAuditQueueDir)
	}
	if cfg.Emit.Forwarder.URL != "" {
		addFile("emit.forwarder.spool_file", cfg.Emit.Forwarder.SpoolFile)
		if cfg.Emit.Forwarder.SpoolFile != "" {
			addFile("emit.forwarder.spool_file", cfg.Emit.Forwarder.SpoolFile+".lock")
		}
		addFile("emit.forwarder.cursor_file", cfg.Emit.Forwarder.CursorFile)
	}
	if cfg.DashboardSnapshot.EnabledWithRecorderDir(cfg.FlightRecorder.Dir) {
		addFile("dashboard_snapshot.path", cfg.DashboardSnapshot.PathWithRecorderDir(cfg.FlightRecorder.Dir))
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
				_, _ = fmt.Fprintf(env.out, "  [DEFERRED] %s: cannot resolve %q without privilege; the privileged install must re-check this write path.\n", p.field, p.path)
				continue
			}
			remedy := ""
			if p.recorder {
				remedy = "; set flight_recorder.dir: " + env.recorderDir() + " and ensure its existing ancestors resolve"
			}
			return fmt.Errorf("contain install config preflight failed for %s: %s %q: resolve write path: %w%s; refusing install", configPath, p.field, p.path, err, remedy)
		}
		if p.recorder {
			if resolved != filepath.Join(root, "recorder") {
				return fmt.Errorf("contain install config preflight failed for %s: %s %q must use the fixed managed recorder directory; set flight_recorder.dir: %s and rerun contain install; refusing install", configPath, p.field, p.path, env.recorderDir())
			}
		} else if !pathWithin(root, resolved) {
			return fmt.Errorf("contain install config preflight failed for %s: %s %q is outside the managed writable data directory %s; set %s to a path inside %s and rerun contain install; refusing install", configPath, p.field, p.path, env.dataDir, p.field, env.dataDir)
		}
	}
	return nil
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
