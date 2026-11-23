// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package workspacediff

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
)

// ControlSurfaceBudget sets per-workspace limits for a control-path snapshot.
// All limits must be positive. Discovery has its own directory and depth
// limits so general workspace contents cannot exhaust the initial Git scan.
type ControlSurfaceBudget struct {
	MaxControlEntries   int
	MaxControlPathBytes int64
	MaxControlDepth     int
	MaxNestedDirs       int
	MaxNestedDepth      int
}

// DefaultControlSurfaceBudget returns Pipelock's local operational defaults.
// See docs/contain-cli.md for the limits and their reporting semantics.
func DefaultControlSurfaceBudget() ControlSurfaceBudget {
	return ControlSurfaceBudget{
		MaxControlEntries: 16_384, MaxControlPathBytes: 8 << 20, MaxControlDepth: 32,
		MaxNestedDirs: 4_096, MaxNestedDepth: 6,
	}
}

var fixedControlPaths = [...]string{
	".claude", ".mcp.json", ".codex", ".cursor", ".gemini", ".vscode", ".idea",
	".envrc", ".direnv", ".gitmodules", ".gitattributes",
}

type controlEntry struct {
	Entry
	mode fs.FileMode
	info fs.FileInfo
}

type controlPass struct {
	entries    map[string]controlEntry
	unreadable map[string]string
	truncated  string
}

// ControlSurfaceSnapshot is an in-memory observation of the monitored paths
// in one workspace. It can be compared independently of a full tree Manifest.
type ControlSurfaceSnapshot struct {
	root       string
	capBytes   int64
	rootInfo   fs.FileInfo
	rootMount  uint64
	mountKnown bool
	priority   controlPass
	nested     controlPass
	problem    string
}

// ControlSurfaceStatement names changes to observed workspace control paths.
// Paths are relative to the containing workspace statement's root.
type ControlSurfaceStatement struct {
	Changed          bool              `json:"changed"`
	Incomplete       bool              `json:"incomplete"`
	IncompleteReason string            `json:"incomplete_reason,omitempty"`
	Added            []string          `json:"added"`
	Removed          []string          `json:"removed"`
	Modified         []string          `json:"modified"`
	Unreadable       []UnreadableEntry `json:"unreadable"`
	Counts           Counts            `json:"counts"`
}

// Paths returns the sorted union of the observed changed paths.
func (s ControlSurfaceStatement) Paths() []string {
	paths := make([]string, 0, len(s.Added)+len(s.Removed)+len(s.Modified))
	paths = append(paths, s.Added...)
	paths = append(paths, s.Removed...)
	paths = append(paths, s.Modified...)
	slices.Sort(paths)
	return slices.Compact(paths)
}

// SnapshotControlSurface observes root Git metadata and fixed control paths
// first, then searches for nested repositories and nested fixed paths. It
// does not invoke Git or follow symlinks.
func SnapshotControlSurface(root string, capBytes int64, budget ControlSurfaceBudget) (ControlSurfaceSnapshot, error) {
	if capBytes <= 0 || budget.MaxControlEntries <= 0 || budget.MaxControlPathBytes <= 0 ||
		budget.MaxControlDepth <= 0 || budget.MaxNestedDirs <= 0 || budget.MaxNestedDepth <= 0 {
		return ControlSurfaceSnapshot{}, errors.New("workspacediff: control surface limits must be positive")
	}
	abs, err := filepath.Abs(root)
	if err != nil {
		return ControlSurfaceSnapshot{}, fmt.Errorf("resolve workspace root: %w", err)
	}
	snap := ControlSurfaceSnapshot{root: abs, capBytes: capBytes}
	info, err := os.Lstat(abs)
	if err != nil {
		snap.problem = fmt.Sprintf("stat workspace root: %v", err)
		return snap, nil
	}
	if !info.IsDir() {
		snap.problem = "workspace root is not a directory"
		return snap, nil
	}
	handle, err := os.OpenRoot(abs)
	if err != nil {
		snap.problem = fmt.Sprintf("open workspace root: %v", err)
		return snap, nil
	}
	defer func() { _ = handle.Close() }()
	opened, err := handle.Lstat(".")
	if err != nil || !os.SameFile(info, opened) {
		snap.problem = "workspace root identity changed during open"
		return snap, nil
	}
	snap.rootInfo = info
	mnt, mntOK := mountID(abs)
	snap.rootMount, snap.mountKnown = mnt, mntOK
	w := controlWalker{
		root: handle, rootPath: abs, rootMount: mnt, mountKnown: mntOK, rootInfo: info,
		capBytes: capBytes, budget: budget, coveredTrees: make(map[string]struct{}),
		seenConfig: make(map[gitConfigSource]struct{}), seenGitDirs: make(map[gitConfigSource]struct{}),
	}
	snap.priority = w.walkPass(func() {
		w.scanGitMarker(".")
		if w.bareRepository(".") {
			w.scanGitDir(".", ".")
		}
		w.scanFixed(".")
	})
	var discoveryLimit string
	snap.nested = w.walkPass(func() { discoveryLimit = w.discoverNested() })
	snap.nested.truncated = joinIncompleteReasons(discoveryLimit, snap.nested.truncated)
	if w.deviceOnly {
		snap.problem = "mount boundary check unavailable (device-only)"
	}
	current, err := os.Lstat(abs)
	currentMount, currentMountOK := mountID(abs)
	if err != nil || !os.SameFile(info, current) || crossedMount(mnt, currentMount, mntOK, currentMountOK) {
		snap.problem = "workspace root identity or mount changed during observation"
	}
	return snap, nil
}

type controlTree struct {
	path     string
	gitDir   string
	worktree string
}

type controlWalker struct {
	root         *os.Root
	rootPath     string
	rootMount    uint64
	mountKnown   bool
	rootInfo     fs.FileInfo
	deviceOnly   bool
	capBytes     int64
	budget       ControlSurfaceBudget
	pass         controlPass
	entryCount   int
	pathBytes    int64
	trees        []controlTree
	treeEntries  int
	coveredTrees map[string]struct{}
	seenConfig   map[gitConfigSource]struct{}
	seenGitDirs  map[gitConfigSource]struct{}
}

func (w *controlWalker) walkPass(seed func()) controlPass {
	w.pass = controlPass{entries: make(map[string]controlEntry), unreadable: make(map[string]string)}
	w.trees = w.trees[:0]
	w.treeEntries = 0
	seed()
	sort.SliceStable(w.trees, func(i, j int) bool {
		return w.trees[i].path != w.trees[i].gitDir && w.trees[j].path == w.trees[j].gitDir
	})
	// Seed critical paths and config targets before enumerating subtrees.
	// Appending trees from within the loop also keeps discovery breadth-first.
	for i := 0; i < len(w.trees) && w.pass.truncated == ""; i++ {
		tree := w.trees[i]
		w.list(tree.path, func(child string, d fs.DirEntry) bool {
			w.treeEntries++
			if w.treeEntries > w.budget.MaxControlEntries {
				w.truncate("control directory entry limit exceeded")
				return false
			}
			w.scanTreeChild(tree, child, d)
			return w.pass.truncated == ""
		})
	}
	return w.pass
}

func (w *controlWalker) truncate(reason string) {
	if w.pass.truncated == "" {
		w.pass.truncated = reason
	}
}

func (w *controlWalker) unreadable(path, reason string) {
	if _, seen := w.pass.unreadable[path]; seen {
		return
	}
	if len(w.pass.unreadable) == w.budget.MaxControlEntries {
		w.truncate("control unreadable path limit exceeded")
		return
	}
	w.pass.unreadable[path] = reason
}

// lookup observes a child of an inspected directory. Configured multi-part
// paths must first go through recordPath to inspect their prefixes.
func (w *controlWalker) lookup(path string) fs.FileInfo {
	info, err := w.root.Lstat(path)
	if err != nil {
		if !errors.Is(err, fs.ErrNotExist) {
			w.unreadable(path, fmt.Sprintf("stat path: %v", err))
		}
		return nil
	}
	mnt, ok := mountID(filepath.Join(w.rootPath, path))
	if w.checkMount(path, info, mnt, ok) {
		return info
	}
	return nil
}

func (w *controlWalker) checkMount(path string, info fs.FileInfo, mnt uint64, ok bool) bool {
	if crossedMount(w.rootMount, mnt, w.mountKnown, ok) {
		w.unreadable(path, "crossed a mount boundary")
		return false
	}
	if !w.mountKnown || !ok {
		w.deviceOnly = true
		rootDev, _, rootOK := statIDsWithInode(w.rootInfo)
		dev, _, haveDev := statIDsWithInode(info)
		if rootOK && haveDev && rootDev != dev {
			w.unreadable(path, "crossed a device boundary")
			return false
		}
	}
	return true
}

func (w *controlWalker) recordPath(path string) controlEntry {
	dir := "."
	for name := range strings.SplitSeq(path, string(filepath.Separator)) {
		dir = filepath.Join(dir, name)
		info := w.lookup(dir)
		if info == nil {
			return controlEntry{}
		}
		if dir == path || !info.IsDir() {
			entry := w.record(dir, info)
			if dir == path {
				return entry
			}
			// A symlink prefix is itself evidence; its target is out of scope.
			return controlEntry{}
		}
	}
	return controlEntry{}
}

func (w *controlWalker) record(path string, info fs.FileInfo) controlEntry {
	if existing, ok := w.pass.entries[path]; ok {
		if !os.SameFile(existing.info, info) {
			w.unreadable(path, "identity changed during observation")
		}
		return existing
	}
	if w.pass.truncated != "" {
		return controlEntry{}
	}
	if w.entryCount == w.budget.MaxControlEntries {
		w.truncate("control entry limit exceeded")
		return controlEntry{}
	}
	if int64(len(path)) > w.budget.MaxControlPathBytes-w.pathBytes {
		w.truncate("control path-bytes limit exceeded")
		return controlEntry{}
	}
	if 1+strings.Count(path, string(filepath.Separator)) > w.budget.MaxControlDepth {
		w.truncate("control depth limit exceeded")
		return controlEntry{}
	}
	w.entryCount++
	w.pathBytes += int64(len(path))
	e := controlEntry{
		Entry: Entry{Path: path, Size: info.Size(), ModTime: info.ModTime()},
		mode:  info.Mode(), info: info,
	}
	switch {
	case info.IsDir():
		e.Kind = KindDir
	case e.mode&fs.ModeSymlink != 0:
		e.Kind = KindSymlink
		target, err := w.root.Readlink(path)
		if err != nil {
			w.unreadable(path, fmt.Sprintf("read symlink: %v", err))
			return controlEntry{}
		}
		e.Target = target
	case e.mode.IsRegular():
		e.Kind = KindFile
		if info.Size() > w.capBytes {
			e.Oversize = true
		} else {
			dev, ino, ok := statIDsWithInode(info)
			digest, oversize, err := hashFileSafe(w.root, path, filepath.Join(w.rootPath, path), w.capBytes, dev, ino, ok)
			if err != nil {
				w.unreadable(path, fmt.Sprintf("hash file: %v", err))
				return controlEntry{}
			}
			e.Digest, e.Oversize = digest, oversize
		}
		if e.Oversize {
			w.unreadable(path, "file exceeded the control digest cap")
		}
	default:
		e.Kind = KindOther
		w.unreadable(path, "unsupported control path type")
	}
	w.recheck(path, info)
	w.pass.entries[path] = e
	return e
}

func (w *controlWalker) recheck(path string, info fs.FileInfo) {
	current := w.lookup(path)
	if current == nil || !os.SameFile(info, current) || info.Mode() != current.Mode() ||
		(!info.IsDir() && (info.Size() != current.Size() || !info.ModTime().Equal(current.ModTime()))) {
		w.unreadable(path, "identity or metadata changed during observation")
	}
}

// list streams bounded batches even for a directory with millions of entries.
func (w *controlWalker) list(path string, visit func(string, fs.DirEntry) bool) {
	info := w.lookup(path)
	if info == nil || !info.IsDir() {
		w.unreadable(path, "directory changed before enumeration")
		return
	}
	file, err := w.root.OpenFile(path, snapshotOpenFlags, 0)
	if err != nil {
		w.unreadable(path, fmt.Sprintf("open directory: %v", err))
		return
	}
	defer func() { _ = file.Close() }()
	opened, err := file.Stat()
	if err != nil || !os.SameFile(info, opened) {
		w.unreadable(path, "directory identity changed during open")
		return
	}
	mnt, ok := fileMountID(file)
	if !w.checkMount(path, opened, mnt, ok) {
		return
	}
	defer w.recheck(path, info)
	for {
		entries, readErr := file.ReadDir(64)
		for _, d := range entries {
			if !visit(filepath.Join(path, d.Name()), d) {
				return
			}
		}
		if readErr != nil {
			if !errors.Is(readErr, io.EOF) {
				w.unreadable(path, fmt.Sprintf("read directory: %v", readErr))
			}
			return
		}
	}
}

func (w *controlWalker) queueTree(e controlEntry, gitDir, worktree string) {
	if e.Kind != KindDir {
		return
	}
	if _, ok := w.coveredTrees[e.Path]; ok {
		return
	}
	w.coveredTrees[e.Path] = struct{}{}
	w.trees = append(w.trees, controlTree{path: e.Path, gitDir: gitDir, worktree: worktree})
}

func (w *controlWalker) scanFixed(dir string) {
	for _, name := range fixedControlPaths {
		path := filepath.Join(dir, name)
		if info := w.lookup(path); info != nil {
			w.queueTree(w.record(path, info), "", "")
		}
	}
}

func (w *controlWalker) scanGitMarker(dir string) {
	path := filepath.Join(dir, ".git")
	info := w.lookup(path)
	if info == nil {
		return
	}
	if info.IsDir() {
		w.scanGitDir(path, dir)
		return
	}
	e := w.record(path, info)
	if e.Kind == KindFile {
		w.scanGitPointer(e, "gitdir: ", dir, dir)
	}
}

func (w *controlWalker) scanGitDir(dir, worktree string) {
	source := gitConfigSource{path: dir, worktree: worktree}
	if _, seen := w.seenGitDirs[source]; seen {
		return
	}
	e := w.recordPath(dir)
	if e.Kind != KindDir {
		return
	}
	w.seenGitDirs[source] = struct{}{}
	configs := []controlEntry{
		w.recordPath(filepath.Join(dir, "config")),
		w.recordPath(filepath.Join(dir, "config.worktree")),
	}
	for _, config := range configs {
		if value, set := w.configuredWorktree(config); set {
			// An outside working tree has no relative paths to inspect.
			worktree, _ = w.workspaceTarget(dir, value)
		}
	}
	w.queueTree(e, dir, worktree)
	for _, config := range configs {
		w.scanGitConfig(config, dir, worktree)
	}
	if common := w.recordPath(filepath.Join(dir, "commondir")); common.Kind == KindFile {
		w.scanGitPointer(common, "", dir, worktree)
	}
	for _, name := range []string{"hooks", "info", "objects/info", "modules", "worktrees"} {
		child := w.recordPath(filepath.Join(dir, filepath.FromSlash(name)))
		w.queueTree(child, dir, worktree)
	}
}

func (w *controlWalker) scanTreeChild(tree controlTree, path string, listed fs.DirEntry) {
	info := w.lookup(path)
	if info == nil {
		if _, excluded := w.pass.unreadable[path]; !excluded {
			w.unreadable(path, "directory entry vanished during enumeration")
		}
		return
	}
	if info.Mode().Type() != listed.Type() {
		w.unreadable(path, "directory entry type changed during enumeration")
	}
	if tree.gitDir != "" {
		rel, _ := filepath.Rel(tree.gitDir, path)
		rel = filepath.ToSlash(rel)
		if volatileGitEntry(rel, info.Mode()) {
			return
		}
		if info.IsDir() && w.gitMetadataChild(path, rel) {
			worktree := tree.worktree
			if strings.HasPrefix(rel, "worktrees/") {
				worktree = w.linkedWorktree(path)
			}
			w.scanGitDir(path, worktree)
			return
		}
	}
	e := w.record(path, info)
	w.queueTree(e, tree.gitDir, tree.worktree)
}

func (w *controlWalker) gitMetadataChild(path, rel string) bool {
	if strings.HasPrefix(rel, "worktrees/") && strings.Count(rel, "/") == 1 {
		return true
	}
	return strings.HasPrefix(rel, "modules/") &&
		(w.lookup(filepath.Join(path, "HEAD")) != nil || w.bareRepository(path))
}

func (w *controlWalker) bareRepository(path string) bool {
	head := w.lookup(filepath.Join(path, "HEAD"))
	if head == nil || !head.Mode().IsRegular() {
		return false
	}
	objects := w.lookup(filepath.Join(path, "objects"))
	if objects == nil || !objects.IsDir() {
		return false
	}
	config := w.lookup(filepath.Join(path, "config"))
	refs := w.lookup(filepath.Join(path, "refs"))
	return (config != nil && config.Mode().IsRegular()) || (refs != nil && refs.IsDir())
}

func (w *controlWalker) discoverNested() string {
	type directory struct {
		path  string
		depth int
	}
	queue := []directory{{path: "."}}
	// Bound wide, flat directories too. MaxNestedDirs bounds the queue and
	// this derived limit bounds the number of directory entries read from it.
	var listed int64
	var limit string
	for i := 0; i < len(queue) && w.pass.truncated == ""; i++ {
		dir := queue[i]
		if _, covered := w.coveredTrees[dir.path]; covered {
			continue
		}
		if dir.depth > 0 {
			if w.bareRepository(dir.path) {
				w.scanGitDir(dir.path, dir.path)
				continue
			}
			w.scanGitMarker(dir.path)
			w.scanFixed(dir.path)
		}
		w.list(dir.path, func(child string, d fs.DirEntry) bool {
			listed++
			if (listed-1)/64 >= int64(w.budget.MaxNestedDirs) {
				limit = "nested directory entry limit exceeded"
				return false
			}
			if !d.IsDir() {
				return true
			}
			if _, covered := w.coveredTrees[child]; covered {
				return true
			}
			if dir.depth >= w.budget.MaxNestedDepth || len(queue) >= w.budget.MaxNestedDirs {
				if limit == "" {
					limit = "nested directory count or depth limit exceeded"
				}
				return true
			}
			queue = append(queue, directory{path: child, depth: dir.depth + 1})
			return true
		})
	}
	return limit
}

func volatileGitEntry(path string, mode fs.FileMode) bool {
	if mode.IsDir() {
		switch path {
		case "objects/pack", "objects/info/commit-graphs", "refs", "logs", "reftable", "rr-cache":
			return true
		}
		digits, objectShard := strings.CutPrefix(path, "objects/")
		return objectShard && len(digits) == 2 && lowercaseHex(digits)
	}
	if mode.IsRegular() {
		switch path {
		case "HEAD", "index", "packed-refs", "FETCH_HEAD", "ORIG_HEAD", "COMMIT_EDITMSG",
			"MERGE_HEAD", "MERGE_MSG", "MERGE_MODE", "MERGE_RR", "SQUASH_MSG", "AUTO_MERGE",
			"CHERRY_PICK_HEAD", "REVERT_HEAD", "TAG_EDITMSG", "NOTES_EDITMSG", "gc.log", "gc.pid",
			"objects/info/packs", "objects/info/commit-graph", "info/refs":
			return true
		}
		digits, sharedIndex := strings.CutPrefix(path, "sharedindex.")
		return sharedIndex && (len(digits) == 40 || len(digits) == 64) && lowercaseHex(digits)
	}
	return false
}

func lowercaseHex(s string) bool {
	return strings.IndexFunc(s, func(r rune) bool {
		return (r < '0' || r > '9') && (r < 'a' || r > 'f')
	}) == -1
}

// DiffControlSurface compares each pass even when another pass was truncated.
// Only paths observed at both endpoints can be compared for modification in a
// truncated pass. A fully collected pass can still report additions/removals.
func DiffControlSurface(before, after ControlSurfaceSnapshot) (ControlSurfaceStatement, error) {
	if before.root == "" || before.root != after.root || before.capBytes != after.capBytes {
		return ControlSurfaceStatement{}, errors.New("workspacediff: incompatible control surface snapshots")
	}
	s := ControlSurfaceStatement{Added: []string{}, Removed: []string{}, Modified: []string{}, Unreadable: []UnreadableEntry{}}
	var identityReason string
	if before.rootInfo != nil && after.rootInfo != nil &&
		(!os.SameFile(before.rootInfo, after.rootInfo) ||
			crossedMount(before.rootMount, after.rootMount, before.mountKnown, after.mountKnown)) {
		identityReason = "workspace root identity or mount changed between observations"
	}
	var priorityDiff, nestedDiff controlPassDiff
	if before.rootInfo != nil && after.rootInfo != nil && identityReason == "" {
		priorityDiff = compareControlPass(before.priority, after.priority)
		nestedDiff = compareControlPass(before.nested, after.nested)
	}
	s.Added = mergeControlPaths(s.Added, priorityDiff.added, nestedDiff.added)
	s.Removed = mergeControlPaths(s.Removed, priorityDiff.removed, nestedDiff.removed)
	s.Modified = mergeControlPaths(s.Modified, priorityDiff.modified, nestedDiff.modified)
	s.Unreadable = mergeUnreadable(
		collectControlUnreadable(before.priority, before.nested),
		collectControlUnreadable(after.priority, after.nested),
	)
	s.Counts = Counts{Added: len(s.Added), Removed: len(s.Removed), Modified: len(s.Modified), Unreadable: len(s.Unreadable)}
	s.Changed = len(s.Added)+len(s.Removed)+len(s.Modified) > 0
	var unreadableReason string
	if len(s.Unreadable) > 0 {
		unreadableReason = "unreadable control paths"
	}
	s.IncompleteReason = joinIncompleteReasons(before.problem, after.problem, identityReason, unreadableReason,
		before.priority.truncated, after.priority.truncated, before.nested.truncated, after.nested.truncated)
	s.Incomplete = s.IncompleteReason != ""
	return s, nil
}

type controlPassDiff struct {
	added, removed, modified []string
}

func compareControlPass(before, after controlPass) controlPassDiff {
	var diff controlPassDiff
	excluded := excludedPrefixes(collectControlUnreadable(before), collectControlUnreadable(after))
	complete := before.truncated == "" && after.truncated == ""
	for path, b := range before.entries {
		a, seen := after.entries[path]
		if seen && (b.mode != a.mode || entryChanged(b.Entry, a.Entry)) {
			diff.modified = append(diff.modified, path)
		}
		if !seen && complete && !withinExcluded(path, excluded) {
			diff.removed = append(diff.removed, path)
		}
	}
	for path := range after.entries {
		if _, seen := before.entries[path]; !seen && complete && !withinExcluded(path, excluded) {
			diff.added = append(diff.added, path)
		}
	}
	return diff
}

func collectControlUnreadable(passes ...controlPass) []UnreadableEntry {
	var entries []UnreadableEntry
	for _, pass := range passes {
		for path, reason := range pass.unreadable {
			entries = append(entries, UnreadableEntry{Path: path, Reason: reason})
		}
	}
	return entries
}

func mergeControlPaths(out, a, b []string) []string {
	out = append(out, a...)
	out = append(out, b...)
	slices.Sort(out)
	return slices.Compact(out)
}
