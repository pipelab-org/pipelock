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
	// MaxNestedPathBytes bounds the path strings discovery keeps queued, so a
	// few hundred thousand directories with long names cannot exhaust memory.
	MaxNestedPathBytes int64
}

// DefaultControlSurfaceBudget returns Pipelock's local operational defaults.
// See docs/contain-cli.md for the limits and their reporting semantics.
func DefaultControlSurfaceBudget() ControlSurfaceBudget {
	return ControlSurfaceBudget{
		MaxControlEntries: 16_384, MaxControlPathBytes: 8 << 20, MaxControlDepth: 32,
		MaxNestedDirs: 200_000, MaxNestedDepth: 64, MaxNestedPathBytes: 64 << 20,
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
	entries        map[string]controlEntry
	unreadable     map[string]string
	truncated      string
	undiscovered   map[string]struct{}
	partlyListed   map[string]struct{}
	discoveryLimit string
	// sources names, for a path found through a reference such as a Git
	// configuration's include or hooks path, the paths whose contents led to it.
	// Discovery finds a path only if it also examines those paths.
	sources map[string][]string
}

// ControlSurfaceSnapshot is an in-memory observation of the monitored paths
// in one workspace. It can be compared independently of a full tree Manifest.
type ControlSurfaceSnapshot struct {
	root     string
	capBytes int64
	identity controlRootIdentity
	priority controlPass
	nested   controlPass
	problem  string
}

// ControlSurfaceStatement names changes to observed workspace control paths.
// Paths are relative to the containing workspace statement's root.
type ControlSurfaceStatement struct {
	Changed                bool              `json:"changed"`
	Incomplete             bool              `json:"incomplete"`
	IncompleteReason       string            `json:"incomplete_reason,omitempty"`
	NestedDiscoveryPartial bool              `json:"nested_discovery_partial,omitempty"`
	NestedDiscoveryReason  string            `json:"nested_discovery_reason,omitempty"`
	Added                  []string          `json:"added"`
	Removed                []string          `json:"removed"`
	Modified               []string          `json:"modified"`
	Unreadable             []UnreadableEntry `json:"unreadable"`
	Counts                 Counts            `json:"counts"`
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
// does not invoke Git or follow symlinks outside the workspace.
func SnapshotControlSurface(root string, capBytes int64, budget ControlSurfaceBudget) (ControlSurfaceSnapshot, error) {
	if capBytes <= 0 || budget.MaxControlEntries <= 0 || budget.MaxControlPathBytes <= 0 ||
		budget.MaxControlDepth <= 0 || budget.MaxNestedDirs <= 0 || budget.MaxNestedDepth <= 0 ||
		budget.MaxNestedPathBytes <= 0 {
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
	dev, ino, idsKnown := statIDsWithInode(info)
	mnt, mntOK := mountID(abs)
	snap.identity = controlRootIdentity{Dev: dev, Ino: ino, IDsKnown: idsKnown, Mount: mnt, MountKnown: mntOK, BootID: workspaceBootID()}
	w := controlWalker{
		root: handle, rootPath: abs, rootMount: mnt, mountKnown: mntOK, rootInfo: info,
		capBytes: capBytes, budget: budget, coveredTrees: make(map[string]struct{}),
		seenConfig: make(map[gitConfigSource]struct{}), seenGitDirs: make(map[gitConfigSource]struct{}),
	}
	snap.priority = w.walkPass(func() {
		w.scanGitMarker(".")
		if w.bareRepository(".") {
			w.scanGitDir(".", ".", false)
		}
		w.scanFixed(".")
	})
	snap.nested = w.walkPass(w.discoverNested)
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
	fixed    bool
	// source is the path whose contents referenced this tree, if any.
	source string
	// walked is set once the walk has listed the tree.
	walked bool
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
	trees        []*controlTree
	queuedTrees  map[string]*controlTree
	treeEntries  int
	coveredTrees map[string]struct{}
	// worktreeSlots are agent worktree checkouts found inside fixed control
	// trees. Their root control paths are scanned with the fixed tree; nested
	// discovery continues below them so their deeper control paths are seen.
	worktreeSlots []string
	discovery     *nestedDiscovery
	seenConfig    map[gitConfigSource]struct{}
	seenGitDirs   map[gitConfigSource]struct{}
	// source is the path whose contents the walker is following, so what it
	// records or queues can be traced back to it.
	source string
	// direct holds the paths, and the trees whose whole content, that discovery
	// reached on its own rather than through a reference.
	direct map[string]struct{}
}

func (w *controlWalker) walkPass(seed func()) controlPass {
	w.pass = controlPass{
		entries: make(map[string]controlEntry), unreadable: make(map[string]string),
		sources: make(map[string][]string),
	}
	w.source = ""
	w.direct = make(map[string]struct{})
	w.trees = w.trees[:0]
	w.queuedTrees = make(map[string]*controlTree)
	w.treeEntries = 0
	w.discovery = nil
	seed()
	sort.SliceStable(w.trees, func(i, j int) bool {
		return w.trees[i].path != w.trees[i].gitDir && w.trees[j].path == w.trees[j].gitDir
	})
	// Seed critical paths and config targets before enumerating subtrees.
	// Appending trees from within the loop also keeps discovery breadth-first.
	// Walking a tree can find an agent worktree checkout, so discovery resumes
	// until neither it nor the trees have work left.
	next := 0
	for w.pass.truncated == "" {
		for ; next < len(w.trees) && w.pass.truncated == ""; next++ {
			queued := w.trees[next]
			queued.walked = true
			tree := *queued
			w.source = tree.source
			w.list(tree.path, func(child string, d fs.DirEntry) bool {
				w.treeEntries++
				if w.treeEntries > w.budget.MaxControlEntries {
					w.truncate(child, "control directory entry limit exceeded")
					return false
				}
				w.scanTreeChild(tree, child, d)
				return w.pass.truncated == ""
			})
			w.source = ""
		}
		if w.pass.truncated != "" || w.discovery == nil || !w.discovery.pending() {
			break
		}
		w.discovery.run()
	}
	w.dropSourcesOfDirectPaths()
	return w.pass
}

// dropSourcesOfDirectPaths forgets the references behind a path that discovery
// also reached on its own, in whatever order the two happened. A reference may
// be the first way a path was recorded, but it is not what makes the path
// observable, so a snapshot that never followed the reference still covers it.
func (w *controlWalker) dropSourcesOfDirectPaths() {
	for path := range w.pass.sources {
		for p := path; ; p = filepath.Dir(p) {
			if _, direct := w.direct[p]; direct {
				delete(w.pass.sources, path)
				break
			}
			if p == "." {
				break
			}
		}
	}
}

func (w *controlWalker) truncate(path, reason string) {
	if w.pass.truncated == "" {
		w.pass.truncated = fmt.Sprintf("%s at %q", reason, path)
	}
}

func (w *controlWalker) unreadable(path, reason string) {
	if _, seen := w.pass.unreadable[path]; seen {
		return
	}
	if len(w.pass.unreadable) == w.budget.MaxControlEntries {
		w.truncate(path, "control unreadable path limit exceeded")
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
	w.noteSource(path)
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
		w.truncate(path, "control entry limit exceeded")
		return controlEntry{}
	}
	if int64(len(path)) > w.budget.MaxControlPathBytes-w.pathBytes {
		w.truncate(path, "control path-bytes limit exceeded")
		return controlEntry{}
	}
	if 1+strings.Count(path, string(filepath.Separator)) > w.budget.MaxControlDepth {
		w.truncate(path, "control depth limit exceeded")
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
			digest, oversize, err := hashFileSafe(w.snapshotFile(path, dev, ino, ok), w.capBytes)
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
	if e.Kind == KindSymlink {
		w.followSymlink(e)
	}
	return e
}

// noteSource remembers the reference being followed as the reason path was
// observed, unless the path is that reference. Observing a path with no
// reference to follow means discovery reached it on its own.
func (w *controlWalker) noteSource(path string) {
	if w.source == "" {
		w.direct[path] = struct{}{}
		return
	}
	if w.source != path && !slices.Contains(w.pass.sources[path], w.source) {
		w.pass.sources[path] = append(w.pass.sources[path], w.source)
	}
}

// following runs fn with source as the reference whose contents it follows.
func (w *controlWalker) following(source string, fn func()) {
	previous := w.source
	w.source = source
	defer func() { w.source = previous }()
	fn()
}

// snapshotFile describes a file the walk observed, to be opened against the
// workspace mount it checked.
func (w *controlWalker) snapshotFile(path string, dev, ino uint64, haveIDs bool) snapshotFile {
	return snapshotFile{
		root: w.root, relPath: path, path: filepath.Join(w.rootPath, path),
		dev: dev, ino: ino, haveIDs: haveIDs,
		workspaceMount: w.rootMount, workspaceMountKnown: w.mountKnown,
	}
}

// followSymlink observes the in-workspace target of a recorded control
// symlink. A symlinked hook, config or agent directory otherwise lets later
// edits to its target pass unobserved while the link itself stays unchanged.
// The target is resolved the way the kernel does, inspecting every prefix, so a
// link leaving the grant, or the grant root itself, is never followed. The entry
// is stored before following, which ends link cycles.
func (w *controlWalker) followSymlink(link controlEntry) {
	if rel, res := w.resolveLinkTarget(link); res == pathResolved {
		w.following(link.Path, func() { w.queueTree(w.recordPath(rel), "", "") })
	}
}

// pathResolution says what resolveWorkspacePath found.
type pathResolution int

const (
	// pathResolved: the path names a place in the workspace, whose last
	// component may or may not exist yet.
	pathResolved pathResolution = iota
	// pathMissing: a directory the path passes through does not exist, so Git
	// finds no configuration there. Creating it later is seen as an addition.
	pathMissing
	// pathBlocked: a file stands where the path needs a directory.
	pathBlocked
	// pathOutside: the path leaves the grant, which is not followed.
	pathOutside
	// pathUnobservable: the path could not be resolved safely. The source that
	// named it was reported unreadable.
	pathUnobservable
)

// resolveLinkTarget resolves where a recorded symlink points, without following
// the target itself. A link with no usable target, one that leaves the workspace
// and one naming the workspace root have no place to observe.
func (w *controlWalker) resolveLinkTarget(link controlEntry) (string, pathResolution) {
	rel, res := w.resolveWorkspacePath(link.Path, filepath.Dir(link.Path), link.Target)
	if res == pathResolved && rel == "." {
		return "", pathOutside
	}
	return rel, res
}

// resolveWorkspacePath finds the workspace place Git reaches from a path named
// in its metadata or by a symlink, relative to base unless value is absolute.
// Git and the kernel resolve a path one component at a time: a symlinked
// directory is followed, and ".." leaves the directory the path has actually
// reached, not the one it was spelled through. Every directory component is
// inspected here the same way, so the result is where Git lands, inside the
// workspace or not.
//
// The value is a literal path, as the kernel reads a symlink target. Git's own
// spellings for a home or installation path are not literal, so the callers that
// read a value from Git metadata screen them first, in workspaceTarget.
//
// The last component is returned as named and is not followed: the caller
// records it, and a symlink there is followed as a recorded link. Each symlink
// passed on the way is recorded as evidence, attributed to source, the path
// whose contents named it, so a snapshot that never read source does not claim
// to have observed what it led to.
//
// A path that leaves the workspace is outside the grant and is not followed. One
// that leaves it and names it again by name is ambiguous, because only the
// workspace root's real parent knows the way back: source is reported unreadable,
// as it is when a symlink loop, too long a chain, or a component that cannot be
// inspected, such as one on another mount, stops the resolution. A directory
// that does not exist yet names no configuration.
func (w *controlWalker) resolveWorkspacePath(source, base, value string) (string, pathResolution) {
	if value == "" || strings.ContainsRune(value, 0) {
		return "", pathOutside
	}
	var pending []string
	if filepath.IsAbs(value) {
		rest, rooted := w.underRoot(value)
		if !rooted {
			return w.outsideWorkspace(source, value)
		}
		pending = pathParts(rest)
	} else {
		if base == "" {
			return "", pathOutside
		}
		pending = append(pathParts(base), pathParts(value)...)
	}
	// The last component of the value is not followed, unless the value ends in a
	// slash or a "." component: the kernel then requires a directory there, which
	// it reaches through a symlink and refuses for a regular file. A value with no
	// component of its own, such as ".", names the directory its base resolves to.
	ownsLast := len(pathParts(value)) > 0
	needsDir := endsInDirectoryMarker(value)
	var stack []string
	for hops := 0; len(pending) > 0; {
		part := pending[0]
		pending = pending[1:]
		if part == ".." {
			if len(stack) == 0 {
				return w.outsideWorkspace(source, filepath.Join(w.rootPath, "..", filepath.Join(pending...)))
			}
			stack = stack[:len(stack)-1]
			continue
		}
		path := filepath.Join(append(slices.Clone(stack), part)...)
		last := len(pending) == 0 && ownsLast
		if last && !needsDir {
			return path, pathResolved
		}
		info := w.lookup(path)
		if info == nil {
			if _, unreadable := w.pass.unreadable[path]; unreadable {
				w.unreadable(source, "configured path could not be inspected")
				return "", pathUnobservable
			}
			if last {
				// Nothing is named yet, as with any last component.
				return path, pathResolved
			}
			return "", pathMissing
		}
		switch {
		case info.IsDir():
			stack = append(stack, part)
		case info.Mode()&fs.ModeSymlink != 0:
			// hops counts this link too, so the 41st is the first refused (see
			// maxConfigLinkHops).
			hops++
			if hops > maxConfigLinkHops {
				w.unreadable(source, "configured path symlink chain is too long")
				return "", pathUnobservable
			}
			link := w.recordAs(source, path, info)
			if link.Kind != KindSymlink || link.Target == "" || strings.ContainsRune(link.Target, 0) {
				w.unreadable(source, "configured path symlink could not be observed")
				return "", pathUnobservable
			}
			if filepath.IsAbs(link.Target) {
				rest, rooted := w.underRoot(link.Target)
				if !rooted {
					return w.outsideWorkspace(source, link.Target)
				}
				stack = nil
				pending = append(pathParts(rest), pending...)
			} else {
				pending = append(pathParts(link.Target), pending...)
			}
		default:
			w.recordAs(source, path, info)
			return "", pathBlocked
		}
	}
	if len(stack) == 0 {
		return ".", pathResolved
	}
	return filepath.Join(stack...), pathResolved
}

// recordAs records a path as evidence for the reference source followed.
func (w *controlWalker) recordAs(source, path string, info fs.FileInfo) (e controlEntry) {
	w.following(source, func() { e = w.record(path, info) })
	return e
}

// underRoot returns the part of an absolute path below the workspace root.
func (w *controlWalker) underRoot(abs string) (string, bool) {
	if abs == w.rootPath {
		return "", true
	}
	return strings.CutPrefix(abs, w.rootPath+string(filepath.Separator))
}

// outsideWorkspace classifies a path the resolution found outside the workspace
// root, which lexical is the cleaned spelling of. Outside the grant is not
// followed. A spelling that cleans back inside names a place only the real
// parent of the root can resolve, so it is reported unreadable instead.
func (w *controlWalker) outsideWorkspace(source, spelling string) (string, pathResolution) {
	if rel, err := filepath.Rel(w.rootPath, filepath.Clean(spelling)); err == nil && filepath.IsLocal(rel) {
		w.unreadable(source, "configured path resolution is ambiguous")
		return "", pathUnobservable
	}
	return "", pathOutside
}

// endsInDirectoryMarker reports whether a path ends in a slash or a "."
// component, either of which makes the kernel require a directory at its end.
func endsInDirectoryMarker(path string) bool {
	path = filepath.ToSlash(path)
	return strings.HasSuffix(path, "/") || strings.HasSuffix(path, "/.")
}

// pathParts splits a path into its components, dropping empty and "." ones.
func pathParts(path string) []string {
	return slices.DeleteFunc(strings.Split(filepath.ToSlash(path), "/"), func(part string) bool {
		return part == "" || part == "."
	})
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
	w.enqueueTree(e, controlTree{gitDir: gitDir, worktree: worktree})
}

func (w *controlWalker) enqueueTree(e controlEntry, tree controlTree) {
	if e.Kind != KindDir {
		return
	}
	if w.source == "" && tree.source == "" {
		w.direct[e.Path] = struct{}{}
	}
	if _, ok := w.coveredTrees[e.Path]; ok {
		// A directory queued as a plain tree, such as the target of a symlink,
		// takes the Git role when a Git scan names it before the walk reaches it.
		if queued := w.queuedTrees[e.Path]; queued != nil && !queued.walked && queued.gitDir == "" && tree.gitDir != "" {
			queued.gitDir, queued.worktree = tree.gitDir, tree.worktree
			queued.fixed = queued.fixed || tree.fixed
		}
		return
	}
	w.coveredTrees[e.Path] = struct{}{}
	tree.path = e.Path
	if tree.source == "" {
		tree.source = w.source
	}
	w.queuedTrees[e.Path] = &tree
	w.trees = append(w.trees, &tree)
}

// scanFixed monitors each fixed control path under dir as a whole. A Git marker
// inside one, such as a submodule, a standalone repository or a bare repository
// for the agent configuration, adds Git metadata checks but never narrows the
// scan to them.
func (w *controlWalker) scanFixed(dir string) {
	for _, name := range fixedControlPaths {
		path := filepath.Join(dir, name)
		if info := w.lookup(path); info != nil {
			e := w.record(path, info)
			if e.Kind == KindDir {
				if w.bareRepository(path) {
					w.scanGitDir(path, path, true)
				} else {
					w.scanGitMarker(path)
				}
			}
			w.enqueueTree(e, controlTree{fixed: true})
		}
	}
}

// scanFixedChild records one entry inside a fixed control tree. A Git marker
// adds Git metadata checks. Only an agent worktree slot exempts the checkout's
// ordinary files: anywhere else, such as a skill or hook directory cloned into
// .claude, those files can run as the operator and stay monitored whole.
func (w *controlWalker) scanFixedChild(path string, info fs.FileInfo) {
	e := w.record(path, info)
	if e.Kind == KindDir {
		if w.bareRepository(path) {
			w.scanGitDir(path, path, true)
			return
		}
		if w.scanGitMarker(path) && agentWorktreePath(path) && w.linkedWorktreeOfProject(path) {
			w.scanFixed(path)
			w.worktreeSlots = append(w.worktreeSlots, path)
			return
		}
	}
	w.enqueueTree(e, controlTree{fixed: true})
}

// agentWorktreePath reports whether path is a direct child of .claude/worktrees,
// where Claude Code's --worktree option creates a full checkout of the project.
// Such a checkout's own control paths are scanned by scanFixed; its source files
// are project content, not agent configuration, once linkedWorktreeOfProject
// confirms it is a linked worktree of that project. The .claude directory must
// be a project's own: one inside another monitored directory, such as a cloned
// skill, is no place Claude Code creates checkouts, so it cannot exempt files
// there.
func agentWorktreePath(path string) bool {
	parent := filepath.Dir(path)
	claude := filepath.Dir(parent)
	if filepath.Base(parent) != "worktrees" || filepath.Base(claude) != ".claude" {
		return false
	}
	for part := range strings.SplitSeq(filepath.ToSlash(filepath.Dir(claude)), "/") {
		if slices.Contains(fixedControlPaths[:], part) {
			return false
		}
	}
	return true
}

func (w *controlWalker) scanGitMarker(dir string) bool {
	path := filepath.Join(dir, ".git")
	info := w.lookup(path)
	if info == nil {
		return false
	}
	if info.IsDir() {
		w.scanGitDir(path, dir, false)
		return true
	}
	e := w.record(path, info)
	if e.Kind == KindFile {
		w.scanGitPointer(e, "gitdir: ", dir, dir)
	}
	return e.Kind == KindFile
}

// scanGitDir observes a Git directory and what its configuration names. fixed
// says the directory is inside a fixed control tree, which is monitored whole:
// Git's volatile-file filter is for repository metadata elsewhere and must not
// hide files from a tree the filter's list does not describe.
func (w *controlWalker) scanGitDir(dir, worktree string, fixed bool) {
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
			worktree, _ = w.workspaceTarget(config.Path, dir, value)
		}
	}
	w.enqueueTree(e, controlTree{gitDir: dir, worktree: worktree, fixed: fixed})
	for _, config := range configs {
		w.scanGitConfig(config, dir, worktree)
	}
	if common := w.recordPath(filepath.Join(dir, "commondir")); common.Kind == KindFile {
		w.scanGitPointer(common, "", dir, worktree)
	}
	for _, name := range []string{"hooks", "info", "objects/info", "modules", "worktrees"} {
		child := w.recordPath(filepath.Join(dir, filepath.FromSlash(name)))
		w.enqueueTree(child, controlTree{gitDir: dir, worktree: worktree, fixed: fixed})
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
		if !tree.fixed && volatileGitEntry(rel, info.Mode()) {
			return
		}
		if info.IsDir() && w.gitMetadataChild(path, rel) {
			worktree := tree.worktree
			if strings.HasPrefix(rel, "worktrees/") {
				worktree = w.linkedWorktree(path)
			}
			w.scanGitDir(path, worktree, tree.fixed)
			return
		}
	}
	if tree.fixed {
		w.scanFixedChild(path, info)
		return
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

// nestedDirectory is one directory awaiting nested discovery.
type nestedDirectory struct {
	path  string
	depth int
	// slot marks an agent worktree checkout whose Git marker and root
	// control paths a fixed tree walk already scanned.
	slot bool
}

// nestedDiscovery is the breadth-first search for nested repositories and
// fixed control paths. It can resume: a checkout found while the discovered
// trees are walked, such as a slot inside a nested project's .claude, is seeded
// the next time it runs.
type nestedDiscovery struct {
	w           *controlWalker
	queue       []nestedDirectory
	next        int
	seeded      int
	queuedBytes int64
	listed      int
	exhausted   bool
}

func (w *controlWalker) discoverNested() {
	w.pass.undiscovered = make(map[string]struct{})
	w.pass.partlyListed = make(map[string]struct{})
	w.discovery = &nestedDiscovery{w: w, queue: []nestedDirectory{{path: "."}}}
	w.discovery.run()
}

func (d *nestedDiscovery) pending() bool {
	return d.next < len(d.queue) || d.seeded < len(d.w.worktreeSlots)
}

// seedSlots queues agent worktree checkouts found since the last run. The fixed
// tree walk does not descend into a checkout's ordinary directories, so nested
// discovery starts there. A checkout that cannot be queued is partly listed:
// its Git marker and fixed paths were still examined by the fixed walk.
func (d *nestedDiscovery) seedSlots() {
	w := d.w
	for ; d.seeded < len(w.worktreeSlots); d.seeded++ {
		slot := w.worktreeSlots[d.seeded]
		switch {
		case d.exhausted:
			w.limitListing(slot, "nested directory entry limit exceeded")
		case len(d.queue) >= w.budget.MaxNestedDirs:
			w.limitListing(slot, "nested directory count limit exceeded")
		case d.queuedBytes+int64(len(slot)) > w.budget.MaxNestedPathBytes:
			w.limitListing(slot, "nested directory path-bytes limit exceeded")
		default:
			d.queuedBytes += int64(len(slot))
			d.queue = append(d.queue, nestedDirectory{
				path: slot, depth: 1 + strings.Count(filepath.ToSlash(slot), "/"), slot: true,
			})
		}
	}
}

// run drains the queue. Queue storage (count and path bytes) and the cost of
// listing wide directories are bounded. A directory that cannot queue a child
// is partly listed.
func (d *nestedDiscovery) run() {
	w := d.w
	d.seedSlots()
	for ; d.next < len(d.queue) && w.pass.truncated == ""; d.next++ {
		dir := d.queue[d.next]
		if _, covered := w.coveredTrees[dir.path]; covered {
			continue
		}
		if dir.depth > 0 && !dir.slot {
			if w.bareRepository(dir.path) {
				w.scanGitDir(dir.path, dir.path, false)
				continue
			}
			w.scanGitMarker(dir.path)
			w.scanFixed(dir.path)
		}
		w.list(dir.path, func(child string, e fs.DirEntry) bool {
			if d.listed == w.budget.MaxNestedDirs {
				w.limitListing(dir.path, "nested directory entry limit exceeded")
				return false
			}
			d.listed++
			if !e.IsDir() {
				return true
			}
			if _, covered := w.coveredTrees[child]; covered {
				return true
			}
			switch {
			case dir.depth >= w.budget.MaxNestedDepth:
				w.limitListing(dir.path, "nested directory depth limit exceeded")
			case len(d.queue) >= w.budget.MaxNestedDirs:
				w.limitListing(dir.path, "nested directory count limit exceeded")
			case d.queuedBytes+int64(len(child)) > w.budget.MaxNestedPathBytes:
				w.limitListing(dir.path, "nested directory path-bytes limit exceeded")
			default:
				d.queuedBytes += int64(len(child))
				d.queue = append(d.queue, nestedDirectory{path: child, depth: dir.depth + 1})
			}
			return true
		})
		if d.listed == w.budget.MaxNestedDirs {
			for _, pending := range d.queue[d.next+1:] {
				if pending.slot {
					w.limitListing(pending.path, "nested directory entry limit exceeded")
				} else {
					w.skipDiscovery(pending.path, "nested directory entry limit exceeded")
				}
			}
			d.next, d.exhausted = len(d.queue), true
			return
		}
	}
}

func (w *controlWalker) skipDiscovery(path, reason string) {
	w.pass.undiscovered[path] = struct{}{}
	w.noteDiscoveryLimit(path, reason)
}

// limitListing records that a directory's listing could not be completed.
func (w *controlWalker) limitListing(path, reason string) {
	w.pass.partlyListed[path] = struct{}{}
	w.noteDiscoveryLimit(path, reason)
}

func (w *controlWalker) noteDiscoveryLimit(path, reason string) {
	if w.pass.discoveryLimit == "" {
		w.pass.discoveryLimit = fmt.Sprintf("%s at %q", reason, path)
	}
}

// discovered reports whether this pass enumerated the place path names. A
// directory never reached was not examined at all. One whose listing was cut
// off had its Git marker and fixed paths examined before the listing began, so
// a path below those names is observed even though its siblings are not.
func (p controlPass) discovered(path string) bool {
	var child string
	for {
		if _, skipped := p.undiscovered[path]; skipped {
			return false
		}
		if _, partial := p.partlyListed[path]; partial && !examinedBeforeListing(child) {
			return false
		}
		if path == "." {
			return true
		}
		child = filepath.Base(path)
		path = filepath.Dir(path)
	}
}

func examinedBeforeListing(name string) bool {
	return name == ".git" || slices.Contains(fixedControlPaths[:], name)
}

func volatileGitEntry(path string, mode fs.FileMode) bool {
	if mode.IsDir() {
		switch path {
		// Git LFS stores content by object ID under lfs/objects.
		// https://github.com/git-lfs/git-lfs/blob/main/docs/spec.md
		case "lfs/objects", "objects/pack", "objects/info/commit-graphs", "refs", "logs", "reftable", "rr-cache":
			return true
		}
		digits, objectShard := strings.CutPrefix(path, "objects/")
		return objectShard && len(digits) == 2 && lowercaseHex(digits)
	}
	if mode.IsRegular() {
		switch path {
		// Git holds objects/maintenance.lock while background maintenance runs,
		// which a commit can start (builtin/gc.c, maintenance_run_tasks).
		case "objects/maintenance.lock":
			return true
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
	identityReason := controlIdentityChange(before.identity, after.identity)
	var priorityDiff, nestedDiff controlPassDiff
	if before.priority.entries != nil && after.priority.entries != nil && identityReason == "" {
		priorityDiff = compareControlPass(before.priority, after.priority)
		nestedDiff = compareControlPass(before.nested, after.nested)
	}
	// The passes classify independently, and a path can be recorded by both. It
	// is added or removed only when no pass observed it at the other endpoint.
	observedBefore := observedControlPaths(before.priority, before.nested)
	observedAfter := observedControlPaths(after.priority, after.nested)
	s.Added = mergeControlPaths(s.Added, unobservedControlPaths(priorityDiff.added, observedBefore),
		unobservedControlPaths(nestedDiff.added, observedBefore))
	s.Removed = mergeControlPaths(s.Removed, unobservedControlPaths(priorityDiff.removed, observedAfter),
		unobservedControlPaths(nestedDiff.removed, observedAfter))
	s.Modified = mergeControlPaths(s.Modified, priorityDiff.modified, nestedDiff.modified)
	if before.priority.entries != nil && after.priority.entries != nil && identityReason == "" {
		s.Modified = mergeControlPaths(s.Modified, nil, modifiedAcrossPasses(
			[]controlPass{before.priority, before.nested}, []controlPass{after.priority, after.nested}))
	}
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
		before.priority.truncated, after.priority.truncated)
	s.NestedDiscoveryReason = joinIncompleteReasons(before.nested.discoveryLimit, after.nested.discoveryLimit,
		before.nested.truncated, after.nested.truncated)
	s.NestedDiscoveryPartial = s.NestedDiscoveryReason != ""
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
		if !seen && complete && after.covers(before, path, excluded) && !withinExcluded(path, excluded) {
			diff.removed = append(diff.removed, path)
		}
	}
	for path := range after.entries {
		if _, seen := before.entries[path]; !seen && complete && before.covers(after, path, excluded) && !withinExcluded(path, excluded) {
			diff.added = append(diff.added, path)
		}
	}
	return diff
}

// covers reports whether this pass examined everything that would have made it
// observe path, had the path been recorded as it was in the other pass: the
// place the path names and, for one found through a reference, the contents of
// the paths that referenced it. A pass that never examined a referencing
// repository cannot show the reference, or what it names, to be gone, and one
// that could not read a referencing path, at either endpoint, never saw what the
// path named. excluded holds the paths unreadable at either endpoint.
func (p controlPass) covers(recorded controlPass, path string, excluded map[string]struct{}) bool {
	return p.coversPath(recorded, path, excluded, make(map[string]struct{}))
}

func (p controlPass) coversPath(recorded controlPass, path string, excluded, visited map[string]struct{}) bool {
	if !p.discovered(path) {
		return false
	}
	visited[path] = struct{}{}
	for _, source := range recorded.sources[path] {
		if withinExcluded(source, excluded) {
			return false
		}
		if _, done := visited[source]; !done && !p.coversPath(recorded, source, excluded, visited) {
			return false
		}
	}
	return true
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

// modifiedAcrossPasses compares a path that different passes recorded at the two
// endpoints, which neither pass could compare on its own.
func modifiedAcrossPasses(before, after []controlPass) []string {
	var modified []string
	for _, b := range before {
		for path, be := range b.entries {
			for _, a := range after {
				if ae, seen := a.entries[path]; seen && (be.mode != ae.mode || entryChanged(be.Entry, ae.Entry)) {
					modified = append(modified, path)
				}
			}
		}
	}
	return modified
}

func observedControlPaths(passes ...controlPass) map[string]struct{} {
	observed := make(map[string]struct{})
	for _, pass := range passes {
		for path := range pass.entries {
			observed[path] = struct{}{}
		}
	}
	return observed
}

func unobservedControlPaths(paths []string, observed map[string]struct{}) []string {
	return slices.DeleteFunc(slices.Clone(paths), func(path string) bool {
		_, seen := observed[path]
		return seen
	})
}

func mergeControlPaths(out, a, b []string) []string {
	out = append(out, a...)
	out = append(out, b...)
	slices.Sort(out)
	return slices.Compact(out)
}
