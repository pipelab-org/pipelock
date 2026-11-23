// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package workspacediff

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"path/filepath"
	"strconv"
	"strings"
)

type gitConfigSource struct {
	path     string
	gitDir   string
	worktree string
}

func (w *controlWalker) scanGitPointer(entry controlEntry, prefix, base, worktree string) {
	path, res := w.pointerTarget(entry, prefix, base)
	switch res {
	case pathMissing, pathBlocked:
		// A Git directory a pointer names has to be there to be scanned. A path
		// through a missing directory or a regular file leads to none, the same
		// as a missing last component: the pointer is not observed. This differs
		// from a config include, where a missing file is no configuration.
		w.unreadable(entry.Path, "Git directory target could not be observed")
	case pathResolved:
		w.following(entry.Path, func() {
			// Git resolves a symlink the pointer names to the directory behind
			// it, which is the Git directory whose configuration is followed.
			targetEntry := w.recordPath(path)
			for hops := 0; targetEntry.Kind == KindSymlink; hops++ {
				rel, linkRes := w.resolveLinkTarget(targetEntry)
				if linkRes != pathResolved || hops == maxConfigLinkHops {
					w.unreadable(entry.Path, "Git directory symlink target could not be observed")
					return
				}
				path = rel
				targetEntry = w.recordPath(path)
			}
			if targetEntry.Kind == KindDir {
				w.scanGitDir(path, worktree, false)
			} else {
				w.unreadable(entry.Path, "Git directory target could not be observed")
			}
		})
	}
}

// pointerTarget reads the Git directory a pointer file names, relative to base,
// and resolves it. The pointer is reported unreadable when it cannot be read or
// is not a pointer, which resolves as pathUnobservable.
func (w *controlWalker) pointerTarget(entry controlEntry, prefix, base string) (string, pathResolution) {
	data, ok := w.readObserved(entry)
	if !ok {
		return "", pathUnobservable
	}
	target, valid := strings.CutPrefix(strings.TrimRight(string(data), "\r\n"), prefix)
	if !valid || target == "" || strings.ContainsRune(target, 0) {
		w.unreadable(entry.Path, "invalid Git directory pointer")
		return "", pathUnobservable
	}
	return w.gitValueTarget(entry.Path, base, target)
}

// linkedWorktreeOfProject reports whether slot is a linked worktree of the
// checkout in the project directory that owns it, as `git worktree add` makes:
// its .git file names a directory under that project's own .git/worktrees, and
// that directory's gitdir file names the slot's .git file in return. A
// standalone repository, a worktree of another repository, or a Git file whose
// metadata does not point back is not one, whatever its directory is called.
// Metadata the workspace does not contain cannot be checked, so it is not one.
func (w *controlWalker) linkedWorktreeOfProject(slot string) bool {
	gitFile := w.pass.entries[filepath.Join(slot, ".git")]
	if gitFile.Kind != KindFile {
		return false
	}
	ownGit := filepath.Join(filepath.Dir(filepath.Dir(filepath.Dir(slot))), ".git")
	if info := w.lookup(ownGit); info == nil || !info.IsDir() {
		return false
	}
	metadata, res := w.pointerTarget(gitFile, "gitdir: ", slot)
	if res != pathResolved || filepath.Base(filepath.Dir(metadata)) != "worktrees" || filepath.Dir(filepath.Dir(metadata)) != ownGit {
		return false
	}
	back := w.recordPath(filepath.Join(metadata, "gitdir"))
	if back.Kind != KindFile {
		return false
	}
	data, ok := w.readObserved(back)
	if !ok {
		return false
	}
	target, inside := w.workspaceTarget(back.Path, metadata, strings.TrimRight(string(data), "\r\n"))
	return inside && target == gitFile.Path
}

func (w *controlWalker) scanGitConfig(entry controlEntry, gitDir, worktree string) {
	if entry.Kind != KindFile && entry.Kind != KindSymlink {
		return
	}
	source := gitConfigSource{path: entry.Path, gitDir: gitDir, worktree: worktree}
	if _, seen := w.seenConfig[source]; seen {
		return
	}
	if len(w.seenConfig) == w.budget.MaxControlEntries {
		w.truncate(entry.Path, "Git config reference limit exceeded")
		return
	}
	w.seenConfig[source] = struct{}{}
	data, ok := w.readConfig(entry)
	if !ok {
		return
	}
	previous := w.source
	w.source = entry.Path
	defer func() { w.source = previous }()
	if !scanGitConfig(string(data), func(section, key, value string) {
		switch {
		case section == "core" && key == "hookspath":
			// Push hooks run in the Git directory, while other hooks run
			// in the working tree (or the Git directory for a bare repo).
			for _, base := range []string{worktree, gitDir} {
				if path, inside := w.workspaceTarget(entry.Path, base, value); inside {
					w.queueTree(w.recordPath(path), "", "")
				}
			}
		case section == "core" && key == "fsmonitor":
			if !gitBoolean(value) {
				if path, inside := w.workspaceTarget(entry.Path, worktree, value); inside {
					w.recordPath(path)
				}
			}
		case (section == "include" || strings.HasPrefix(section, "includeif.")) && key == "path":
			if path, inside := w.workspaceTarget(entry.Path, filepath.Dir(entry.Path), value); inside {
				w.scanGitConfig(w.recordPath(path), gitDir, worktree)
			}
		}
	}) {
		w.unreadable(entry.Path, "could not parse Git configuration")
	}
}

func (w *controlWalker) configuredWorktree(entry controlEntry) (value string, set bool) {
	if entry.Kind != KindFile && entry.Kind != KindSymlink {
		return "", false
	}
	data, ok := w.readConfig(entry)
	if !ok {
		return "", false
	}
	scanGitConfig(string(data), func(section, key, setting string) {
		if section == "core" && key == "worktree" {
			value, set = setting, true
		}
	})
	return value, set
}

// workspaceTarget resolves a path named in Git metadata to the workspace place
// Git finds, or reports that it names none this walk observes. See
// resolveWorkspacePath. Git expands a leading "~" to a home directory and
// "%(prefix)/" to its installation, so a value spelled that way names a place
// outside the workspace whatever the workspace holds. That expansion belongs to
// Git metadata alone: a symlink target is a literal path to the kernel, and is
// resolved without it.
func (w *controlWalker) workspaceTarget(source, base, value string) (string, bool) {
	rel, res := w.gitValueTarget(source, base, value)
	return rel, res == pathResolved
}

// gitValueTarget resolves a value read from Git metadata, keeping what
// resolveWorkspacePath found for a caller that tells a missing place from one
// outside the workspace.
func (w *controlWalker) gitValueTarget(source, base, value string) (string, pathResolution) {
	if strings.HasPrefix(value, "~") || strings.HasPrefix(value, "%(prefix)/") {
		return "", pathOutside
	}
	return w.resolveWorkspacePath(source, base, value)
}

// A linked worktree records the path to its .git file in its metadata.
func (w *controlWalker) linkedWorktree(gitDir string) string {
	entry := w.recordPath(filepath.Join(gitDir, "gitdir"))
	if entry.Kind == KindFile {
		if data, ok := w.readObserved(entry); ok {
			if target, inside := w.workspaceTarget(entry.Path, gitDir, strings.TrimRight(string(data), "\r\n")); inside {
				return filepath.Dir(target)
			}
		}
	}
	return ""
}

// maxConfigLinkHops matches the kernel's limit on symlinks in one resolution.
const maxConfigLinkHops = 40

// readConfig reads a Git config file. Git reads through a symlink, so a link
// is followed to the regular file the walk recorded for its target, while the
// config keeps its own path for resolving relative includes. A target outside
// the workspace, or one that cannot be resolved safely, is unreadable; a target
// that does not exist reads as no configuration, and appears as an addition if
// it is created.
func (w *controlWalker) readConfig(entry controlEntry) ([]byte, bool) {
	file := entry
	for range maxConfigLinkHops {
		switch file.Kind {
		case KindFile:
			return w.readObserved(file)
		case KindSymlink:
			rel, res := w.resolveLinkTarget(file)
			switch res {
			case pathResolved:
			case pathMissing:
				// Nothing is there to read; creating it is seen as an addition.
				return nil, false
			default:
				w.unreadable(entry.Path, "Git config symlink target could not be observed")
				return nil, false
			}
			// The link names its target, so a snapshot that does not read the link
			// has not observed it.
			var next controlEntry
			w.following(file.Path, func() { next = w.recordPath(rel) })
			if next.Kind == "" {
				if _, err := w.root.Lstat(rel); !errors.Is(err, fs.ErrNotExist) {
					w.unreadable(entry.Path, "Git config symlink target could not be observed")
				}
				return nil, false
			}
			file = next
		default:
			w.unreadable(entry.Path, "Git config symlink target is not a regular file")
			return nil, false
		}
	}
	w.unreadable(entry.Path, "Git config symlink chain is too long")
	return nil, false
}

func (w *controlWalker) readObserved(entry controlEntry) ([]byte, bool) {
	if entry.Oversize {
		return nil, false
	}
	dev, ino, ok := statIDsWithInode(entry.info)
	file, err := openSnapshotRegular(w.snapshotFile(entry.Path, dev, ino, ok))
	if err != nil {
		w.unreadable(entry.Path, fmt.Sprintf("open Git metadata: %v", err))
		return nil, false
	}
	defer func() { _ = file.Close() }()
	mnt, mntOK := fileMountID(file)
	if !w.checkMount(entry.Path, entry.info, mnt, mntOK) {
		return nil, false
	}
	data, err := io.ReadAll(io.LimitReader(file, readLimit(entry.Size)))
	if err != nil {
		w.unreadable(entry.Path, fmt.Sprintf("read Git metadata: %v", err))
		return nil, false
	}
	digest := sha256.Sum256(data)
	if hex.EncodeToString(digest[:]) != entry.Digest {
		w.unreadable(entry.Path, "Git metadata changed between hashing and parsing")
		return nil, false
	}
	w.recheck(entry.Path, entry.info)
	return data, true
}

// Git's documented config grammar (git-config(1)) allows quoted subsections,
// comments, case-insensitive section and key names, and continued values.
// Read every local include and conditional include without evaluating branch,
// remote or gitdir conditions. The caller never invokes Git on the workspace.
func scanGitConfig(data string, visit func(section, key, value string)) bool {
	data = strings.TrimPrefix(data, "\ufeff")
	if strings.ContainsRune(data, 0) {
		return false
	}
	var line strings.Builder
	var section string
	quoted := false
	for i := 0; i < len(data); i++ {
		ch := data[i]
		switch {
		case ch == '\\' && i+1 < len(data):
			next := data[i+1]
			i++
			switch {
			case next == '\n':
			case next == '\r' && i+1 < len(data) && data[i+1] == '\n':
				i++
			default:
				line.WriteByte(ch)
				line.WriteByte(next)
			}
		case ch == '\n':
			if quoted || !gitConfigLine(line.String(), &section, visit) {
				return false
			}
			line.Reset()
		case !quoted && (ch == '#' || ch == ';'):
			for i+1 < len(data) && data[i+1] != '\n' {
				i++
			}
		default:
			line.WriteByte(ch)
			if ch == '"' {
				quoted = !quoted
			}
		}
	}
	return !quoted && gitConfigLine(line.String(), &section, visit)
}

func gitConfigLine(line string, section *string, visit func(section, key, value string)) bool {
	line = strings.Trim(line, " \t\r\v\f")
	if line == "" {
		return true
	}
	if line[0] == '[' {
		end := gitSectionEnd(line)
		if end < 0 {
			return false
		}
		name := line[1:end]
		if i := strings.IndexAny(name, " \t"); i >= 0 {
			name = name[:i] + "."
		}
		*section = strings.ToLower(name)
		line = strings.Trim(line[end+1:], " \t\r\v\f")
		if line == "" {
			return true
		}
	}
	key, raw, hasValue := strings.Cut(line, "=")
	key = strings.ToLower(strings.Trim(key, " \t\r\v\f"))
	if key == "" || *section == "" {
		return false
	}
	if !hasValue {
		visit(*section, key, "")
		return true
	}
	value, ok := gitConfigValue(raw)
	if ok {
		visit(*section, key, value)
	}
	return ok
}

func gitSectionEnd(line string) int {
	quoted := false
	for i := 1; i < len(line); i++ {
		switch line[i] {
		case '\\':
			i++
		case '"':
			quoted = !quoted
		case ']':
			if !quoted {
				return i
			}
		}
	}
	return -1
}

func gitConfigValue(raw string) (string, bool) {
	var value strings.Builder
	quoted := false
	spaceStart := -1
	raw = strings.TrimLeft(raw, " \t\r")
	for i := 0; i < len(raw); i++ {
		ch := raw[i]
		if !quoted && (ch == ' ' || ch == '\t' || ch == '\r') {
			if spaceStart < 0 {
				spaceStart = i
			}
			continue
		}
		if spaceStart >= 0 {
			value.WriteString(raw[spaceStart:i])
			spaceStart = -1
		}
		switch ch {
		case '"':
			quoted = !quoted
			continue
		case '\\':
			i++
			if i >= len(raw) {
				return "", false
			}
			switch raw[i] {
			case '"', '\\':
				ch = raw[i]
			case 'n':
				ch = '\n'
			case 't':
				ch = '\t'
			case 'b':
				ch = '\b'
			default:
				return "", false
			}
		}
		value.WriteByte(ch)
	}
	return value.String(), !quoted
}

func gitBoolean(value string) bool {
	switch strings.ToLower(value) {
	case "", "true", "yes", "on", "false", "no", "off":
		return true
	}
	if strings.ContainsRune(value, '_') {
		return false
	}
	_, err := strconv.ParseInt(value, 0, 32)
	return err == nil
}
