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
	"slices"
	"strconv"
	"strings"
)

type gitConfigSource struct {
	path     string
	gitDir   string
	worktree string
}

func (w *controlWalker) scanGitPointer(entry controlEntry, prefix, base, worktree string) {
	if path, inside := w.pointerTarget(entry, prefix, base); inside {
		w.following(entry.Path, func() {
			// Git resolves a symlink the pointer names to the directory behind
			// it, which is the Git directory whose configuration is followed.
			targetEntry := w.recordPath(path)
			for hops := 0; targetEntry.Kind == KindSymlink; hops++ {
				rel, ok := w.linkTarget(targetEntry)
				if !ok || hops == maxConfigLinkHops {
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
// and reports it when it lies inside the workspace.
func (w *controlWalker) pointerTarget(entry controlEntry, prefix, base string) (string, bool) {
	data, ok := w.readObserved(entry)
	if !ok {
		return "", false
	}
	target, valid := strings.CutPrefix(strings.TrimRight(string(data), "\r\n"), prefix)
	if !valid || target == "" || strings.ContainsRune(target, 0) {
		w.unreadable(entry.Path, "invalid Git directory pointer")
		return "", false
	}
	return w.workspaceTarget(entry.Path, base, target)
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
	metadata, inside := w.pointerTarget(gitFile, "gitdir: ", slot)
	if !inside || filepath.Base(filepath.Dir(metadata)) != "worktrees" || filepath.Dir(filepath.Dir(metadata)) != ownGit {
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

// Config paths are relative to Git's working directory for hooks and
// fsmonitor, or to the including file for includes. Resolve literal paths
// without opening any external repository or config. Git resolves a path one
// component at a time, so a ".." after a symlinked component leaves that
// component's target; when cleaning the path lexically would name a different
// place, inside the workspace or not, the path cannot be observed and source,
// the file that named it, is reported unreadable.
func (w *controlWalker) workspaceTarget(source, base, value string) (string, bool) {
	if value == "" || strings.ContainsRune(value, 0) ||
		strings.HasPrefix(value, "~") || strings.HasPrefix(value, "%(prefix)/") {
		return "", false
	}
	joined := value
	if !filepath.IsAbs(value) {
		if base == "" {
			return "", false
		}
		joined = filepath.Join(w.rootPath, base, value)
	}
	rel, err := filepath.Rel(w.rootPath, filepath.Clean(joined))
	inside := err == nil && filepath.IsLocal(rel)
	if slices.Contains(strings.Split(filepath.ToSlash(value), "/"), "..") && w.dotDotAmbiguous(base, value, inside) {
		w.unreadable(source, "configured path resolution is ambiguous")
		return "", false
	}
	return rel, inside
}

// dotDotAmbiguous reports whether a ".." in value follows anything but a plain
// directory, whose parent is then the lexical parent. A ".." after a symlink, or
// after a component that cannot be inspected, leaves somewhere cleaning does not
// find, possibly inside the workspace. A ".." that leaves the workspace through
// plain directories ends what can be observed, unless the path then names a
// place inside the workspace again. inside is the lexical result, which an
// absolute path outside the workspace cannot confirm.
func (w *controlWalker) dotDotAmbiguous(base, value string, inside bool) bool {
	var stack []string
	rest := value
	if filepath.IsAbs(value) {
		var rooted bool
		if rest, rooted = strings.CutPrefix(value, w.rootPath+string(filepath.Separator)); !rooted {
			return inside
		}
	} else {
		stack = slices.DeleteFunc(strings.Split(filepath.ToSlash(base), "/"), func(part string) bool {
			return part == "" || part == "."
		})
	}
	for part := range strings.SplitSeq(filepath.ToSlash(rest), "/") {
		switch part {
		case "", ".":
		case "..":
			// Past the workspace root nothing can be observed. Naming the
			// workspace again from there is a place only the real parent knows.
			if len(stack) == 0 {
				return inside
			}
			// A component that does not exist now has no target to leave. If it
			// becomes a symlink, the next snapshot finds that and is ambiguous.
			info, err := w.root.Lstat(strings.Join(stack, "/"))
			if err != nil && !errors.Is(err, fs.ErrNotExist) || err == nil && !info.IsDir() {
				return true
			}
			stack = stack[:len(stack)-1]
		default:
			stack = append(stack, part)
		}
	}
	return false
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
			rel, ok := w.linkTarget(file)
			if !ok {
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
