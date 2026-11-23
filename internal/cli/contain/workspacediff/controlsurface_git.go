// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package workspacediff

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
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
	data, ok := w.readObserved(entry)
	if !ok {
		return
	}
	target, valid := strings.CutPrefix(strings.TrimRight(string(data), "\r\n"), prefix)
	if !valid || target == "" || strings.ContainsRune(target, 0) {
		w.unreadable(entry.Path, "invalid Git directory pointer")
		return
	}
	if path, inside := w.workspaceTarget(base, target); inside {
		targetEntry := w.recordPath(path)
		if targetEntry.Kind == KindDir {
			w.scanGitDir(path, worktree)
		} else if targetEntry.Kind != KindSymlink {
			w.unreadable(entry.Path, "Git directory target could not be observed")
		}
	}
}

func (w *controlWalker) scanGitConfig(entry controlEntry, gitDir, worktree string) {
	if entry.Kind != KindFile {
		return
	}
	source := gitConfigSource{path: entry.Path, gitDir: gitDir, worktree: worktree}
	if _, seen := w.seenConfig[source]; seen {
		return
	}
	if len(w.seenConfig) == w.budget.MaxControlEntries {
		w.truncate("Git config reference limit exceeded")
		return
	}
	w.seenConfig[source] = struct{}{}
	data, ok := w.readObserved(entry)
	if !ok {
		return
	}
	if !scanGitConfig(string(data), func(section, key, value string) {
		switch {
		case section == "core" && key == "hookspath":
			// Push hooks run in the Git directory, while other hooks run
			// in the working tree (or the Git directory for a bare repo).
			for _, base := range []string{worktree, gitDir} {
				if path, inside := w.workspaceTarget(base, value); inside {
					w.queueTree(w.recordPath(path), "", "")
				}
			}
		case section == "core" && key == "fsmonitor":
			if !gitBoolean(value) {
				if path, inside := w.workspaceTarget(worktree, value); inside {
					w.recordPath(path)
				}
			}
		case (section == "include" || strings.HasPrefix(section, "includeif.")) && key == "path":
			if path, inside := w.workspaceTarget(filepath.Dir(entry.Path), value); inside {
				w.scanGitConfig(w.recordPath(path), gitDir, worktree)
			}
		}
	}) {
		w.unreadable(entry.Path, "could not parse Git configuration")
	}
}

func (w *controlWalker) configuredWorktree(entry controlEntry) (value string, set bool) {
	if entry.Kind != KindFile {
		return "", false
	}
	data, ok := w.readObserved(entry)
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
// lexically first so no external repository or config is opened.
func (w *controlWalker) workspaceTarget(base, value string) (string, bool) {
	if value == "" || strings.ContainsRune(value, 0) ||
		strings.HasPrefix(value, "~") || strings.HasPrefix(value, "%(prefix)/") {
		return "", false
	}
	if !filepath.IsAbs(value) {
		if base == "" {
			return "", false
		}
		value = filepath.Join(w.rootPath, base, value)
	}
	rel, err := filepath.Rel(w.rootPath, filepath.Clean(value))
	return rel, err == nil && filepath.IsLocal(rel)
}

// A linked worktree records the path to its .git file in its metadata.
func (w *controlWalker) linkedWorktree(gitDir string) string {
	entry := w.recordPath(filepath.Join(gitDir, "gitdir"))
	if entry.Kind == KindFile {
		if data, ok := w.readObserved(entry); ok {
			if target, inside := w.workspaceTarget(gitDir, strings.TrimRight(string(data), "\r\n")); inside {
				return filepath.Dir(target)
			}
		}
	}
	return ""
}

func (w *controlWalker) readObserved(entry controlEntry) ([]byte, bool) {
	if entry.Oversize {
		return nil, false
	}
	dev, ino, ok := statIDsWithInode(entry.info)
	file, err := openSnapshotRegular(w.root, entry.Path, filepath.Join(w.rootPath, entry.Path), dev, ino, ok)
	if err != nil {
		w.unreadable(entry.Path, fmt.Sprintf("open Git metadata: %v", err))
		return nil, false
	}
	defer func() { _ = file.Close() }()
	mnt, mntOK := fileMountID(file)
	if !w.checkMount(entry.Path, entry.info, mnt, mntOK) {
		return nil, false
	}
	data, err := io.ReadAll(io.LimitReader(file, entry.Size+1))
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
