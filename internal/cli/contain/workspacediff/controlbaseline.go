// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package workspacediff

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"path/filepath"
	"runtime"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/jsonscan"
)

const (
	controlBaselineSchema   = "workspace-control-baseline/v1"
	maxControlBaselineBytes = 128 << 20
)

type controlRootIdentity struct {
	Dev        uint64 `json:"dev"`
	Ino        uint64 `json:"ino"`
	IDsKnown   bool   `json:"ids_known"`
	Mount      uint64 `json:"root_mount"`
	MountKnown bool   `json:"mount_known"`
	BootID     string `json:"boot_id"`
}

func controlIdentityChange(before, after controlRootIdentity) string {
	switch {
	case before.BootID != "" && after.BootID != "" && before.BootID != after.BootID:
		return "host rebooted since the baseline was recorded"
	case before.IDsKnown && after.IDsKnown && (before.Dev != after.Dev || before.Ino != after.Ino),
		crossedMount(before.Mount, after.Mount, before.MountKnown, after.MountKnown):
		return "workspace root identity or mount changed between observations"
	default:
		return ""
	}
}

// Wire paths and symlink targets use base64 byte strings because Linux permits
// names that are not valid UTF-8. A control entry's path also keys its pass.
// Modification times are Unix seconds and nanoseconds: the agent chooses them,
// and a time outside RFC 3339's years 0-9999 must still be recordable.
type baselineEntry struct {
	Path     []byte       `json:"path"`
	Mode     *fs.FileMode `json:"mode"`
	Kind     EntryKind    `json:"kind"`
	Size     int64        `json:"size"`
	ModSec   int64        `json:"mod_time_sec"`
	ModNsec  int32        `json:"mod_time_nsec"`
	Digest   string       `json:"digest"`
	Oversize bool         `json:"oversize"`
	Target   []byte       `json:"symlink_target"`
}

type baselineUnreadable struct {
	Path   []byte `json:"path"`
	Reason []byte `json:"reason"`
}

// baselineSource records the paths whose contents led discovery to Path. The
// comparison needs them to tell a path that is gone from one whose referencing
// repository was not examined.
type baselineSource struct {
	Path []byte   `json:"path"`
	From [][]byte `json:"from"`
}

type baselinePass struct {
	Entries        []baselineEntry      `json:"entries"`
	Unreadable     []baselineUnreadable `json:"unreadable"`
	Sources        []baselineSource     `json:"sources"`
	Truncated      []byte               `json:"truncated"`
	Undiscovered   [][]byte             `json:"undiscovered"`
	PartlyListed   [][]byte             `json:"partly_listed"`
	DiscoveryLimit []byte               `json:"discovery_limit"`
}

type controlBaseline struct {
	Schema   string               `json:"schema"`
	Root     []byte               `json:"root"`
	CapBytes int64                `json:"cap_bytes"`
	Identity *controlRootIdentity `json:"identity"`
	Priority *baselinePass        `json:"priority"`
	Nested   *baselinePass        `json:"nested"`
	Problem  []byte               `json:"problem"`
}

// CapBytes returns the per-file digest limit used for the snapshot.
func (s ControlSurfaceSnapshot) CapBytes() int64 {
	return s.capBytes
}

// CompareControlBaseline compares a persisted observation with a fresh one.
func CompareControlBaseline(before, after ControlSurfaceSnapshot) (ControlSurfaceStatement, error) {
	for _, snapshot := range []*ControlSurfaceSnapshot{&before, &after} {
		if runtime.GOOS == "linux" && (snapshot.identity.BootID == "" || !snapshot.identity.IDsKnown || !snapshot.identity.MountKnown) {
			snapshot.problem = joinIncompleteReasons(snapshot.problem, "workspace boot, root, or mount identity unavailable")
		}
	}
	// A reboot or a replaced root makes the comparison incomplete, never clean.
	// The control paths are still compared: this statement is what an operator
	// reviews before replacing the baseline, and an identity change must not
	// hide the paths that moved.
	identityReason := controlIdentityChange(before.identity, after.identity)
	before.identity = after.identity
	statement, err := DiffControlSurface(before, after)
	if err != nil {
		return ControlSurfaceStatement{}, err
	}
	if identityReason != "" {
		statement.IncompleteReason = joinIncompleteReasons(identityReason, statement.IncompleteReason)
		statement.Incomplete = true
	}
	return statement, nil
}

// EncodeControlBaseline serializes the observation needed by DiffControlSurface.
func EncodeControlBaseline(s ControlSurfaceSnapshot) ([]byte, error) {
	if !filepath.IsAbs(s.root) || filepath.Clean(s.root) != s.root || s.capBytes <= 0 {
		return nil, errors.New("invalid control surface snapshot")
	}
	doc := controlBaseline{
		Schema: controlBaselineSchema, Root: []byte(s.root), CapBytes: s.capBytes,
		Identity: &s.identity, Priority: encodeBaselinePass(s.priority),
		Nested: encodeBaselinePass(s.nested), Problem: []byte(s.problem),
	}
	data, err := json.Marshal(doc)
	if len(data) > maxControlBaselineBytes {
		return nil, errors.New("workspace control baseline exceeds size limit")
	}
	return data, err
}

// DecodeControlBaseline loads a bounded, strict baseline for the exact root.
func DecodeControlBaseline(r io.Reader, root string) (ControlSurfaceSnapshot, error) {
	data, err := io.ReadAll(io.LimitReader(r, maxControlBaselineBytes+1))
	if err != nil {
		return ControlSurfaceSnapshot{}, err
	}
	if len(data) > maxControlBaselineBytes {
		return ControlSurfaceSnapshot{}, errors.New("workspace control baseline exceeds size limit")
	}
	var doc controlBaseline
	if err := jsonscan.DecodeStrict(data, &doc); err != nil {
		return ControlSurfaceSnapshot{}, fmt.Errorf("decode workspace control baseline: %w", err)
	}
	if string(doc.Root) != root {
		return ControlSurfaceSnapshot{}, errors.New("workspace control baseline root does not match requested workspace")
	}
	if doc.Schema != controlBaselineSchema || doc.CapBytes <= 0 || doc.Identity == nil || doc.Priority == nil || doc.Nested == nil {
		return ControlSurfaceSnapshot{}, errors.New("invalid workspace control baseline schema or fields")
	}
	priority, err := doc.Priority.decode()
	if err != nil {
		return ControlSurfaceSnapshot{}, err
	}
	nested, err := doc.Nested.decode()
	if err != nil {
		return ControlSurfaceSnapshot{}, err
	}
	if len(doc.Problem) == 0 && (priority.entries == nil || nested.entries == nil) {
		return ControlSurfaceSnapshot{}, errors.New("workspace control baseline is missing observation data")
	}
	return ControlSurfaceSnapshot{root: root, capBytes: doc.CapBytes, identity: *doc.Identity, priority: priority, nested: nested, problem: string(doc.Problem)}, nil
}

func encodeBaselinePass(p controlPass) *baselinePass {
	wire := &baselinePass{Truncated: []byte(p.truncated), DiscoveryLimit: []byte(p.discoveryLimit)}
	if p.entries != nil {
		wire.Entries = make([]baselineEntry, 0, len(p.entries))
	}
	for path, e := range p.entries {
		mode := e.mode
		wire.Entries = append(wire.Entries, baselineEntry{
			Path: []byte(path), Mode: &mode, Kind: e.Kind,
			Size: e.Size, ModSec: e.ModTime.Unix(), ModNsec: int32(e.ModTime.Nanosecond()), // #nosec G115 -- Nanosecond is in [0, 999999999].
			Digest: e.Digest, Oversize: e.Oversize, Target: []byte(e.Target),
		})
	}
	for path, reason := range p.unreadable {
		wire.Unreadable = append(wire.Unreadable, baselineUnreadable{Path: []byte(path), Reason: []byte(reason)})
	}
	for path, from := range p.sources {
		source := baselineSource{Path: []byte(path), From: make([][]byte, 0, len(from))}
		for _, f := range from {
			source.From = append(source.From, []byte(f))
		}
		wire.Sources = append(wire.Sources, source)
	}
	for path := range p.undiscovered {
		wire.Undiscovered = append(wire.Undiscovered, []byte(path))
	}
	for path := range p.partlyListed {
		wire.PartlyListed = append(wire.PartlyListed, []byte(path))
	}
	return wire
}

func (wire *baselinePass) decode() (controlPass, error) {
	p := controlPass{
		unreadable: make(map[string]string, len(wire.Unreadable)),
		truncated:  string(wire.Truncated), discoveryLimit: string(wire.DiscoveryLimit),
		undiscovered: decodeDiscoveryPaths(wire.Undiscovered), partlyListed: decodeDiscoveryPaths(wire.PartlyListed),
	}
	if wire.Entries != nil {
		p.entries = make(map[string]controlEntry, len(wire.Entries))
	}
	for _, e := range wire.Entries {
		path := string(e.Path)
		if _, exists := p.entries[path]; exists || path == "" || e.Mode == nil || e.ModNsec < 0 || e.ModNsec >= 1e9 {
			return controlPass{}, fmt.Errorf("invalid or duplicate workspace control baseline entry %q", path)
		}
		p.entries[path] = controlEntry{mode: *e.Mode, Entry: Entry{
			Path: path, Kind: e.Kind, Size: e.Size,
			ModTime: time.Unix(e.ModSec, int64(e.ModNsec)), Digest: e.Digest, Oversize: e.Oversize, Target: string(e.Target),
		}}
	}
	for _, e := range wire.Unreadable {
		p.unreadable[string(e.Path)] = string(e.Reason)
	}
	p.sources = make(map[string][]string, len(wire.Sources))
	for _, e := range wire.Sources {
		path := string(e.Path)
		if _, exists := p.sources[path]; exists || path == "" {
			return controlPass{}, fmt.Errorf("invalid or duplicate workspace control baseline source %q", path)
		}
		from := make([]string, 0, len(e.From))
		for _, f := range e.From {
			from = append(from, string(f))
		}
		p.sources[path] = from
	}
	return p, nil
}

func decodeDiscoveryPaths(paths [][]byte) map[string]struct{} {
	out := make(map[string]struct{}, len(paths))
	for _, path := range paths {
		out[string(path)] = struct{}{}
	}
	return out
}
