// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package mcpwrap

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
)

// ForeignReason explains why a proxy-shaped invocation is not WrapperSelf. It
// never upgrades a classification: every value other than ForeignNone still
// means the invocation is not proven to run this executable.
type ForeignReason int

const (
	// ForeignNone means the invocation is not proxy-shaped or is WrapperSelf.
	ForeignNone ForeignReason = iota
	// ForeignRelativePath means the command is not an absolute path, so its
	// meaning depends on the launching process's working directory or PATH.
	ForeignRelativePath
	// ForeignMissing means the absolute command path does not exist.
	ForeignMissing
	// ForeignDifferentFile means the command exists but is not this executable.
	ForeignDifferentFile
	// ForeignUncheckable means identity could not be inspected (for example a
	// permission error, or this process cannot locate its own executable).
	// It is not evidence that the path is absent.
	ForeignUncheckable
)

// ExplainInvocation returns why command/args, if proxy-shaped, is not proven
// to run this executable. It performs the same identity check as
// ClassifyInvocation, so callers can derive the state and its explanation from
// one inspection.
func ExplainInvocation(command string, args []string) (WrapperState, ForeignReason) {
	if command == "" || len(args) < 2 || args[0] != subcmdMCP || args[1] != subcmdProxy {
		return WrapperNone, ForeignNone
	}
	self, err := os.Executable()
	return explainExecutable(command, self, err)
}

// explainExecutable is the single identity check behind both
// ClassifyInvocation and ExplainInvocation, so a state and its explanation can
// never disagree. The state logic is unchanged from the original
// classifier: only os.SameFile with this executable yields WrapperSelf. The
// reason only describes why a WrapperForeign result was reached.
func explainExecutable(command, self string, executableErr error) (WrapperState, ForeignReason) {
	relative := !filepath.IsAbs(command)
	if executableErr != nil {
		return WrapperForeign, ForeignUncheckable
	}
	selfInfo, err := os.Stat(self)
	if err != nil {
		return WrapperForeign, ForeignUncheckable
	}
	commandInfo, err := os.Stat(command)
	switch {
	case err == nil && os.SameFile(selfInfo, commandInfo):
		return WrapperSelf, ForeignNone
	case relative:
		return WrapperForeign, ForeignRelativePath
	case errors.Is(err, fs.ErrNotExist):
		return WrapperForeign, ForeignMissing
	case err != nil:
		return WrapperForeign, ForeignUncheckable
	default:
		return WrapperForeign, ForeignDifferentFile
	}
}
