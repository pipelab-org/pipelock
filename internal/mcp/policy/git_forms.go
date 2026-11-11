// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package policy

// Git forms below are the ones Git 2.56.0 documents as discarding work or
// skipping hooks. Sources: git-checkout(1) (including ARGUMENT DISAMBIGUATION),
// git-switch(1), git-restore(1), git-branch(1), git-push(1), git-commit(1),
// git-merge(1), git-rebase(1), git-am(1), and core.hooksPath in git-config(1).
// Short options that Git pairs by case (-b/-B, -c/-C, -d/-D, -m/-M, -f, -n,
// -S/-W) are matched case-sensitively. The surrounding pattern stays
// case-insensitive so a subcommand spelled in any case still counts.

// gitWholeTreePath is a pathspec token Git 2.56.0 applies to every tracked
// path from the work tree root, other than "." and "./". Those two do that
// too, and so do "./.", ":/" and ":(top)" (checked with git restore). "."
// and "./" are left out. Every ordered pair of argument tokens is tried, so
// a pattern that matches "checkout ." also matches checkout together with
// the "." in "git status ." or "git restore --staged .". A directory such
// as "src" is not included: the command text does not show whether the path
// is one file.
const gitWholeTreePath = `(?:\./\.(?:/\.?)*/?|:/|:\(top\))`

// gitRestoreSafeToken is one restore argument that does not limit the command
// to the index. RE2 has no lookahead, so this is the complement of "--staged"
// and of a short cluster that contains S. The surrounding pattern is
// case-insensitive; the S in the short cluster stays case-sensitive.
const gitRestoreSafeToken = `(?:` +
	`--(?:(?:s(?:t(?:a(?:g(?:e(?:d[^\s;|&]|[^\s;|&d])|[^\s;|&e])|[^\s;|&g])|[^\s;|&a])|[^\s;|&t])|[^\s;|&s])[^\s;|&]*|--)` +
	`|-(?-i:[A-RT-Za-z]+)` +
	`|[^\s;|&-]+` +
	`)`

// destructiveGitArgPattern is the Destructive Git Operation argument pattern.
// It keeps the push --force, reset --hard, and clean -fd forms and adds the
// whole-tree discards and ref resets documented above.
//
// push --force-with-lease is a different option (git-push(1)) and is not
// matched. branch -D is not matched here; see gitUnmergedBranchDeleteArgPattern.
// A branch -f or --force that also deletes still matches here, and the block
// action wins over the warn rule, because this expression cannot subtract
// one flag from another.
//
// git restore with no pathspec is not matched: Git 2.56.0 rejects it
// ("you must specify path(s) to restore") before it changes anything.
// --staged without --worktree rewrites the index only, same as a mixed reset,
// which this rule does not cover.
const destructiveGitArgPattern = `(?i)` + shellCommandStart + `(git\s+)?(?:` +
	`push(?:\s+[^\s;|&]+)*?\s+(?:--force(?:[\s;&|()<>]|$)|-[a-z]*f[a-z]*\b|\+[^\s;|&]+)` +
	`|reset(?:\s+[^\s;|&]+)*?\s+--hard\b` +
	`|clean(?:\s+[^\s;|&]+)*?\s+(?:-[a-z]*(?:f[a-z]*d|d[a-z]*f)[a-z]*\b|-[a-z]*f[a-z]*(?:\s+[^\s;|&]+)*?\s+-[a-z]*d[a-z]*\b|-[a-z]*d[a-z]*(?:\s+[^\s;|&]+)*?\s+-[a-z]*f[a-z]*\b)` +
	`|checkout(?:\s+[^\s;|&]+)*?\s+(?:--force(?:[\s;&|()<>]|$)|(?-i:-[A-Za-z]*[Bf][A-Za-z]*)(?:[\s;&|()<>]|$)|(?:--\s+)?` + gitWholeTreePath + `(?:[\s;&|()<>]|$))` +
	`|switch(?:\s+[^\s;|&]+)*?\s+(?:--discard-changes\b|--force-create\b|--force(?:[\s;&|()<>]|$)|(?-i:-[A-Za-z]*[Cf][A-Za-z]*)(?:[\s;&|()<>]|$))` +
	`|branch(?:\s+[^\s;|&]+)*?\s+(?:--force(?:[\s;&|()<>]|$)|(?-i:-[A-Za-z]*[CMf][A-Za-z]*)(?:[\s;&|()<>]|$))` +
	`|restore(?:\s+` + gitRestoreSafeToken + `)*\s+(?:--\s+)?` + gitWholeTreePath + `(?:[\s;&|()<>]|$)` +
	`|restore(?:\s+[^\s;|&]+)*?\s+(?:--worktree\b|(?-i:-[A-Za-z]*W[A-Za-z]*\b))(?:\s+[^\s;|&]+)*\s+(?:--\s+)?` + gitWholeTreePath + `(?:[\s;&|()<>]|$)` +
	`)`

// gitHookBypassArgPattern matches a hook skip. git-commit(1) and git-am(1)
// take -n as --no-verify. git-merge(1) and git-rebase(1) take -n as --no-stat,
// so only the long option counts for those. git-push(1) --no-verify skips the
// pre-push hook. core.hooksPath is an assignment (git -c or git config with a
// value); a read or --unset is not.
//
// gitHookValue is the assigned hooks path. An equals sign may carry any
// value, including an empty one. A separate token has to contain "/" or
// start with ".". A free token would also match whatever word stood before
// "config" once that word is tried after the key, and strict presets block
// that incomplete check.
const gitHookValue = `(?:=[^\s;|&]*|\s+(?:\.[^\s;|&]*|[^\s;|&]*\/[^\s;|&]*))`

const gitHookBypassArgPattern = `(?i)` + shellCommandStart + `(git\s+)?(?:` +
	`(?:commit|am)(?:\s+[^\s;|&]+)*?\s+(?:--no-verify(?:[\s;&|()<>]|$)|(?-i:-[A-Za-z]*n[A-Za-z]*)(?:[\s;&|()<>]|$))` +
	`|(?:merge|rebase|push)(?:\s+[^\s;|&]+)*?\s+--no-verify(?:[\s;&|()<>]|$)` +
	`|config(?:\s+[^\s;|&]+)*?\s+core\.hooksPath` + gitHookValue +
	`|-c(?:=|\s+)core\.hooksPath` + gitHookValue +
	`)`

// gitUnmergedBranchDeleteArgPattern matches git-branch(1) -D, the short
// spelling of an unmerged branch delete. -d alone deletes a merged branch and
// is not matched. A delete that also passes -f or --force matches
// destructiveGitArgPattern as well.
const gitUnmergedBranchDeleteArgPattern = `(?i)` + shellCommandStart + `(git\s+)?branch(?:\s+[^\s;|&]+)*?\s+(?:` +
	`(?-i:-[A-Za-z]*D[A-Za-z]*)(?:[\s;&|()<>]|$)` +
	`|(?-i:-[A-Za-z]*(?:d[A-Za-z]*f|f[A-Za-z]*d)[A-Za-z]*)(?:[\s;&|()<>]|$)` +
	`|(?:--delete\b|(?-i:-[A-Za-z]*d[A-Za-z]*\b))(?:\s+[^\s;|&]+)*?\s+(?:--force(?:[\s;&|()<>]|$)|(?-i:-[A-Za-z]*f[A-Za-z]*)(?:[\s;&|()<>]|$))` +
	`|--force(?:\s+[^\s;|&]+)*?\s+(?:--delete\b|(?-i:-[A-Za-z]*[dD][A-Za-z]*)(?:[\s;&|()<>]|$))` +
	`|(?-i:-[A-Za-z]*f[A-Za-z]*\b)(?:\s+[^\s;|&]+)*?\s+(?:--delete\b|(?-i:-[A-Za-z]*[dD][A-Za-z]*)(?:[\s;&|()<>]|$))` +
	`)`
