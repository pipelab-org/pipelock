// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package policy

import (
	"regexp"
	"strings"
)

// gitBuiltins is the output of `git --list-cmds=builtins` from Git 2.56.0, the
// version the Git option tables in long_options.go follow. Git runs a builtin
// before it looks up an alias, so a configured alias cannot replace one
// (git-config(1), alias.*: "aliases that hide existing commands are ignored").
// Builtin names match exactly: Git 2.56.0 reads git RESET as an alias name.
// Every other subcommand word may run an alias from any configuration source,
// including files and environment the command line does not show, or an
// external git-<name> program.
var gitBuiltins = func() map[string]bool {
	set := make(map[string]bool)
	for _, name := range strings.Fields(`add am annotate apply archive backfill
		bisect blame branch bugreport bundle cat-file check-attr check-ignore
		check-mailmap check-ref-format checkout checkout--worker checkout-index
		cherry cherry-pick clean clone column commit commit-graph commit-tree
		config count-objects credential credential-cache
		credential-cache--daemon credential-store describe diagnose diff
		diff-files diff-index diff-pairs diff-tree difftool fast-export
		fast-import fetch fetch-pack fmt-merge-msg for-each-ref for-each-repo
		format-patch format-rev fsck fsck-objects fsmonitor--daemon gc
		get-tar-commit-id grep hash-object help history hook index-pack init
		init-db interpret-trailers last-modified log ls-files ls-remote ls-tree
		mailinfo mailsplit maintenance merge merge-base merge-file merge-index
		merge-ours merge-recursive merge-recursive-ours merge-recursive-theirs
		merge-subtree merge-tree mktag mktree multi-pack-index mv name-rev notes
		pack-objects pack-redundant pack-refs patch-id pickaxe prune
		prune-packed pull push range-diff read-tree rebase receive-pack reflog
		refs remote remote-ext remote-fd repack replace replay repo rerere reset
		restore rev-list rev-parse revert rm send-pack shortlog show show-branch
		show-index show-ref sparse-checkout stage stash status stripspace
		submodule--helper switch symbolic-ref tag unpack-file unpack-objects
		update-index update-ref update-server-info upload-archive
		upload-archive--writer upload-pack url-parse var verify-commit
		verify-pack verify-tag version whatchanged worktree write-tree`) {
		set[name] = true
	}
	return set
}()

// gitToolName matches the dedicated git tool, whose arguments are Git's own
// argument list without the word git. It is the git alternative of the default
// Destructive Git Operation rule's tool pattern, with the namespace prefixes
// every shipped rule accepts (builtinToolNameAliasPrefix); the rule's other
// alternatives are shell tools. TestGitToolNameFromRules derives it from the
// default rules.
var gitToolName = regexp.MustCompile(`(?i)^(?:` + builtinToolNameAliasPrefix + `)?git$`)

// gitSubcommandUnknown reports whether args run a Git subcommand that is not a
// builtin, reading each subcommand word as Git receives it. The normalized
// views drop invisible characters, fold lookalike letters and split words on
// every Unicode space, so a word such as fetch followed by a carriage return,
// or written with a Cyrillic e, reads there as the builtin fetch while Git
// looks it up as written and runs an alias or git-<name> program. Here only
// the shell's own spelling is resolved (quotes, escapes, expansions), and
// words split on the shell's default field separators, space and tab; a
// newline stays in the word and separates commands as in the normalized views.
// gitBuiltins then matches only the exact ASCII name. gitTool is as for
// normalizeLineOptions.
func gitSubcommandUnknown(args []string, gitTool bool) bool {
	var words []string
	for _, arg := range args {
		words = append(words, strings.FieldsFunc(resolveShellSpelling(arg), func(r rune) bool { return r == ' ' || r == '\t' })...)
	}
	_, unknown := normalizeOptions(words, false, gitTool)
	return unknown
}

// gitDestructiveOptions are the long options in the covered Git subcommands'
// option tables (commandLongOptions) that a built-in rule blocks on their own:
// reset --hard and push --force under Destructive Git Operation, and git rm
// --force under Destructive File Delete. Clean's force option is blocked only
// together with -d, which has no long form. TestGitDestructiveOptionsFromRules
// derives this list from DefaultToolPolicyRules.
var gitDestructiveOptions = []struct{ command, option string }{
	{"reset", "hard"},
	{"push", "force"},
	{"rm", "force"},
}

// gitDestructiveReadings returns "<subcommand> --<option>" for each destructive
// option that word spells in full or abbreviates, ambiguous prefixes included,
// as Git would read it if the subcommand ran that builtin. Option names match
// case-sensitively, as Git's parse-options does; a value after = is ignored.
func gitDestructiveReadings(word string) []string {
	name, _, _ := strings.Cut(strings.TrimPrefix(word, "--"), "=")
	if !strings.HasPrefix(word, "--") || name == "" {
		return nil
	}
	var readings []string
	for _, d := range gitDestructiveOptions {
		if strings.HasPrefix(d.option, name) {
			readings = append(readings, d.command+" --"+d.option)
		}
	}
	return readings
}
