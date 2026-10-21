// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package projectscan

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/BurntSushi/toml"
)

// Agent type constants.
const (
	AgentClaudeCode = "claude-code"
	AgentCursor     = "cursor"
	AgentCrewAI     = "crewai"
	AgentLangGraph  = "langgraph"
	AgentAutoGen    = "autogen"
	AgentGeneric    = "generic"
)

// detectAgent identifies the agent type from project markers.
func detectAgent(dir string) string {
	// Claude Code markers
	if dirExists(filepath.Join(dir, ".claude")) || fileExists(filepath.Join(dir, "CLAUDE.md")) {
		return AgentClaudeCode
	}

	// Cursor markers
	if dirExists(filepath.Join(dir, ".cursor")) || fileExists(filepath.Join(dir, ".cursorrules")) {
		return AgentCursor
	}

	// Framework markers in Python requirements
	if deps := readPythonDeps(dir); len(deps) > 0 {
		for _, dep := range deps {
			switch {
			case strings.HasPrefix(dep, "crewai"):
				return AgentCrewAI
			case strings.HasPrefix(dep, "langgraph"):
				return AgentLangGraph
			case strings.HasPrefix(dep, "autogen") || strings.HasPrefix(dep, "pyautogen"):
				return AgentAutoGen
			}
		}
	}

	// LangGraph in package.json
	if hasDependency(filepath.Join(dir, "package.json"), "@langchain/langgraph") {
		return AgentLangGraph
	}

	return AgentGeneric
}

// detectLanguages counts file extensions to identify languages.
func detectLanguages(dir string) []string {
	counts := make(map[string]int)
	_ = filepath.WalkDir(dir, func(_ string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			if skipDirs[d.Name()] {
				return filepath.SkipDir
			}
			return nil
		}
		ext := filepath.Ext(d.Name())
		switch ext {
		case ".py":
			counts["Python"]++
		case ".js":
			counts["JavaScript"]++
		case ".ts":
			counts["TypeScript"]++
		case ".go":
			counts["Go"]++
		case ".rs":
			counts["Rust"]++
		case ".rb":
			counts["Ruby"]++
		case ".java":
			counts["Java"]++
		}
		return nil
	})

	// Return languages sorted by count (descending)
	type langCount struct {
		name  string
		count int
	}
	var langs []langCount
	for name, count := range counts {
		langs = append(langs, langCount{name, count})
	}
	// Simple insertion sort -- small slice
	for i := 1; i < len(langs); i++ {
		for j := i; j > 0 && langs[j].count > langs[j-1].count; j-- {
			langs[j], langs[j-1] = langs[j-1], langs[j]
		}
	}

	result := make([]string, len(langs))
	for i, l := range langs {
		result[i] = l.name
	}
	return result
}

// Ecosystem constants.
const (
	EcoNPM      = "npm"
	EcoPip      = "pip"
	EcoGoMod    = "go"
	EcoCargo    = "cargo"
	EcoRubyGems = "rubygems"
	EcoMaven    = "maven"
)

// ecosystemDomains maps each ecosystem to domains that should be allowlisted.
var ecosystemDomains = map[string][]string{
	EcoNPM:      {"registry.npmjs.org", "*.npmjs.com"},
	EcoPip:      {"pypi.org", "*.python.org", "*.pythonhosted.org"},
	EcoGoMod:    {"pkg.go.dev", "proxy.golang.org", "sum.golang.org"},
	EcoCargo:    {"crates.io", "*.crates.io", "*.docs.rs"},
	EcoRubyGems: {"*.rubygems.org"},
	EcoMaven:    {"*.maven.org"},
}

// detectEcosystems identifies package ecosystems from manifest files.
func detectEcosystems(dir string) []string {
	var ecos []string
	checks := []struct {
		files []string
		eco   string
	}{
		{[]string{"package.json", "package-lock.json", "yarn.lock", "pnpm-lock.yaml"}, EcoNPM},
		{[]string{"requirements.txt", "pyproject.toml", "Pipfile", "setup.py", "setup.cfg"}, EcoPip},
		{[]string{"go.mod"}, EcoGoMod},
		{[]string{"Cargo.toml", "Cargo.lock"}, EcoCargo},
		{[]string{"Gemfile", "Gemfile.lock"}, EcoRubyGems},
		{[]string{"pom.xml", "build.gradle", "build.gradle.kts"}, EcoMaven},
	}

	for _, c := range checks {
		for _, f := range c.files {
			if fileExists(filepath.Join(dir, f)) {
				ecos = append(ecos, c.eco)
				break
			}
		}
	}
	return ecos
}

// mcpConfig represents the structure of .mcp.json files.
type mcpConfig struct {
	MCPServers map[string]json.RawMessage `json:"mcpServers"`
}

// detectMCPServers reads .mcp.json and returns server names.
func detectMCPServers(dir string) []string {
	path := filepath.Join(dir, ".mcp.json")
	data, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		return nil
	}

	var cfg mcpConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil
	}

	servers := make([]string, 0, len(cfg.MCPServers))
	for name := range cfg.MCPServers {
		servers = append(servers, name)
	}
	return servers
}

// hasGitRepo checks for a .git directory.
func hasGitRepo(dir string) bool {
	return dirExists(filepath.Join(dir, ".git"))
}

// readPythonDeps reads dependency names from requirements.txt or pyproject.toml.
func readPythonDeps(dir string) []string {
	// Try requirements.txt first
	path := filepath.Join(dir, "requirements.txt")
	data, err := os.ReadFile(filepath.Clean(path))
	if err == nil {
		return parsePythonRequirements(string(data))
	}

	// Try pyproject.toml dependencies section (simplified)
	path = filepath.Join(dir, "pyproject.toml")
	data, err = os.ReadFile(filepath.Clean(path))
	if err == nil {
		return parsePyprojectDeps(string(data))
	}

	return nil
}

func parsePythonRequirements(content string) []string {
	var deps []string
	for _, line := range strings.Split(content, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "-") {
			continue
		}
		// Extract package name before version specifier or inline comment
		for i, ch := range line {
			if ch == '=' || ch == '>' || ch == '<' || ch == '!' || ch == '[' || ch == ';' || ch == '#' {
				line = line[:i]
				break
			}
		}
		dep := strings.TrimSpace(strings.ToLower(line))
		if dep != "" {
			deps = append(deps, dep)
		}
	}
	return deps
}

func parsePyprojectDeps(content string) []string {
	// Simplified: look for lines that contain known framework names
	lower := strings.ToLower(content)
	var deps []string
	for _, name := range []string{"crewai", "langgraph", "autogen", "pyautogen"} {
		if strings.Contains(lower, name) {
			deps = append(deps, name)
		}
	}
	return deps
}

// hasDependency checks if a package.json contains a dependency.
func hasDependency(path, pkg string) bool {
	data, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		return false
	}

	var pj struct {
		Dependencies    map[string]string `json:"dependencies"`
		DevDependencies map[string]string `json:"devDependencies"`
	}
	if err := json.Unmarshal(data, &pj); err != nil {
		return false
	}

	if _, ok := pj.Dependencies[pkg]; ok {
		return true
	}
	_, ok := pj.DevDependencies[pkg]
	return ok
}

// hostileToolingPackages are Python packages associated with guardrail removal,
// model ablation, or safety bypass toolchains.
var hostileToolingPackages = []string{
	"obliteratus",
	"abliterator",
	"refusal-ablation",
	"llm-abliterator",
}

// detectHostileTooling checks project dependencies for guardrail-removal toolchains.
// Returns findings for each detected package.
func detectHostileTooling(dir string) []Finding {
	var findings []Finding

	// readPythonDeps/parsePyprojectDeps only looks for agent frameworks, so
	// the dependency-bearing manifests are inspected separately here.
	manifests := []struct {
		file  string
		names func([]byte) (map[string]bool, error)
	}{
		{"requirements.txt", requirementNames},
		{"pyproject.toml", pyprojectDependencyNames},
	}
	for _, m := range manifests {
		data, err := readManifest(filepath.Join(dir, m.file))
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err != nil {
			// A manifest we cannot read cannot establish that the project is clean.
			reason := "unreadable"
			if errors.Is(err, errManifestTooLarge) {
				reason = "larger than the scan size limit"
			}
			findings = append(findings, inspectionWarning(m.file, reason))
			continue
		}
		deps, namesErr := m.names(data)
		for _, hostile := range hostileToolingPackages {
			if deps[hostile] && !hasHostileFinding(findings, hostile) {
				findings = append(findings, Finding{
					Severity: "warning",
					Category: "tooling",
					Message:  fmt.Sprintf("Guardrail-removal toolchain detected: %s. Consider `pipelock generate config --preset hostile-model`.", hostile),
					Pattern:  hostile,
				})
			}
		}
		if namesErr != nil {
			// Names found before the problem are reported above; the rest of
			// the manifest could not be read, so say so instead of staying quiet.
			findings = append(findings, inspectionWarning(m.file, "malformed"))
		}
	}

	// Check for HuggingFace ablation configs
	ablationFiles := []string{
		"abliterate.py",
		"abliteration.py",
		"remove_refusals.py",
		"uncensor.py",
	}
	for _, name := range ablationFiles {
		if fileExists(filepath.Join(dir, name)) {
			findings = append(findings, Finding{
				Severity: "warning",
				Category: "tooling",
				File:     name,
				Message:  fmt.Sprintf("Ablation script detected: %s. The model in this project may have safety guardrails removed.", name),
			})
		}
	}

	return findings
}

// errManifestTooLarge reports a manifest over maxScanFileBytes. The TOML
// decoder recurses once per nesting level, so a few MB of nested brackets
// overflows the goroutine stack, which Go cannot recover from.
var errManifestTooLarge = errors.New("manifest exceeds the scan size limit")

// readManifest reads a dependency manifest, refusing anything over the same
// size limit scanFiles applies to config files.
func readManifest(path string) ([]byte, error) {
	f, err := os.Open(filepath.Clean(path))
	if err != nil {
		return nil, err
	}
	defer f.Close() //nolint:errcheck // read-only file
	data, err := io.ReadAll(io.LimitReader(f, maxScanFileBytes+1))
	if err != nil {
		return nil, err
	}
	if len(data) > maxScanFileBytes {
		return nil, errManifestTooLarge
	}
	return data, nil
}

// inspectionWarning reports a manifest whose dependencies could not be fully
// read, so an incomplete scan never looks the same as a clean one.
func inspectionWarning(file, reason string) Finding {
	return Finding{
		Severity: "warning",
		Category: "tooling",
		File:     file,
		Message:  fmt.Sprintf("Could not inspect %s dependencies (%s); fix the manifest and scan again.", file, reason),
	}
}

// requirementComment matches a comment in a pip requirements file: a line
// starting with # or whitespace followed by #. Line continuation is a trailing
// backslash. https://pip.pypa.io/en/stable/reference/requirements-file-format/
var requirementComment = regexp.MustCompile(`(?:^|\s)#.*$`)

// utf8BOM is the byte order mark pip accepts at the start of a requirements file.
const utf8BOM = "\xef\xbb\xbf"

// requirementNames returns the normalized package names in a pip requirements
// file. Option lines (-r, -e, --index-url) start with a dash, which is not a
// PEP 508 name, so they yield no name; per-requirement options (--hash) are
// cut off before the requirement is read.
func requirementNames(data []byte) (map[string]bool, error) {
	text := strings.TrimPrefix(string(data), utf8BOM)
	text = strings.ReplaceAll(text, "\r\n", "\n")
	text = strings.ReplaceAll(text, "\\\n", " ")
	names := make(map[string]bool)
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(requirementComment.ReplaceAllString(line, ""))
		if i := strings.Index(line, " --"); i >= 0 {
			line = line[:i]
		}
		if name := pep508DependencyName(line); name != "" {
			names[name] = true
		}
	}
	return names, nil
}

// dependencyWalk collects package names from the dependency-bearing tables of
// a decoded pyproject.toml. A node with an unexpected type is recorded in
// problems, never skipped silently, so one malformed table cannot hide names
// that other tables declare.
type dependencyWalk struct {
	root     map[string]any
	names    map[string]bool
	problems []string
}

func (w *dependencyWalk) bad(path string) { w.problems = append(w.problems, path) }

// lookup returns the node at keys and its dotted path. A missing key is not a
// problem; a non-table where a table is required is.
func (w *dependencyWalk) lookup(keys ...string) (any, string, bool) {
	var cur any = w.root
	path := ""
	for _, key := range keys {
		table, ok := cur.(map[string]any)
		if !ok {
			w.bad(path)
			return nil, "", false
		}
		next, found := table[key]
		if !found {
			return nil, "", false
		}
		cur = next
		if path != "" {
			path += "."
		}
		path += key
	}
	return cur, path, true
}

// requirements reads an array of PEP 508 strings. PEP 735 groups may also hold
// {include-group = "name"} tables, which name no package.
func (w *dependencyWalk) requirements(path string, node any, allowInclude bool) {
	items, ok := node.([]any)
	if !ok {
		w.bad(path)
		return
	}
	for _, item := range items {
		switch it := item.(type) {
		case string:
			if name := pep508DependencyName(it); name != "" {
				w.names[name] = true
			}
		case map[string]any:
			if _, isInclude := it["include-group"].(string); !allowInclude || !isInclude || len(it) != 1 {
				w.bad(path)
			}
		default:
			w.bad(path)
		}
	}
}

// groups reads a table whose values are requirement arrays.
func (w *dependencyWalk) groups(path string, node any, allowInclude bool) {
	table, ok := node.(map[string]any)
	if !ok {
		w.bad(path)
		return
	}
	for name, group := range table {
		w.requirements(path+"."+name, group, allowInclude)
	}
}

// keyed reads a Poetry-style table whose keys are package names.
func (w *dependencyWalk) keyed(path string, node any) {
	table, ok := node.(map[string]any)
	if !ok {
		w.bad(path)
		return
	}
	for name := range table {
		w.names[normalizePythonPackageName(name)] = true
	}
}

// each visits every table in a table of tables (Poetry groups, Hatch envs).
func (w *dependencyWalk) each(path string, node any, visit func(path string, table map[string]any)) {
	outer, ok := node.(map[string]any)
	if !ok {
		w.bad(path)
		return
	}
	for name, inner := range outer {
		table, ok := inner.(map[string]any)
		if !ok {
			w.bad(path + "." + name)
			continue
		}
		visit(path+"."+name, table)
	}
}

// pyprojectDependencyNames returns the normalized package names declared in
// the dependency-bearing pyproject.toml tables. Sources:
//   - build-system.requires: PEP 518, https://peps.python.org/pep-0518/
//   - project.dependencies, project.optional-dependencies: PEP 621,
//     https://peps.python.org/pep-0621/
//   - dependency-groups: PEP 735, https://peps.python.org/pep-0735/
//   - tool.poetry dependencies, dev-dependencies and group.*.dependencies:
//     https://python-poetry.org/docs/pyproject/
//   - tool.uv.dev-dependencies:
//     https://docs.astral.sh/uv/concepts/projects/dependencies/
//   - tool.pdm.dev-dependencies, the pre-PEP 735 PDM groups that PDM still reads
//   - tool.hatch.envs.*.dependencies and extra-dependencies:
//     https://hatch.pypa.io/latest/config/environment/overview/
//
// On a parse failure the returned map is nil. On an unexpected node type the
// names found elsewhere are still returned alongside the error.
func pyprojectDependencyNames(data []byte) (map[string]bool, error) {
	var root map[string]any
	if err := toml.Unmarshal(data, &root); err != nil {
		return nil, fmt.Errorf("parse pyproject.toml: %w", err)
	}
	w := &dependencyWalk{root: root, names: make(map[string]bool)}

	if node, path, ok := w.lookup("build-system", "requires"); ok {
		w.requirements(path, node, false)
	}
	if node, path, ok := w.lookup("project", "dependencies"); ok {
		w.requirements(path, node, false)
	}
	if node, path, ok := w.lookup("project", "optional-dependencies"); ok {
		w.groups(path, node, false)
	}
	if node, path, ok := w.lookup("dependency-groups"); ok {
		w.groups(path, node, true)
	}
	if node, path, ok := w.lookup("tool", "poetry", "dependencies"); ok {
		w.keyed(path, node)
	}
	if node, path, ok := w.lookup("tool", "poetry", "dev-dependencies"); ok {
		w.keyed(path, node)
	}
	if node, path, ok := w.lookup("tool", "poetry", "group"); ok {
		w.each(path, node, func(path string, table map[string]any) {
			if deps, found := table["dependencies"]; found {
				w.keyed(path+".dependencies", deps)
			}
		})
	}
	if node, path, ok := w.lookup("tool", "uv", "dev-dependencies"); ok {
		w.requirements(path, node, false)
	}
	if node, path, ok := w.lookup("tool", "pdm", "dev-dependencies"); ok {
		w.groups(path, node, false)
	}
	if node, path, ok := w.lookup("tool", "hatch", "envs"); ok {
		w.each(path, node, func(path string, table map[string]any) {
			for _, key := range []string{"dependencies", "extra-dependencies"} {
				if deps, found := table[key]; found {
					w.requirements(path+"."+key, deps, false)
				}
			}
		})
	}

	if len(w.problems) > 0 {
		return w.names, fmt.Errorf("unexpected dependency shape in %s", strings.Join(w.problems, ", "))
	}
	return w.names, nil
}

// PEP 508's name grammar starts with an ASCII letter or digit, permits
// internal [-_.], and ends with a letter or digit:
// https://peps.python.org/pep-0508/#complete-grammar.
var pep508PackageName = regexp.MustCompile(`^[A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?`)

func pep508DependencyName(requirement string) string {
	requirement = strings.TrimSpace(requirement)
	name := pep508PackageName.FindString(requirement)
	if name == "" {
		return ""
	}
	rest := strings.TrimSpace(requirement[len(name):])
	if rest != "" && !strings.ContainsRune("[(@<>=!~;", rune(rest[0])) {
		return ""
	}
	return normalizePythonPackageName(name)
}

// PEP 503 normalizes runs of hyphens, underscores, and dots to one hyphen,
// then lowercases: https://peps.python.org/pep-0503/#normalized-names.
var pythonPackageSeparators = regexp.MustCompile(`[-_.]+`)

func normalizePythonPackageName(name string) string {
	return strings.ToLower(pythonPackageSeparators.ReplaceAllString(name, "-"))
}

func hasHostileFinding(findings []Finding, pattern string) bool {
	for _, f := range findings {
		if f.Category == "tooling" && f.Pattern == pattern {
			return true
		}
	}
	return false
}

func fileExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && !info.IsDir()
}

func dirExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.IsDir()
}
