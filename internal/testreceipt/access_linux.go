// Copyright 2026 Pipelab
// SPDX-License-Identifier: Apache-2.0

package testreceipt

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/testwait"
)

type accessWatch struct {
	fd   int
	dir  int
	file int
}

type observedAccess struct {
	dir, file bool
}

func watchEvidence(t *testing.T, dir, file string) accessWatch {
	t.Helper()
	fd, err := unix.InotifyInit1(unix.IN_CLOEXEC | unix.IN_NONBLOCK)
	if err != nil {
		t.Fatalf("initialize inotify: %v", err)
	}
	t.Cleanup(func() { _ = unix.Close(fd) })
	add := func(path string) int {
		t.Helper()
		wd, err := unix.InotifyAddWatch(fd, path, unix.IN_OPEN|unix.IN_ACCESS|unix.IN_DONT_FOLLOW)
		if err != nil {
			t.Fatalf("watch %q: %v", path, err)
		}
		return wd
	}
	return accessWatch{fd: fd, dir: add(dir), file: add(file)}
}

func (watch accessWatch) read(t *testing.T) observedAccess {
	t.Helper()
	var access observedAccess
	var buffer [4096]byte
	for {
		n, err := unix.Read(watch.fd, buffer[:])
		switch {
		case errors.Is(err, unix.EAGAIN):
			return access
		case errors.Is(err, unix.EINTR):
			continue
		case err != nil || n == 0:
			t.Fatalf("read inotify: %d bytes, %v", n, err)
		}
		for events := buffer[:n]; len(events) > 0; {
			if len(events) < unix.SizeofInotifyEvent {
				t.Fatal("truncated inotify header")
			}
			wd := int(binary.NativeEndian.Uint32(events[:4]))
			mask := binary.NativeEndian.Uint32(events[4:8])
			nameBytes := int(binary.NativeEndian.Uint32(events[12:16]))
			if nameBytes > len(events)-unix.SizeofInotifyEvent {
				t.Fatal("truncated inotify name")
			}
			if mask&unix.IN_Q_OVERFLOW != 0 {
				t.Fatal("inotify queue overflow; evidence accesses were lost")
			}
			if mask&(unix.IN_OPEN|unix.IN_ACCESS) != 0 {
				// Changes to unrelated children are not receipt reads. A
				// watch on the stream captures its opens independently.
				access.dir = access.dir || wd == watch.dir && nameBytes == 0
				access.file = access.file || wd == watch.file
			}
			events = events[unix.SizeofInotifyEvent+nameBytes:]
		}
	}
}

func calibrateEvidenceWatch(t *testing.T, fixture oracleFixture) {
	t.Helper()
	watch := watchEvidence(t, fixture.dir, fixture.file)
	if got := watch.read(t); got != (observedAccess{}) {
		t.Fatalf("new watch unexpectedly has access events: %+v", got)
	}
	if _, err := os.ReadDir(fixture.dir); err != nil {
		t.Fatal(err)
	}
	if got := watch.read(t); got != (observedAccess{dir: true}) {
		t.Fatalf("directory open did not generate its own inotify event: %+v", got)
	}
	file, err := os.Open(fixture.file)
	if err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	if got := watch.read(t); !got.file {
		t.Fatalf("stream open did not generate an inotify event: %+v", got)
	}
	t.Log("calibrated inotify against a directory listing and a stream open")
}

// AccessOracleExclusion binds a command that needs host privileges, a service,
// or a long-lived process to the test that drives the relevant code path.
type AccessOracleExclusion struct {
	Reason, Package, Test string
}

// AccessOracle describes the existing Cobra probes and the command-specific
// inputs that differ from the default isolated command invocation.
type AccessOracle struct {
	Root       *cobra.Command
	Probes     map[string][]ReceiptProbe
	Inputs     map[string][]string
	MustOpen   []string
	Runtimes   []string
	Exclusions map[string]AccessOracleExclusion
	Invoke     func(t *testing.T, args []string, out io.Writer, dir string, existingProbe bool) int
}

// BuildAccessBinary builds the actual CLI for probes that cannot share Go
// process state with other tests.
func BuildAccessBinary(t *testing.T, name string, enterprise bool) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	args := []string{"build", "-o", path}
	if enterprise {
		args = append(args, "-tags", "enterprise")
	}
	args = append(args, "./cmd/"+name)
	cmd := exec.CommandContext(t.Context(), "go", args...) // #nosec G204 -- Go build of a known repository command.
	cmd.Dir = accessRepoRoot(t)
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build %s: %v\n%s", name, err, output)
	}
	return path
}

// ExecuteAccessBinary runs an isolated CLI probe without inheriting credentials
// or the developer's installed integrations. No program receives input on stdin.
func ExecuteAccessBinary(t *testing.T, binary string, args []string, out io.Writer, side string) int {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), testwait.Deadline(5*time.Second))
	defer cancel()
	cmd := exec.CommandContext(ctx, binary, args...) // #nosec G204 -- locally built CLI and fixed test input.
	cmd.Dir = filepath.Join(side, "work")
	if err := os.Mkdir(cmd.Dir, 0o750); err != nil {
		t.Fatal(err)
	}
	cmd.Env = []string{
		"HOME=" + side, "XDG_CONFIG_HOME=" + filepath.Join(side, "config"),
		"XDG_DATA_HOME=" + filepath.Join(side, "data"), "XDG_RUNTIME_DIR=" + side,
		"PIPELOCK_HOME=" + filepath.Join(side, "home"), "PIPELOCK_CONFIG=" + filepath.Join(side, "pipelock.yaml"),
		"PIPELOCK_API_URL=http://127.0.0.1:0", "PATH=" + filepath.Join(side, "bin"),
	}
	for _, key := range []string{"HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY", "http_proxy", "https_proxy", "all_proxy", "no_proxy"} {
		if value, ok := os.LookupEnv(key); ok {
			cmd.Env = append(cmd.Env, key+"="+value)
		}
	}
	cmd.Stdout, cmd.Stderr = out, out
	err := cmd.Run()
	if err == nil {
		return 0
	}
	if ctx.Err() != nil {
		t.Fatalf("command %v did not finish: %v", args, ctx.Err())
	}
	var exit *exec.ExitError
	if !errors.As(err, &exit) || exit.ExitCode() < 0 {
		t.Fatalf("run command %v: %v", args, err)
	}
	return exit.ExitCode()
}

func accessRepoRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("cannot locate repository root for access oracle")
		}
		dir = parent
	}
}

func requireExclusionTest(t *testing.T, command string, skip AccessOracleExclusion) {
	t.Helper()
	if skip.Reason == "" || skip.Package == "" || !strings.HasPrefix(skip.Test, "Test") {
		t.Errorf("exclusion for %s must name a reason and behavior test", command)
		return
	}
	files, err := filepath.Glob(filepath.Join(accessRepoRoot(t), skip.Package, "*_test.go"))
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range files {
		file, err := parser.ParseFile(token.NewFileSet(), path, nil, parser.SkipObjectResolution)
		if err != nil {
			t.Fatal(err)
		}
		for _, decl := range file.Decls {
			if fn, ok := decl.(*ast.FuncDecl); ok && fn.Recv == nil && fn.Name.Name == skip.Test {
				t.Logf("excluded %s: %s (%s/%s)", command, skip.Reason, skip.Package, skip.Test)
				return
			}
		}
	}
	t.Errorf("exclusion for %s references missing test %s/%s", command, skip.Package, skip.Test)
}

func visitRunnable(cmd *cobra.Command, visit func(*cobra.Command)) {
	if cmd.Runnable() && cmd.Parent() != nil {
		visit(cmd)
	}
	for _, child := range cmd.Commands() {
		visitRunnable(child, visit)
	}
}

// RunObservedAccessOracle runs every runnable command, including runnable
// groups. Successful receipt verification must report a valid v3 verdict.
func RunObservedAccessOracle(t *testing.T, suite AccessOracle) {
	t.Helper()
	fixtures := oracleFixtures(t)
	fixture := fixtures[0]
	calibrateEvidenceWatch(t, fixture)
	var lc net.ListenConfig
	listener, err := lc.Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := listener.Addr().String()
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	var touched []string
	var tested, excluded, cases int
	seen := make(map[string]bool)
	ran := make(map[string]bool)
	visitRunnable(suite.Root, func(cmd *cobra.Command) {
		name := strings.TrimPrefix(cmd.CommandPath(), suite.Root.Name()+" ")
		seen[name] = true
		if skip, ok := suite.Exclusions[name]; ok {
			excluded++
			requireExclusionTest(t, name, skip)
			return
		}
		tested++
		args, ok := suite.Inputs[name]
		if !ok {
			args = accessOperands(cmd)
		}
		args = requiredAccessFlags(cmd, args)
		probes := []ReceiptProbe{{Args: args}}
		probes = append(probes, suite.Probes[name]...)
		probes = append(probes, accessFlagProbes(cmd, args, suite.Probes[name])...)
		t.Run(name, func(t *testing.T) {
			ran[name] = true
			observed := false
			for i, probe := range probes {
				cases++
				t.Run(fmt.Sprintf("probe_%d", i), func(t *testing.T) {
					observed = runAccessProbe(t, suite, cmd, name, fixture, address, probe.Args, i > 0 && i <= len(suite.Probes[name])) || observed
				})
			}
			if slices.Contains(suite.Runtimes, name) {
				cases++
				t.Run("damaged_history", func(t *testing.T) {
					runAccessProbe(t, suite, cmd, name, fixtures[1], address, args, false)
				})
			}
			if observed {
				touched = append(touched, name)
			}
		})
	})
	for _, name := range suite.MustOpen {
		if ran[name] && !slices.Contains(touched, name) {
			t.Errorf("fixture did not reach the evidence reader in %s", name)
		}
	}
	for name := range suite.Inputs {
		if !seen[name] {
			t.Errorf("stale observed-access inputs for %s", name)
		}
	}
	t.Logf("%s: %d runnable commands, %d invocations, %d exclusions", suite.Root.Name(), tested, cases, excluded)
	t.Logf("commands that opened v3 evidence: %s", strings.Join(touched, ", "))
}

func accessOperands(cmd *cobra.Command) []string {
	_, usage, _ := strings.Cut(cmd.Use, " ")
	var args []string
	for _, word := range strings.Fields(usage) {
		if strings.HasPrefix(word, "[") {
			break
		}
		if pathOperand.MatchString(word) && readsReceiptOperand(cmd) {
			if strings.Contains(strings.ToLower(word), "dir") {
				args = append(args, "$dir")
			} else {
				args = append(args, "$file")
			}
		} else {
			args = append(args, "example")
		}
	}
	return args
}

func requiredAccessFlags(cmd *cobra.Command, args []string) []string {
	cmd.InheritedFlags()
	cmd.Flags().VisitAll(func(flag *pflag.Flag) {
		marked, ok := flag.Annotations[cobra.BashCompOneRequiredFlag]
		if !ok || !slices.Contains(marked, "true") || slices.Contains(args, "--"+flag.Name) {
			return
		}
		input := evidenceFlagInput(cmd, flag)
		if input == "" {
			input = "example"
			switch {
			case flag.Name == "config":
				input = "$config"
			case strings.HasSuffix(flag.Name, "key-file"):
				input = "$keyfile"
			case strings.Contains(flag.Name, "key") || strings.Contains(flag.Name, "fingerprint"):
				input = "$pub"
			case strings.Contains(flag.Name, "out"):
				input = "$tmp/output"
			case strings.Contains(flag.Name, "url"):
				input = "http://127.0.0.1:0"
			case flag.Value.Type() == "int" || flag.Value.Type() == "uint":
				input = "1"
			}
		}
		if flag.NoOptDefVal != "" {
			i := slices.Index(args, "--")
			if i < 0 {
				i = len(args)
			}
			args = slices.Insert(slices.Clone(args), i, "--"+flag.Name+"="+flag.NoOptDefVal)
		} else {
			args = replaceAccessFlag(args, flag.Name, input)
		}
	})
	return args
}

func readsReceiptOperand(cmd *cobra.Command) bool {
	switch cmd.Name() {
	case "aarp", "provenance", "audit-packet", "chain", "completeness", "independent", "receipt", "replay", "verify-run", "verify-receipt":
		return true
	}
	return cmd.Parent().Name() == "evidence"
}

func evidenceFlagInput(cmd *cobra.Command, flag *pflag.Flag) string {
	switch flag.Value.Type() {
	case "string", "stringArray", "stringSlice":
	default:
		return ""
	}
	switch flag.Name {
	case "chain", "receipt-dir", "recorder-dir", "sessions", "capture-dir", "capture-output", "receipts-dir", "contract-store", "recheck-source":
		return "$dir"
	case "location":
		return "evidence"
	case "events", "bundle", "inventory", "pin", "receipt-out", "anchor-local-log":
		return "$file"
	}
	if flag.Name == "cert" && (cmd.Name() == "verify-cert" || cmd.Parent().Name() == "coverage-cert") {
		return "$file"
	}
	usage := strings.ToLower(flag.Usage)
	if strings.Contains(usage, "receipt") || strings.Contains(usage, "evidence") || strings.Contains(usage, "recorder") {
		switch {
		case strings.Contains(usage, "directory"):
			return "$dir"
		case strings.Contains(usage, "file") && !strings.Contains(usage, "key") && !strings.Contains(usage, "out"):
			return "$file"
		}
	}
	return ""
}

func accessFlagProbes(cmd *cobra.Command, defaults []string, existing []ReceiptProbe) []ReceiptProbe {
	cmd.InheritedFlags()
	var probes []ReceiptProbe
	cmd.Flags().VisitAll(func(flag *pflag.Flag) {
		input := evidenceFlagInput(cmd, flag)
		if input == "" || slices.ContainsFunc(existing, func(p ReceiptProbe) bool {
			return hasAccessInput(p.Args, flag.Name)
		}) {
			return
		}
		args := defaults
		if flag.Name == "location" {
			for _, probe := range existing {
				if probe.Directory && slices.Contains(probe.Args, "$dir") {
					args = slices.Clone(probe.Args)
					args[slices.Index(args, "$dir")] = "$tmp"
					probes = append(probes, ReceiptProbe{Args: replaceAccessFlag(args, flag.Name, input)})
					return
				}
			}
		}
		if len(existing) != 0 {
			args = existing[0].Args
		}
		probes = append(probes, ReceiptProbe{Args: replaceAccessFlag(args, flag.Name, input)})
	})
	return probes
}

func hasAccessInput(args []string, name string) bool {
	for i, arg := range args {
		if arg == "--"+name && i+1 < len(args) {
			return strings.Contains(args[i+1], "$dir") || strings.Contains(args[i+1], "$file")
		}
	}
	return false
}

func replaceAccessFlag(args []string, name, input string) []string {
	out := slices.Clone(args)
	for i, arg := range out {
		if arg == "--"+name && i+1 < len(out) {
			out[i+1] = input
			return out
		}
	}
	if i := slices.Index(out, "--"); i >= 0 {
		return slices.Insert(out, i, "--"+name, input)
	}
	return append(out, "--"+name, input)
}

func runAccessProbe(t *testing.T, suite AccessOracle, cmd *cobra.Command, name string, fixture oracleFixture, address string, args []string, existing bool) bool {
	t.Helper()
	side := t.TempDir()
	dir := filepath.Join(side, "evidence")
	if err := os.Mkdir(dir, 0o750); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(dir, filepath.Base(fixture.file))
	oracleWriteFile(t, file, oracleReadFile(t, fixture.file))
	configPath := filepath.Join(side, "pipelock.yaml")
	configYAML := fmt.Sprintf("fetch_proxy:\n  listen: %q\nflight_recorder:\n  enabled: true\n  dir: %q\n  signing_key_path: %q\nlearn:\n  capture_dir: %q\nlearn_lock:\n  store_dir: %q\n", address, dir, fixture.keyFile, dir, dir)
	if name == "logs" || name == "explain event" {
		configYAML += fmt.Sprintf("logging:\n  output: file\n  file: %q\n", file)
	}
	oracleWriteFile(t, configPath, []byte(configYAML))
	if _, err := config.LoadForRuntime(configPath); err != nil {
		t.Fatalf("load access oracle config: %v", err)
	}

	cmd.InheritedFlags()
	if cmd.Flags().Lookup("config") != nil && !slices.Contains(args, "--config") {
		args = replaceAccessFlag(args, "config", "$config")
	}
	replace := strings.NewReplacer("$dir", dir, "$file", file, "$pub", fixture.key,
		"$keyfile", fixture.keyFile, "$config", configPath, "$tmp", side)
	argv := strings.Fields(name)
	for _, arg := range args {
		argv = append(argv, replace.Replace(arg))
	}
	before, err := v3StreamNames(dir)
	if err != nil {
		t.Fatal(err)
	}
	watch := watchEvidence(t, dir, file)
	var out bytes.Buffer
	code := suite.Invoke(t, argv, &out, side, existing)
	got := watch.read(t)
	if got == (observedAccess{}) {
		if fixture.name == "damaged" {
			t.Errorf("%s did not reach damaged v3 history", name)
		}
		return false
	}
	t.Logf("access: directory=%t stream=%t exit=%d", got.dir, got.file, code)
	if slices.Contains(suite.Runtimes, name) {
		if fixture.name == "damaged" {
			if code == 0 || !got.file {
				t.Errorf("%s did not reject damaged v3 history after opening the stream (exit %d, opened %t)", name, code, got.file)
			}
			return true
		}
		// A runtime that appends opens the existing stream and starts its own.
		// Only a stream this invocation created excuses the missing verdict; a
		// second stream that was already present proves nothing.
		if code == 0 && got.file {
			created, err := createdV3Stream(dir, before)
			if err != nil {
				t.Fatal(err)
			}
			if created {
				return true
			}
		}
	}
	if code == 0 && !validObservedSuccess(name, got, out.String()) {
		t.Errorf("%s opened v3 evidence and exited successfully without a v3 verification verdict", name)
	}
	return true
}

// v3StreamNames lists the receipt-profile stream files in dir.
func v3StreamNames(dir string) (map[string]bool, error) {
	streams, err := filepath.Glob(filepath.Join(dir, "*.receipt-v3.jsonl"))
	if err != nil {
		return nil, err
	}
	names := make(map[string]bool, len(streams))
	for _, stream := range streams {
		names[filepath.Base(stream)] = true
	}
	return names, nil
}

// createdV3Stream reports whether dir now holds a stream absent from before.
func createdV3Stream(dir string, before map[string]bool) (bool, error) {
	after, err := v3StreamNames(dir)
	if err != nil {
		return false, err
	}
	for name := range after {
		if !before[name] {
			return true, nil
		}
	}
	return false, nil
}

func validObservedSuccess(name string, access observedAccess, output string) bool {
	// Init and doctor inspect the directory to recognize the profile and
	// explicitly delegate evidence health. Neither may read the stream.
	if !access.file && (name == "init" || name == "doctor") {
		return strings.Contains(output, "pipelock verify-receipt --chain")
	}
	// A verdict counts only when the verifier actually read the stream.
	if (name != "verify-receipt" && name != "chain" && name != "v3") || !access.file {
		return false
	}
	var result struct {
		Kind     string
		Verdict  string
		ExitCode *int `json:"exit_code"`
	}
	line, _, _ := strings.Cut(output, "\n")
	return json.Unmarshal([]byte(line), &result) == nil && result.Kind == "verify_result" &&
		result.Verdict == "VALID" && result.ExitCode != nil && *result.ExitCode == 0
}
