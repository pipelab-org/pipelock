// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

// Package serviceenv validates configuration with the supported configuration
// environment and static identity of the local system pipelock.service.
// It does not start that service or recreate its mount namespace.
package serviceenv

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/license"
)

const (
	// These are local observation policies shared with containment's typed
	// systemd readers (lifecycle_linux.go, verify.go), not systemd limits.
	maxObservationBytes = 64 << 10
	// D-Bus specification, Message Protocol: maximum complete message is
	// 2^27 bytes. Introspect XML is a string within that message; its header
	// exceeds the newline busctl adds. This is not a property-value limit.
	// https://dbus.freedesktop.org/doc/dbus-specification.html#message-protocol
	maxCatalogBytes = 1 << 27
	commandBudget   = 2 * time.Second
	// Unit is intentionally fixed; this is not an arbitrary-unit env reader.
	Unit             = "pipelock.service"
	unitObject       = "/org/freedesktop/systemd1/unit/pipelock_2eservice"
	serviceInterface = "org.freedesktop.systemd1.Service"
	unitInterface    = "org.freedesktop.systemd1.Unit"
	managerInterface = "org.freedesktop.systemd1.Manager"
)

// CheckOptions binds a selected validator to a candidate. AllowMissing is
// reserved for provisional first-install validation: a missing unit uses
// PlannedUser/PlannedEnvironment and still requires a reachable system manager.
// Installation must subsequently validate the loaded prospective unit with
// AllowMissing=false before starting or restarting it.
type CheckOptions struct {
	Binary                    string
	ConfigFile                string
	Service                   string
	RequireBuildCompatibility bool
	AllowMissing              bool
	PlannedUser               string
	PlannedEnvironment        []string
	ExpectedFragmentPath      string
	// ExpectedExecStart binds installer validation to the loaded managed command.
	// Unset for standalone checks, which may validate a different candidate.
	ExpectedExecStart []string
}

// ErrUnavailable identifies missing manager/identity privileges, not invalid config
// or unsupported service definitions. Dry-run callers may defer this check.
var ErrUnavailable = errors.New("service environment validation unavailable")

var (
	errObservationOverflow = errors.New("service observation exceeded its output bound")
	errObservationPolicy   = errors.New("service observation exceeded its resource policy")
	errValidatorStart      = errors.New("cannot start selected validator under the service identity; verify executable permissions and access to the configuration directory")
)

// Check runs the normal config validator in a subprocess. Neither caller
// environment nor child output is used as evidence or returned to the caller.
func Check(ctx context.Context, opts CheckOptions) error {
	return check(ctx, opts, defaultBackend())
}

type identity struct {
	UID    uint32
	GID    uint32
	Groups []uint32
	Home   string
}

type fileImage struct {
	Data  []byte
	Stamp string
}

type backend struct {
	command  func(context.Context, string, ...string) ([]byte, int, error)
	readFile func(string) (fileImage, error)
	// readCandidate reads the configuration under validation; nil uses readFile.
	readCandidate func(string) (fileImage, error)
	identity      func(string, string, []string) (identity, error)
	execute       func(context.Context, CheckOptions, []string, identity, []byte) error
}

type snapshot struct {
	Properties  map[string]string
	Environment []string
	Identity    identity
	Files       map[string]string
	Candidate   fileImage
}

func check(ctx context.Context, opts CheckOptions, b backend) error {
	if opts.Service != "pipelock" && opts.Service != Unit {
		return errors.New("service configuration validation only supports pipelock.service")
	}
	if opts.ConfigFile == "" || opts.ConfigFile == "-" || !filepath.IsAbs(opts.ConfigFile) || !filepath.IsAbs(opts.Binary) {
		return errors.New("service configuration validation requires absolute binary and config paths")
	}
	if ctx.Err() != nil {
		return errors.New("service configuration validation canceled")
	}
	before, err := observe(ctx, opts, b)
	if err != nil {
		return err
	}
	if err := b.execute(ctx, opts, before.Environment, before.Identity, before.Candidate.Data); err != nil {
		if ctx.Err() != nil {
			return errors.New("service configuration validation canceled")
		}
		// Never wrap arbitrary child/start errors: values may occur in output,
		// executable paths, loader diagnostics, or environment-derived paths.
		if errors.Is(err, ErrUnavailable) {
			return ErrUnavailable
		}
		if errors.Is(err, errValidatorStart) {
			return errValidatorStart
		}
		return errors.New("configuration validation failed for pipelock.service; validator output withheld; for config diagnostics, run the selected binary's check --config command against the original candidate in an environment you control; its output can contain configuration values; then rerun the privileged service check")
	}
	after, err := observe(ctx, opts, b)
	if err != nil {
		return err
	}
	if !reflect.DeepEqual(before, after) {
		return errors.New("service configuration inputs changed during validation; retry")
	}
	return nil
}

func observe(ctx context.Context, opts CheckOptions, b backend) (snapshot, error) {
	s := snapshot{Properties: make(map[string]string), Files: make(map[string]string)}
	out, code, err := b.command(ctx, "/usr/bin/systemctl", "--system", "--no-ask-password", "--no-pager", "show", "--all", "--property=Id,LoadState,NeedDaemonReload,Transient", Unit)
	if ctx.Err() != nil {
		return s, errors.New("service configuration validation canceled")
	}
	if errors.Is(err, errObservationOverflow) {
		return s, errObservationOverflow
	}
	if errors.Is(err, errObservationPolicy) {
		return s, errObservationPolicy
	}
	if err != nil || code != 0 && len(out) == 0 {
		return s, fmt.Errorf("cannot inspect local pipelock.service: %w", ErrUnavailable)
	}
	if len(out) > maxObservationBytes {
		return s, errors.New("service identity observation exceeds bound")
	}
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		key, value, ok := strings.Cut(line, "=")
		if !ok || !slices.Contains([]string{"Id", "LoadState", "NeedDaemonReload", "Transient"}, key) {
			return s, errors.New("invalid service identity observation")
		}
		if _, exists := s.Properties[key]; exists {
			return s, errors.New("duplicate service identity property")
		}
		s.Properties[key] = value
	}
	if s.Properties["Id"] != Unit || len(s.Properties) != 4 {
		return s, errors.New("missing or mismatched pipelock.service identity")
	}
	missing := s.Properties["LoadState"] == "not-found"
	if (!missing && (code != 0 || s.Properties["LoadState"] != "loaded")) || missing && !opts.AllowMissing {
		return s, errors.New("pipelock.service is not loaded")
	}
	if s.Properties["NeedDaemonReload"] != "no" || s.Properties["Transient"] != "no" {
		return s, errors.New("pipelock.service is transient or has stale definitions; reload definitions and retry")
	}
	manager, err := readProperty(ctx, b, "/org/freedesktop/systemd1", managerInterface, "Environment")
	if err != nil {
		return s, err
	}
	base, err := decodeStringList(manager)
	if err != nil {
		return s, err
	}
	values := make(map[string]string)
	if err := applyAssignments(values, base); err != nil {
		return s, err
	}
	s.Properties["manager"] = string(manager)
	if missing {
		if opts.PlannedUser == "" {
			return s, errors.New("first-install configuration validation requires the planned service identity")
		}
		s.Identity, err = b.identity(opts.PlannedUser, "", nil)
		if err != nil {
			if errors.Is(err, ErrUnavailable) {
				return s, ErrUnavailable
			}
			return s, errors.New("cannot resolve planned service identity")
		}
		// Match observeLoaded's USER_CREDS_CLEAN home omission rule.
		if s.Identity.Home != "/" {
			values["HOME"] = s.Identity.Home
		}
		if err := applyAssignments(values, opts.PlannedEnvironment); err != nil {
			return s, err
		}
	} else if err := observeLoaded(ctx, opts, b, &s, values); err != nil {
		return s, err
	}
	if opts.ExpectedFragmentPath != "" {
		var fragment string
		if missing || decodeProperty([]byte(s.Properties["FragmentPath"]), "s", &fragment) != nil || fragment != opts.ExpectedFragmentPath {
			return s, errors.New("loaded pipelock.service does not match the prospective unit path")
		}
	}
	s.Environment = configurationEnvironment(values)
	readCandidate := b.readCandidate
	if readCandidate == nil {
		readCandidate = b.readFile
	}
	s.Candidate, err = readCandidate(opts.ConfigFile)
	if err != nil {
		return s, errors.New("cannot read stable regular candidate configuration")
	}
	return s, nil
}

func readProperty(ctx context.Context, b backend, object, iface, property string) ([]byte, error) {
	out, code, err := b.command(ctx, "/usr/bin/busctl", "--system", "--json=short", "--allow-interactive-authorization=no", "--auto-start=no", "get-property", "org.freedesktop.systemd1", object, iface, property)
	if ctx.Err() != nil {
		return nil, errors.New("service configuration validation canceled")
	}
	if errors.Is(err, errObservationOverflow) {
		return nil, errObservationOverflow
	}
	if errors.Is(err, errObservationPolicy) {
		return nil, errObservationPolicy
	}
	if err != nil || code != 0 {
		return nil, fmt.Errorf("cannot read typed service property %s: %w", property, ErrUnavailable)
	}
	if len(out) > maxObservationBytes {
		return nil, errors.New("typed service property exceeds bound")
	}
	return out, nil
}

func observeLoaded(ctx context.Context, opts CheckOptions, b backend, s *snapshot, values map[string]string) error {
	catalog, err := serviceCatalog(ctx, b)
	if err != nil {
		return err
	}
	version, versionRaw, err := managerVersion(ctx, b)
	if err != nil {
		return err
	}
	s.Properties["Version"] = string(versionRaw)
	// Signatures come from org.freedesktop.systemd1(5). Refuse dynamic
	// sources rather than guessing future credentials/PAM/pre-start results.
	properties := []struct{ name, signature string }{
		{"Environment", "as"},
		{"EnvironmentFiles", "a(sb)"},
		{"UnsetEnvironment", "as"},
		{"User", "s"},
		{"Group", "s"},
		{"SupplementaryGroups", "as"},
		{"SetLoginEnvironment", "b"},
		{"PassEnvironment", "as"},
		{"PAMName", "s"},
		{"DynamicUser", "b"},
		{"RootDirectory", "s"},
		{"RootImage", "s"},
		{"WorkingDirectory", "s"},
		{"LoadCredential", "a(ss)"},
		{"LoadCredentialEncrypted", "a(ss)"},
		{"SetCredential", "a(say)"},
		{"SetCredentialEncrypted", "a(say)"},
		{"ImportCredential", "as"},
		{"ExecStartPre", "a(sasbttttuii)"},
		{"ExecCondition", "a(sasbttttuii)"},
	}
	for _, property := range properties {
		signature, exists := catalog[property.name]
		if !exists {
			introduced := propertyIntroduction(property.name)
			if introduced == 0 || version >= introduced {
				return errors.New("required service property is absent from introspection")
			}
			// A successfully introspected older manager cannot implement this
			// upstream directive. A present backport is read normally below.
			s.Properties[property.name] = "unavailable-before-introduction"
			continue
		}
		if signature != property.signature {
			return errors.New("unexpected introspected service property signature")
		}
		raw, err := readProperty(ctx, b, unitObject, serviceInterface, property.name)
		if err != nil {
			return err
		}
		var value json.RawMessage
		if err := decodeProperty(raw, property.signature, &value); err != nil {
			return err
		}
		s.Properties[property.name] = string(raw)
		switch property.name {
		case "Environment", "EnvironmentFiles", "UnsetEnvironment", "User", "Group", "SupplementaryGroups", "SetLoginEnvironment":
			continue
		case "DynamicUser":
			if string(value) == "false" {
				continue
			}
		case "PAMName", "RootDirectory", "RootImage", "WorkingDirectory":
			if string(value) == `""` || property.name == "WorkingDirectory" && string(value) == `"/"` {
				continue
			}
		default:
			if string(value) == "[]" {
				continue
			}
		}
		return fmt.Errorf("service configuration validation does not support %s", property.name)
	}
	if len(opts.ExpectedExecStart) > 0 {
		if err := observeInvocation(ctx, opts, b, s, catalog); err != nil {
			return err
		}
	}
	var unitUser, unitGroup string
	if decodeProperty([]byte(s.Properties["User"]), "s", &unitUser) != nil || decodeProperty([]byte(s.Properties["Group"]), "s", &unitGroup) != nil {
		return errors.New("invalid static service identity")
	}
	groups, err := decodeStringList([]byte(s.Properties["SupplementaryGroups"]))
	if err != nil {
		return err
	}
	s.Identity, err = b.identity(unitUser, unitGroup, groups)
	if err != nil {
		if errors.Is(err, ErrUnavailable) {
			return ErrUnavailable
		}
		return errors.New("cannot resolve static service identity")
	}
	// Before SetLoginEnvironment (255), systemd sets HOME only for explicit
	// User=. USER_CREDS_CLEAN omits the unenlightening '/' home (v252 execute.c).
	login := unitUser != ""
	if s.Properties["SetLoginEnvironment"] != "unavailable-before-introduction" {
		if decodeProperty([]byte(s.Properties["SetLoginEnvironment"]), "b", &login) != nil {
			return errors.New("invalid service login environment setting")
		}
		// v255 exposes its unresolved tristate as a boolean; v256's getter
		// resolves the User= default. Without User=, true is ambiguous in255.
		if version == 255 && unitUser == "" && login {
			return errors.New("ambiguous systemd 255 login environment without an explicit service user")
		}
	}
	if login && s.Identity.Home != "/" {
		values["HOME"] = s.Identity.Home
	}
	assignments, err := decodeStringList([]byte(s.Properties["Environment"]))
	if err != nil {
		return err
	}
	if err := applyAssignments(values, assignments); err != nil {
		return err
	}
	files, err := decodeEnvironmentFiles([]byte(s.Properties["EnvironmentFiles"]))
	if err != nil {
		return err
	}
	for _, file := range files {
		if !filepath.IsAbs(file.Path) || filepath.Clean(file.Path) != file.Path || strings.ContainsAny(file.Path, "*?[\\\x00\r\n") {
			return errors.New("service environment files require literal clean absolute paths")
		}
		image, err := b.readFile(file.Path)
		if err != nil {
			if file.Optional && (errors.Is(err, errMissingFile) || errors.Is(err, errUnreadableFile) || errors.Is(err, os.ErrPermission)) {
				s.Files[file.Path] = "unavailable"
				continue
			}
			return errors.New("cannot read stable regular service environment file")
		}
		s.Files[file.Path] = image.Stamp
		assignments, err := parseEnvironmentFile(image.Data, version)
		if err != nil {
			return err
		}
		if err := applyAssignments(values, assignments); err != nil {
			return err
		}
	}
	unsets, err := decodeStringList([]byte(s.Properties["UnsetEnvironment"]))
	if err != nil {
		return err
	}
	for _, unset := range unsets {
		name, value, assignment := strings.Cut(unset, "=")
		if !validName(name) || strings.ContainsRune(value, 0) {
			return errors.New("invalid service unset assignment")
		}
		if actual, exists := values[name]; exists && (!assignment || actual == value) {
			delete(values, name)
		}
	}
	for _, property := range []string{"FragmentPath", "DropInPaths"} {
		raw, err := readProperty(ctx, b, unitObject, unitInterface, property)
		if err != nil {
			return err
		}
		var decodeErr error
		if property == "DropInPaths" {
			_, decodeErr = decodeStringList(raw)
		} else {
			var path string
			decodeErr = decodeProperty(raw, "s", &path)
		}
		if decodeErr != nil {
			return errors.New("invalid service definition observation")
		}
		s.Properties[property] = string(raw)
	}
	return nil
}

var (
	errMissingFile    = errors.New("file is missing")
	errUnreadableFile = errors.New("file cannot be read")
)

func applyAssignments(values map[string]string, assignments []string) error {
	for _, assignment := range assignments {
		name, value, ok := strings.Cut(assignment, "=")
		if !ok || !validName(name) || strings.ContainsRune(value, 0) {
			return errors.New("invalid service environment assignment")
		}
		values[name] = value
	}
	return nil
}

func configurationEnvironment(values map[string]string) []string {
	// This list is the actual config.Load/config.Validate/license verification
	// input contract. HOME and PIPELOCK_HOME supply signing/CA default paths.
	// Do not pass arbitrary service variables (e.g. LD_PRELOAD) into a checker.
	keys := []string{
		config.EnvKillSwitchAPIToken, config.EnvLicenseKey, config.EnvLicenseCRLFile,
		config.EnvLicensePublicKey, config.EnvLicenseRequireIntermediate, config.EnvLicenseCRLMaxAge,
		license.EnvLicenseIntermediateFile, "HOME", "PIPELOCK_HOME",
	}
	out := make([]string, 0, len(keys))
	for _, key := range keys {
		if value, exists := values[key]; exists {
			out = append(out, key+"="+value)
		}
	}
	slices.Sort(out)
	return out
}

func contentStamp(body []byte, metadata string) string {
	return fmt.Sprintf("%s:%x", metadata, sha256.Sum256(body))
}
