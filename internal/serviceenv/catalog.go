// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package serviceenv

import (
	"context"
	"errors"
	"strconv"
	"strings"
)

// busctl(1) introspect documents NAME TYPE SIGNATURE RESULT/VALUE FLAGS.
// Upstream v249 src/busctl/busctl.c:introspect prints the first three columns
// without abbreviation. JSON mode does not change this command's table.
// Only availability/signatures come from this table; values always use the
// strict typed get-property path. Introspection cannot silently turn a denied
// property getter into an absent property.
func serviceCatalog(ctx context.Context, b backend) (map[string]string, error) {
	out, code, err := b.command(ctx, "/usr/bin/busctl", "--system", "--no-pager", "--no-legend", "--allow-interactive-authorization=no", "--auto-start=no", "introspect", "org.freedesktop.systemd1", unitObject, serviceInterface)
	if err != nil || code != 0 || len(out) == 0 || len(out) > maxObservationBytes {
		return nil, errors.New("cannot inspect service property availability")
	}
	properties := make(map[string]string)
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 5 || !strings.HasPrefix(fields[0], ".") {
			return nil, errors.New("invalid service property catalog")
		}
		switch fields[1] {
		case "method", "signal":
			continue
		case "property":
		default:
			return nil, errors.New("invalid service catalog member")
		}
		name := strings.TrimPrefix(fields[0], ".")
		if !validName(name) {
			return nil, errors.New("invalid service catalog property")
		}
		if _, duplicate := properties[name]; duplicate {
			return nil, errors.New("duplicate service catalog property")
		}
		properties[name] = fields[2]
	}
	return properties, nil
}

func managerVersion(ctx context.Context, b backend) (int, []byte, error) {
	raw, err := readProperty(ctx, b, "/org/freedesktop/systemd1", managerInterface, "Version")
	if err != nil {
		return 0, nil, err
	}
	var value string
	if decodeProperty(raw, "s", &value) != nil {
		return 0, nil, errors.New("invalid system manager version")
	}
	// Join containment's detectSystemdVersion contract: the leading decimal
	// major of PID 1's version, never the installed helper's --version.
	end := 0
	for end < len(value) && value[end] >= '0' && value[end] <= '9' {
		end++
	}
	version, err := strconv.Atoi(value[:end])
	if err != nil || version <= 0 {
		return 0, nil, errors.New("unresolved system manager version")
	}
	return version, raw, nil
}

// Published introductions: systemd.exec(5) v255 SetLoginEnvironment (255),
// ImportCredential (254); upstream dbus-execute.c v249/v250 distinguishes
// encrypted credentials. Missing baseline properties are never synthesized.
func propertyIntroduction(name string) int {
	switch name {
	case "SetLoginEnvironment":
		return 255
	case "ImportCredential":
		return 254
	case "LoadCredentialEncrypted", "SetCredentialEncrypted":
		return 250
	default:
		return 0
	}
}
