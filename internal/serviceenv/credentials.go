// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package serviceenv

import (
	"errors"
	"path/filepath"
	"strings"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"gopkg.in/yaml.v3"
)

type credentialSource struct{ Property, Name, Path string }

func candidateCredential(data []byte) (string, error) {
	var node yaml.Node
	if yaml.Unmarshal(data, &node) != nil {
		return "", errors.New("cannot inspect native credential reference in candidate")
	}
	if len(node.Content) == 0 || node.Content[0].Kind != yaml.MappingNode {
		return "", nil
	}
	var cfg struct {
		KillSwitch config.KillSwitch `yaml:"kill_switch"`
	}
	if yaml.Unmarshal(data, &cfg) != nil {
		return "", errors.New("cannot inspect native credential reference in candidate")
	}
	return config.KillSwitchCredentialName(cfg.KillSwitch.APITokenFile)
}

func requireCredential(data []byte, credential *credentialSource) error {
	name, err := candidateCredential(data)
	if err != nil {
		return err
	}
	if name != "" && (credential == nil || credential.Name != name) {
		return errors.New("native kill-switch credential requires exactly one matching LoadCredential or LoadCredentialEncrypted with an absolute regular source file")
	}
	return nil
}

func observeCredential(property string, raw []byte, b backend, s *snapshot) error {
	var rows [][]string
	if decodeProperty(raw, "a(ss)", &rows) != nil || len(rows) != 1 || len(rows[0]) != 2 || s.Credential != nil {
		return errors.New("only one native kill-switch file credential is supported")
	}
	name, err := candidateCredential(s.Candidate.Data)
	if err != nil {
		return err
	}
	source := rows[0][1]
	if name == "" || name != rows[0][0] || !staticCredentialPath(source) {
		return errors.New("service credential must match kill_switch.api_token_file and use an absolute regular source; see docs/guides/service-credentials.md")
	}
	// Snapshot the opaque source, not the running unit's decrypted credential.
	// Re-observation rejects rotation during validation. PID 1 materializes a
	// new credential for the validation invocation (systemd.exec Credentials).
	image, err := b.readFile(source)
	if err != nil {
		return errors.New("cannot observe stable regular credential source")
	}
	s.Files[source] = image.Stamp
	s.Credential = &credentialSource{Property: property, Name: name, Path: source}
	return nil
}

func staticCredentialPath(path string) bool {
	return filepath.IsAbs(path) && filepath.Clean(path) == path && !strings.ContainsAny(path, "\\:*?[%\x00\r\n\t \"")
}
