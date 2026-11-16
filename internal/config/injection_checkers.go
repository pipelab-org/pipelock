// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"crypto/x509"
	"fmt"
	"math"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// Injection checker types.
const (
	// InjectionCheckerTypeProtocol is a service speaking pipelock.checker/v1.
	InjectionCheckerTypeProtocol = "protocol"
	// InjectionCheckerTypeJev is the TypeSafe Jev decision API adapter.
	InjectionCheckerTypeJev = "jev"
)

// JevDefaultEndpoint is the Jev endpoint used when none is configured.
const JevDefaultEndpoint = "https://api.typesafe.ai/v1/systemone"

// Bounds on operator-supplied checker budgets. The request bound matches the
// largest body the Jev API documents accepting; the response bound and
// timeout are generous ceilings for a single-item classification reply.
const (
	maxCheckerTimeoutMS        = 60000
	maxCheckerRequestBytes     = 32 << 20
	maxCheckerResponseBytes    = 1 << 20
	maxCheckerCAFileBytes      = 1 << 20
	injectionCheckerNamePrefix = "prompt_injection_detection.checkers."
)

var (
	injectionCheckerNameRE = regexp.MustCompile(`^[a-z][a-z0-9_-]{0,63}$`)
	envVarNameRE           = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)
)

// InjectionCheckerRevision pins the identity a protocol checker must report.
type InjectionCheckerRevision struct {
	Checker string `yaml:"checker" json:"checker"`
	Model   string `yaml:"model" json:"model"`
	Adapter string `yaml:"adapter" json:"adapter"`
}

// InjectionCheckerScore pins the score scale a protocol checker may report.
type InjectionCheckerScore struct {
	Scale         string   `yaml:"scale" json:"scale"`
	CalibrationID string   `yaml:"calibration_id" json:"calibration_id"`
	Min           *float64 `yaml:"min" json:"min"`
	Max           *float64 `yaml:"max" json:"max"`
}

// InjectionCheckerConfig defines one named external checker. Credentials are
// named by environment variable; their values never appear in configuration.
type InjectionCheckerConfig struct {
	Type               string                    `yaml:"type" json:"type"`
	Endpoint           string                    `yaml:"endpoint,omitempty" json:"endpoint,omitempty"`
	UnixSocket         string                    `yaml:"unix_socket,omitempty" json:"unix_socket,omitempty"`
	PeerUID            *uint32                   `yaml:"peer_uid,omitempty" json:"peer_uid,omitempty"`
	AllowLoopbackHTTP  *bool                     `yaml:"allow_loopback_http,omitempty" json:"allow_loopback_http,omitempty"`
	CAFile             string                    `yaml:"ca_file,omitempty" json:"ca_file,omitempty"`
	AuthorizationEnv   string                    `yaml:"authorization_env,omitempty" json:"authorization_env,omitempty"`
	APIKeyEnv          string                    `yaml:"api_key_env,omitempty" json:"api_key_env,omitempty"`
	Revision           *InjectionCheckerRevision `yaml:"revision,omitempty" json:"revision,omitempty"`
	Score              *InjectionCheckerScore    `yaml:"score,omitempty" json:"score,omitempty"`
	Model              string                    `yaml:"model,omitempty" json:"model,omitempty"`
	Threshold          *float64                  `yaml:"threshold,omitempty" json:"threshold,omitempty"`
	TimeoutMS          int                       `yaml:"timeout_ms" json:"timeout_ms"`
	MaxRequestBytes    int64                     `yaml:"max_request_bytes" json:"max_request_bytes"`
	MaxResponseBytes   int64                     `yaml:"max_response_bytes" json:"max_response_bytes"`
	SendContentOffHost *bool                     `yaml:"send_content_off_host,omitempty" json:"send_content_off_host,omitempty"`
}

// EffectiveEndpoint returns the configured endpoint or the type default.
func (c InjectionCheckerConfig) EffectiveEndpoint() string {
	if c.Endpoint == "" && c.Type == InjectionCheckerTypeJev {
		return JevDefaultEndpoint
	}
	return c.Endpoint
}

// SendsOffHost reports whether content can leave the machine: the endpoint
// is neither a Unix socket nor a numeric loopback address.
func (c InjectionCheckerConfig) SendsOffHost() bool {
	if c.UnixSocket != "" {
		return false
	}
	u, err := url.Parse(c.EffectiveEndpoint())
	if err != nil {
		return true
	}
	ip := net.ParseIP(u.Hostname())
	return ip == nil || !ip.IsLoopback()
}

// EndpointHost is the endpoint's host for diagnostics, never its path,
// query or credentials.
func (c InjectionCheckerConfig) EndpointHost() string {
	if c.UnixSocket != "" {
		return "unix:" + c.UnixSocket
	}
	u, err := url.Parse(c.EffectiveEndpoint())
	if err != nil {
		return "invalid"
	}
	return u.Host
}

// CredentialEnv names the environment variable holding this checker's
// credential, or empty.
func (c InjectionCheckerConfig) CredentialEnv() string {
	if c.Type == InjectionCheckerTypeJev {
		return c.APIKeyEnv
	}
	return c.AuthorizationEnv
}

func (c InjectionCheckerConfig) clone() InjectionCheckerConfig {
	out := c
	if c.PeerUID != nil {
		v := *c.PeerUID
		out.PeerUID = &v
	}
	if c.AllowLoopbackHTTP != nil {
		v := *c.AllowLoopbackHTTP
		out.AllowLoopbackHTTP = &v
	}
	if c.Revision != nil {
		v := *c.Revision
		out.Revision = &v
	}
	if c.Score != nil {
		v := *c.Score
		if c.Score.Min != nil {
			m := *c.Score.Min
			v.Min = &m
		}
		if c.Score.Max != nil {
			m := *c.Score.Max
			v.Max = &m
		}
		out.Score = &v
	}
	if c.Threshold != nil {
		v := *c.Threshold
		out.Threshold = &v
	}
	if c.SendContentOffHost != nil {
		v := *c.SendContentOffHost
		out.SendContentOffHost = &v
	}
	return out
}

func cloneInjectionCheckers(in map[string]InjectionCheckerConfig) map[string]InjectionCheckerConfig {
	if in == nil {
		return nil
	}
	out := make(map[string]InjectionCheckerConfig, len(in))
	for k, v := range in {
		out[k] = v.clone()
	}
	return out
}

// canonicalString renders every behavior-relevant field in a fixed order.
// Credential values are never read; only the variable names are bound.
func (c InjectionCheckerConfig) canonicalString() string {
	var b strings.Builder
	field := func(name, value string) { fmt.Fprintf(&b, "%s=%q;", name, value) }
	field("type", c.Type)
	field("endpoint", c.EffectiveEndpoint())
	field("unix_socket", c.UnixSocket)
	if c.PeerUID != nil {
		field("peer_uid", fmt.Sprint(*c.PeerUID))
	}
	field("allow_loopback_http", fmt.Sprint(c.AllowLoopbackHTTP != nil && *c.AllowLoopbackHTTP))
	field("ca_file", c.CAFile)
	field("authorization_env", c.AuthorizationEnv)
	field("api_key_env", c.APIKeyEnv)
	if c.Revision != nil {
		field("revision", c.Revision.Checker+"\x00"+c.Revision.Model+"\x00"+c.Revision.Adapter)
	}
	if c.Score != nil && c.Score.Min != nil && c.Score.Max != nil {
		field("score", fmt.Sprintf("%s\x00%s\x00%v\x00%v", c.Score.Scale, c.Score.CalibrationID, *c.Score.Min, *c.Score.Max))
	}
	field("model", c.Model)
	if c.Threshold != nil {
		field("threshold", fmt.Sprint(*c.Threshold))
	}
	field("timeout_ms", fmt.Sprint(c.TimeoutMS))
	field("max_request_bytes", fmt.Sprint(c.MaxRequestBytes))
	field("max_response_bytes", fmt.Sprint(c.MaxResponseBytes))
	field("send_content_off_host", fmt.Sprint(c.SendContentOffHost != nil && *c.SendContentOffHost))
	return b.String()
}

func sortedCheckerNames(m map[string]InjectionCheckerConfig) []string {
	names := make([]string, 0, len(m))
	for name := range m {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// validateInjectionCheckers rejects invalid checker definitions with a
// message naming the checker and field.
func (c *Config) validateInjectionCheckers() error {
	if c.PromptInjectionDetection == nil {
		return nil
	}
	checkers := c.PromptInjectionDetection.Checkers
	for _, name := range sortedCheckerNames(checkers) {
		if err := validateInjectionChecker(name, checkers[name]); err != nil {
			return err
		}
	}
	return nil
}

func validateInjectionChecker(name string, cc InjectionCheckerConfig) error {
	field := injectionCheckerNamePrefix + name
	if name == InjectionCheckerBasic || !injectionCheckerNameRE.MatchString(name) {
		return fmt.Errorf("%s: checker names use lowercase letters, digits, '_' and '-', start with a letter, and cannot be %q", field, InjectionCheckerBasic)
	}
	if cc.TimeoutMS < 1 || cc.TimeoutMS > maxCheckerTimeoutMS {
		return fmt.Errorf("%s.timeout_ms: must be between 1 and %d", field, maxCheckerTimeoutMS)
	}
	if cc.MaxRequestBytes < 1 || cc.MaxRequestBytes > maxCheckerRequestBytes {
		return fmt.Errorf("%s.max_request_bytes: must be between 1 and %d", field, maxCheckerRequestBytes)
	}
	if cc.MaxResponseBytes < 1 || cc.MaxResponseBytes > maxCheckerResponseBytes {
		return fmt.Errorf("%s.max_response_bytes: must be between 1 and %d", field, maxCheckerResponseBytes)
	}
	switch cc.Type {
	case InjectionCheckerTypeProtocol:
		if err := validateProtocolChecker(field, cc); err != nil {
			return err
		}
	case InjectionCheckerTypeJev:
		if err := validateJevChecker(field, cc); err != nil {
			return err
		}
	default:
		return fmt.Errorf("%s.type %q: must be %s or %s", field, cc.Type, InjectionCheckerTypeProtocol, InjectionCheckerTypeJev)
	}
	if cc.SendsOffHost() && (cc.SendContentOffHost == nil || !*cc.SendContentOffHost) {
		return fmt.Errorf("%s.send_content_off_host: the endpoint %s is not on this machine, so checked content leaves it; set send_content_off_host: true to consent, or use a Unix socket or loopback endpoint", field, cc.EndpointHost())
	}
	return nil
}

func validateCheckerURL(field, raw string) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Hostname() == "" || (u.Scheme != "http" && u.Scheme != "https") {
		return nil, fmt.Errorf("%s.endpoint: must be an absolute http or https URL", field)
	}
	if u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.Opaque != "" {
		return nil, fmt.Errorf("%s.endpoint: must not contain credentials, a query or a fragment", field)
	}
	return u, nil
}

func validateProtocolChecker(field string, cc InjectionCheckerConfig) error {
	if cc.APIKeyEnv != "" || cc.Model != "" || cc.Threshold != nil {
		return fmt.Errorf("%s: api_key_env, model and threshold apply only to type jev", field)
	}
	if cc.Endpoint == "" {
		return fmt.Errorf("%s.endpoint: required", field)
	}
	u, err := validateCheckerURL(field, cc.Endpoint)
	if err != nil {
		return err
	}
	if cc.UnixSocket != "" {
		if !filepath.IsAbs(cc.UnixSocket) {
			return fmt.Errorf("%s.unix_socket: must be an absolute path", field)
		}
		if u.Scheme != "http" || u.Host != "localhost" {
			return fmt.Errorf("%s.endpoint: with unix_socket the endpoint must be http://localhost/<path>", field)
		}
	} else {
		if cc.PeerUID != nil {
			return fmt.Errorf("%s.peer_uid: requires unix_socket", field)
		}
		if u.Scheme == "http" {
			ip := net.ParseIP(u.Hostname())
			if cc.AllowLoopbackHTTP == nil || !*cc.AllowLoopbackHTTP || ip == nil || !ip.IsLoopback() {
				return fmt.Errorf("%s.endpoint: plain http requires a numeric loopback address and allow_loopback_http: true; use https otherwise", field)
			}
		}
	}
	if cc.CAFile != "" {
		if u.Scheme != "https" {
			return fmt.Errorf("%s.ca_file: applies only to https endpoints", field)
		}
		if _, err := LoadCheckerCAPool(cc.CAFile); err != nil {
			return fmt.Errorf("%s.ca_file: %w", field, err)
		}
	}
	if cc.AuthorizationEnv != "" && !envVarNameRE.MatchString(cc.AuthorizationEnv) {
		return fmt.Errorf("%s.authorization_env: must be an environment variable name", field)
	}
	if cc.Revision == nil || cc.Revision.Checker == "" || cc.Revision.Model == "" || cc.Revision.Adapter == "" {
		return fmt.Errorf("%s.revision: checker, model and adapter are all required; every response is checked against them", field)
	}
	if s := cc.Score; s != nil {
		if s.Scale == "" || s.CalibrationID == "" || s.Min == nil || s.Max == nil ||
			math.IsNaN(*s.Min) || math.IsInf(*s.Min, 0) || math.IsNaN(*s.Max) || math.IsInf(*s.Max, 0) || *s.Min >= *s.Max {
			return fmt.Errorf("%s.score: scale, calibration_id, min and max are required, finite, with min below max", field)
		}
	}
	return nil
}

func validateJevChecker(field string, cc InjectionCheckerConfig) error {
	if cc.Revision != nil || cc.UnixSocket != "" || cc.PeerUID != nil || cc.AllowLoopbackHTTP != nil ||
		cc.CAFile != "" || cc.AuthorizationEnv != "" || cc.Score != nil {
		return fmt.Errorf("%s: revision, unix_socket, peer_uid, allow_loopback_http, ca_file, authorization_env and score do not apply to type jev", field)
	}
	if cc.Endpoint != "" {
		u, err := validateCheckerURL(field, cc.Endpoint)
		if err != nil {
			return err
		}
		if u.Scheme != "https" {
			return fmt.Errorf("%s.endpoint: must be https", field)
		}
	}
	switch cc.Model {
	case "":
		return fmt.Errorf("%s.model: required; pin an exact model version such as jev-1.14.0", field)
	case "jev-latest", "jev-preview":
		return fmt.Errorf("%s.model %q: moving aliases are not accepted; pin an exact model version such as jev-1.14.0", field, cc.Model)
	}
	if cc.APIKeyEnv == "" || !envVarNameRE.MatchString(cc.APIKeyEnv) {
		return fmt.Errorf("%s.api_key_env: required environment variable name", field)
	}
	if cc.Threshold == nil || math.IsNaN(*cc.Threshold) || *cc.Threshold <= 0 || *cc.Threshold > 1 {
		return fmt.Errorf("%s.threshold: required, greater than 0 and at most 1", field)
	}
	if cc.SendContentOffHost == nil || !*cc.SendContentOffHost {
		return fmt.Errorf("%s.send_content_off_host: Jev is a hosted service, so checked content leaves this machine; set send_content_off_host: true to consent", field)
	}
	return nil
}

// LoadCheckerCAPool reads a PEM bundle of root certificates for a checker.
func LoadCheckerCAPool(path string) (*x509.CertPool, error) {
	info, err := os.Stat(filepath.Clean(path))
	if err != nil {
		return nil, fmt.Errorf("cannot read CA file: %w", err)
	}
	if !info.Mode().IsRegular() || info.Size() > maxCheckerCAFileBytes {
		return nil, fmt.Errorf("CA file must be a regular file of at most %d bytes", maxCheckerCAFileBytes)
	}
	data, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		return nil, fmt.Errorf("cannot read CA file: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(data) {
		return nil, fmt.Errorf("CA file contains no PEM certificates")
	}
	return pool, nil
}

// injectionCheckerWarnings reports unset credential variables and checker
// definitions no surface uses. Neither blocks loading: a checker without its
// credential reports every item unassessed at runtime.
func (c *Config) injectionCheckerWarnings() []Warning {
	if c == nil || c.PromptInjectionDetection == nil {
		return nil
	}
	used := map[string]bool{}
	for _, sc := range c.PromptInjectionDetection.Surfaces {
		used[sc.Checker] = true
		used[sc.Watch] = true
	}
	var out []Warning
	for _, name := range sortedCheckerNames(c.PromptInjectionDetection.Checkers) {
		cc := c.PromptInjectionDetection.Checkers[name]
		field := injectionCheckerNamePrefix + name
		if env := cc.CredentialEnv(); env != "" {
			if _, ok := os.LookupEnv(env); !ok {
				out = append(out, Warning{Field: field, Message: fmt.Sprintf("environment variable %s is not set; this checker reports every item unassessed until it is", env)})
			}
		}
		if !used[name] {
			out = append(out, Warning{Field: field, Message: "checker is defined but no surface selects or watches it"})
		}
	}
	return out
}
