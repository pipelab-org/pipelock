// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package session

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"reflect"
	"strings"

	"github.com/spf13/cobra"

	"github.com/luckyPipewrench/pipelock/internal/proxy"
	"github.com/luckyPipewrench/pipelock/internal/termsafe"
)

// ReloadCmd returns the synchronous daemon reload command. It reuses the
// session admin resolver and transport, including explicit/env recovery access
// when the on-disk candidate is malformed.
func ReloadCmd() *cobra.Command {
	flags := &rootFlags{}
	var status, jsonOutput bool
	cmd := &cobra.Command{
		Use: "reload", Short: "Reload the running daemon and report its actual activation verdict",
		Long: "Reload the daemon's configured file through its authenticated admin API. Requires an API token. --config only resolves connection credentials; it cannot choose the daemon's reload source. Use --status to inspect live identity and pending restart fields without reloading.",
		Args: cobra.NoArgs, SilenceUsage: true,
	}
	bindPersistentFlags(cmd, flags)
	cmd.Flags().BoolVar(&status, "status", false, "query live daemon reload status without reloading")
	cmd.Flags().BoolVar(&jsonOutput, flagJSON, false, usageJSON)
	cmd.RunE = func(cmd *cobra.Command, _ []string) error {
		return runClientCmd(flags, cmd.Context(), cmd.OutOrStdout(), func(ctx context.Context, client *Client, out io.Writer) error {
			result, err := client.ConfigReload(ctx, status)
			if err != nil {
				return err
			}
			if jsonOutput {
				if err := writeJSON(out, result); err != nil {
					return err
				}
			} else {
				if _, err := fmt.Fprintf(out, "config %s: instance=%s generation=%d\nsource candidate=%s last-accepted=%s\ncanonical policy=%s\npending restart=%t fields=%s\nreload available=%t watcher=%s\n",
					result.Verdict, termsafe.Escape(result.InstanceID), result.Generation,
					result.CandidateSourceHash, result.AcceptedSourceHash, result.CanonicalPolicyHash,
					result.PendingRestart, termsafe.Escape(strings.Join(result.RestartRequiredFields, ", ")),
					result.ReloadAvailable, termsafe.Escape(result.WatcherState)); err != nil {
					return err
				}
				if result.Reason != "" {
					if _, err := fmt.Fprintln(out, termsafe.Escape(result.Reason)); err != nil {
						return err
					}
				}
			}
			if result.PendingRestart || (result.Verdict != proxy.ReloadAccepted && result.Verdict != proxy.ReloadUnchanged) {
				return fmt.Errorf("daemon config %s: %s", result.Verdict, termsafe.Escape(result.Reason))
			}
			return nil
		})
	}
	return cmd
}

// ConfigReload receives this request's completed transaction, or a serialized
// status snapshot. It never substitutes offline validation or polls latest.
func (c *Client) ConfigReload(ctx context.Context, status bool) (proxy.ReloadOutcome, error) {
	method, path := http.MethodPost, "/api/v1/config/reload"
	if status {
		method, path = http.MethodGet, "/api/v1/config/status"
	}
	// Synchronous activation can wait for a serialized durable transaction.
	// Use the caller's context for cancellation instead of the short timeout
	// intended for status queries. Copy both clients to avoid changing siblings.
	requestClient := c
	if !status {
		if transport, ok := c.http.(*http.Client); ok {
			httpCopy := *transport
			httpCopy.Timeout = 0
			clientCopy := *c
			clientCopy.http = &httpCopy
			requestClient = &clientCopy
		}
	}
	var result proxy.ReloadOutcome
	var raw json.RawMessage
	if err := requestClient.do(ctx, method, c.base+path, nil, &raw); err != nil {
		return result, err
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		return result, fmt.Errorf("malformed daemon reload outcome: %w", err)
	}
	// The wire type is the required-field source; don't maintain a second
	// independently curated list of required status keys.
	wire := reflect.TypeFor[proxy.ReloadOutcome]()
	for field := range wire.NumField() {
		name, option, _ := strings.Cut(wire.Field(field).Tag.Get("json"), ",")
		if option == "omitempty" {
			continue
		}
		if value, ok := fields[name]; !ok || bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
			return result, fmt.Errorf("malformed daemon reload outcome: missing %s", name)
		}
	}
	if err := json.Unmarshal(raw, &result); err != nil {
		return result, fmt.Errorf("malformed daemon reload outcome: %w", err)
	}
	if err := validateReloadOutcome(result); err != nil {
		return result, err
	}
	return result, nil
}

func validateReloadOutcome(out proxy.ReloadOutcome) error {
	invalid := errors.New("malformed or unknown daemon reload outcome")
	if out.InstanceID == "" || out.Generation == 0 || out.Trigger == "" || out.WatcherState == "" || out.RestartRequiredFields == nil {
		return invalid
	}
	if !reloadHashValid(out.CanonicalPolicyHash, false) || !reloadHashValid(out.CandidateSourceHash, true) || !reloadHashValid(out.AcceptedSourceHash, true) {
		return invalid
	}
	if out.PendingRestart != (len(out.RestartRequiredFields) > 0) {
		return invalid
	}
	switch out.Verdict {
	case proxy.ReloadAccepted, proxy.ReloadUnchanged:
		if out.PendingRestart {
			return invalid
		}
	case proxy.ReloadRestartRequired:
		if !out.PendingRestart {
			return invalid
		}
	case proxy.ReloadRejected, proxy.ReloadUncertain, proxy.ReloadUnavailable, proxy.ReloadCompensated:
		if out.Reason == "" {
			return invalid
		}
	default:
		return invalid
	}
	return nil
}

func reloadHashValid(hash string, optional bool) bool {
	if optional && (hash == "" || hash == "defaults") {
		return true
	}
	decoded, err := hex.DecodeString(hash)
	return err == nil && len(decoded) == 32
}
