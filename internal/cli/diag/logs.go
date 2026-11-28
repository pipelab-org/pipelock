// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package diag

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/evidencename"

	"github.com/spf13/cobra"
)

func LogsCmd() *cobra.Command {
	var logFile string
	var last int
	var filter string
	var follow bool

	cmd := &cobra.Command{
		Use:   "logs",
		Short: "View Pipelock audit logs",
		Long: `View, filter, and tail audit log entries.

Examples:
  pipelock logs --file pipelock-audit.log
  pipelock logs --file pipelock-audit.log --last 20
  pipelock logs --file pipelock-audit.log --filter blocked
  pipelock logs --file pipelock-audit.log -f`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if logFile == "" {
				return errLogFileRequired
			}

			if err := evidencename.RefuseReceiptName(logFile); err != nil {
				return err
			}
			f, err := os.Open(filepath.Clean(logFile))
			if err != nil {
				return fmt.Errorf("opening log file: %w", err)
			}
			defer f.Close() //nolint:errcheck // read-only file

			var lines []string
			var pending string
			sc := bufio.NewScanner(f)
			sc.Split(func(data []byte, atEOF bool) (int, []byte, error) {
				advance, token, splitErr := evidencename.SplitLegacyJSONLines(data, atEOF)
				if follow && atEOF && token != nil && advance == len(data) && len(data) > 0 && data[len(data)-1] != '\n' {
					pending = string(token)
					return advance, nil, splitErr
				}
				return advance, token, splitErr
			})
			for sc.Scan() {
				line := sc.Text()
				if filter != "" && !matchFilter(line, filter) {
					continue
				}
				lines = append(lines, line)
			}
			if err := sc.Err(); err != nil {
				if errors.Is(err, bufio.ErrTooLong) {
					return fmt.Errorf("logs cannot inspect an oversized line; for receipt evidence use 'pipelock verify-receipt <path>': %w", err)
				}
				return fmt.Errorf("reading log file: %w", err)
			}

			// Apply --last N
			if last > 0 && len(lines) > last {
				lines = lines[len(lines)-last:]
			}

			for _, line := range lines {
				cmd.Println(line)
			}

			if follow {
				cmd.PrintErrln("--- following (Ctrl+C to stop) ---")
				reader := bufio.NewReader(f)
				for {
					select {
					case <-cmd.Context().Done():
						return nil
					default:
					}
					fragment, err := reader.ReadString('\n')
					pending += fragment
					if claimErr := evidencename.RefuseReceiptContent([]byte(pending)); claimErr != nil {
						return fmt.Errorf("reading log file %q: %w", logFile, claimErr)
					}
					if len(pending) > bufio.MaxScanTokenSize {
						return fmt.Errorf("logs cannot inspect an oversized line; for receipt evidence use 'pipelock verify-receipt <path>'")
					}
					if err != nil {
						if err == io.EOF {
							time.Sleep(250 * time.Millisecond)
							continue
						}
						return err
					}
					line := strings.TrimRight(pending, "\n")
					pending = ""
					if filter != "" && !matchFilter(line, filter) {
						continue
					}
					cmd.Println(line)
				}
			}

			return nil
		},
	}

	cmd.Flags().StringVar(&logFile, "file", "", "audit log file path")
	cmd.Flags().IntVarP(&last, "last", "n", 0, "show only the last N entries")
	cmd.Flags().StringVar(&filter, "filter", "", "filter by event type (allowed, blocked, error, anomaly)")
	cmd.Flags().BoolVarP(&follow, "follow", "f", false, "follow the log file for new entries")

	return cmd
}

var errLogFileRequired = errors.New("--file is required (specify the audit log file path)")

// matchFilter checks if a JSON log line matches the event type filter.
func matchFilter(line, filter string) bool {
	var entry map[string]any
	if err := json.Unmarshal([]byte(line), &entry); err != nil {
		// If it's not JSON, do a simple string match
		return strings.Contains(line, filter)
	}
	if event, ok := entry["event"].(string); ok {
		return event == filter
	}
	return false
}
