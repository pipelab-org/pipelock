// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package audit

// LogTLSCRLWarning reports an issuer that cannot support CRL distribution points.
func (l *Logger) LogTLSCRLWarning() {
	e := newLogEntry(l.zl.Warn(), EventConfigReload).
		str("status", "warning").
		str("detail", "TLS CA lacks CRL signing usage; certificate revocation checking compatibility is unavailable (regenerate with pipelock tls init)")
	e.msg("TLS certificate revocation checking compatibility unavailable")
	if l.emitter != nil {
		l.emitEvent(string(EventConfigReload), e.fields)
	}
}
