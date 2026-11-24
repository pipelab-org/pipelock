// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"net"
	"net/http"
	"net/url"
	"strconv"

	"github.com/luckyPipewrench/pipelock/internal/certgen"
	"github.com/luckyPipewrench/pipelock/internal/config"
)

const tlsCRLPath = "/.well-known/pipelock/ca.crl"

// SetTLSCRLBoundAddress supplies the actual main listener address after binding.
// It also updates a cache loaded before :0 was assigned its real port.
func (p *Proxy) SetTLSCRLBoundAddress(addr string) {
	p.tlsCRLMu.Lock()
	defer p.tlsCRLMu.Unlock()
	p.tlsCRLAddr = addr
	if cache := p.certCachePtr.Load(); cache != nil {
		p.configureTLSCRLLocked(cache, p.cfgPtr.Load())
	}
}

func (p *Proxy) configureTLSCRLLocked(cache *certgen.CertCache, cfg *config.Config) {
	raw := cfg.TLSInterception.CRLURL
	if raw == "off" {
		cache.SetCRLDistributionPoints(nil)
		return
	}
	if !cache.CanSignCRL() {
		p.tlsCRLWarnOnce.Do(func() {
			p.logger.LogTLSCRLWarning()
		})
		cache.SetCRLDistributionPoints(nil)
		return
	}
	if raw == "" {
		addr := p.tlsCRLAddr
		if addr == "" {
			addr = cfg.FetchProxy.Listen
		}
		raw = defaultTLSCRLURL(addr)
	}
	if raw == "" {
		cache.SetCRLDistributionPoints(nil)
	} else {
		cache.SetCRLDistributionPoints([]string{raw})
	}
}

func defaultTLSCRLURL(addr string) string {
	host, port, err := net.SplitHostPort(addr)
	if err != nil || port == "0" || port == "" {
		return ""
	}
	if ip := net.ParseIP(host); host == "" || ip != nil && ip.IsUnspecified() {
		host = "127.0.0.1"
	}
	return (&url.URL{Scheme: "http", Host: net.JoinHostPort(host, port), Path: tlsCRLPath}).String()
}

func (p *Proxy) handleTLSCRL(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	cache := p.certCachePtr.Load()
	if cache == nil || !p.cfgPtr.Load().TLSInterception.Enabled || !cache.CanSignCRL() {
		http.NotFound(w, r)
		return
	}
	der, err := cache.CRL()
	if err != nil {
		http.Error(w, "CRL unavailable", http.StatusServiceUnavailable)
		return
	}
	w.Header().Set("Content-Type", "application/pkix-crl")
	w.Header().Set("Cache-Control", "public, max-age=3600")
	w.Header().Set("Content-Length", strconv.Itoa(len(der)))
	if r.Method == http.MethodGet {
		_, _ = w.Write(der)
	}
}

// Only the exact CRL path at this listener's loopback port is handled locally.
// No hostname resolution, alternate paths, credentials or query data qualify.
func (p *Proxy) isSelfCRLRequest(r *http.Request) bool {
	if r.URL.Scheme != "http" || r.URL.EscapedPath() != tlsCRLPath || r.URL.RawQuery != "" || r.URL.ForceQuery || r.URL.User != nil || r.URL.Fragment != "" {
		return false
	}
	ip := net.ParseIP(r.URL.Hostname())
	if ip == nil || !ip.IsLoopback() {
		return false
	}
	p.tlsCRLMu.Lock()
	addr := p.tlsCRLAddr
	p.tlsCRLMu.Unlock()
	host, port, err := net.SplitHostPort(addr)
	if err != nil || port == "0" || port == "" {
		return false
	}
	boundIP := net.ParseIP(host)
	if boundIP == nil || !boundIP.IsUnspecified() && !boundIP.Equal(ip) {
		return false
	}
	return r.URL.Port() == port || r.URL.Port() == "" && port == "80"
}
