package main

import (
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"time"
)

func parseTrustedProxies(value string) ([]netip.Prefix, error) {
	var prefixes []netip.Prefix
	for _, item := range strings.Split(value, ",") {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		p, err := netip.ParsePrefix(item)
		if err != nil {
			return nil, fmt.Errorf("TRUSTED_PROXIES: invalid CIDR %q", item)
		}
		prefixes = append(prefixes, p)
	}
	return prefixes, nil
}
func (g *gateway) trustedProxy(ip netip.Addr) bool {
	for _, p := range g.trustedProxies {
		if p.Contains(ip.Unmap()) {
			return true
		}
	}
	return false
}
func (g *gateway) clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	peer, err := netip.ParseAddr(host)
	if err != nil {
		return host
	}
	peer = peer.Unmap()
	if !g.trustedProxy(peer) {
		return peer.String()
	}
	// Walk from the closest proxy towards the client. Never trust an address
	// supplied to the first untrusted hop by someone further to its left.
	hops := strings.Split(r.Header.Get("X-Forwarded-For"), ",")
	for i := len(hops) - 1; i >= 0; i-- {
		ip, err := netip.ParseAddr(strings.TrimSpace(hops[i]))
		if err != nil {
			return peer.String()
		}
		ip = ip.Unmap()
		if !g.trustedProxy(ip) {
			return ip.String()
		}
	}
	return peer.String()
}

var nonPublicRanges = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"), netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("192.0.0.0/24"), netip.MustParsePrefix("192.0.2.0/24"),
	netip.MustParsePrefix("198.18.0.0/15"), netip.MustParsePrefix("198.51.100.0/24"),
	netip.MustParsePrefix("203.0.113.0/24"), netip.MustParsePrefix("240.0.0.0/4"),
	netip.MustParsePrefix("2001:db8::/32"), netip.MustParsePrefix("64:ff9b::/96"),
	netip.MustParsePrefix("64:ff9b:1::/48"), netip.MustParsePrefix("2002::/16"),
}

func publicMetadataIP(ip net.IP) bool {
	addr, ok := netip.AddrFromSlice(ip)
	if !ok {
		return false
	}
	addr = addr.Unmap()
	if !addr.IsGlobalUnicast() || addr.IsPrivate() || addr.IsLoopback() || addr.IsLinkLocalUnicast() {
		return false
	}
	for _, prefix := range nonPublicRanges {
		if prefix.Contains(addr) {
			return false
		}
	}
	return true
}

const registrationTTL = time.Hour

func unapprovedExpired(c *client, now time.Time) bool {
	return !c.Manual && !c.Approved && c.LastUsed.IsZero() && now.Sub(c.Created) >= registrationTTL
}
func (l *limiter) allowRegistration(ip string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	if l.registrations == nil {
		l.registrations = map[string][]time.Time{}
	}
	for key, ts := range l.registrations {
		kept := ts[:0]
		for _, at := range ts {
			if now.Sub(at) < time.Hour {
				kept = append(kept, at)
			}
		}
		if len(kept) == 0 {
			delete(l.registrations, key)
		} else {
			l.registrations[key] = kept
		}
	}
	kept := l.registrationGlobal[:0]
	for _, at := range l.registrationGlobal {
		if now.Sub(at) < time.Hour {
			kept = append(kept, at)
		}
	}
	l.registrationGlobal = kept
	if len(l.registrations[ip]) >= 5 || len(kept) >= 60 {
		return false
	}
	l.registrations[ip] = append(l.registrations[ip], now)
	l.registrationGlobal = append(l.registrationGlobal, now)
	return true
}
