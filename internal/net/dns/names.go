// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package dns

import (
	"net/netip"
	"strings"

	"golang.org/x/net/publicsuffix"
)

// HostName returns s as a lower-case DNS host name under a public suffix
// ICANN manages, with at least one label of its own, or "" when it is not
// one: IP addresses, single labels, names outside the public DNS such as
// host.corp or host.local, and anything with characters outside letters,
// digits, hyphens and dots. A name under a hosting provider's suffix
// (site.github.io) is a host name.
func HostName(s string) string {
	s = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(s), "."))
	if s == "" || len(s) > 253 || strings.Contains(s, "..") || !strings.Contains(s, ".") {
		return ""
	}
	for _, r := range s {
		if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-' || r == '.') {
			return ""
		}
	}
	if _, err := netip.ParseAddr(s); err == nil {
		return ""
	}
	if suffix := icannSuffix(s); suffix == "" || suffix == s {
		return ""
	}
	return s
}

// icannSuffix returns the public suffix ICANN manages that name ends in,
// below any hosting provider's suffix (io for site.github.io), or "" when
// there is none.
func icannSuffix(name string) string {
	suffix, icann := publicsuffix.PublicSuffix(name)
	for !icann {
		i := strings.Index(suffix, ".")
		if i < 0 {
			return ""
		}
		suffix, icann = publicsuffix.PublicSuffix(suffix[i+1:])
	}
	return suffix
}

// RegistrableDomain returns the domain under which name is registered with a
// registry: one label in front of the public suffix ICANN manages, such as
// example.co.uk for www.example.co.uk. A name under a private suffix (a
// hosting provider's, such as site.github.io) gives the provider's domain,
// github.io, since that is what a registry holds; the site has no domain
// registration of its own. It returns "" when name is not a host name.
func RegistrableDomain(name string) string {
	name = HostName(name)
	if name == "" {
		return ""
	}

	suffix := icannSuffix(name)
	labels := strings.Split(name, ".")
	n := len(strings.Split(suffix, ".")) + 1
	if len(labels) < n {
		return ""
	}
	return strings.Join(labels[len(labels)-n:], ".")
}
