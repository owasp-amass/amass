// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package scope

import (
	"strings"

	oam "github.com/owasp-amass/open-asset-model"
	"github.com/owasp-amass/open-asset-model/dns"
	"golang.org/x/net/publicsuffix"
)

func (s *Scope) AddFQDN(fqdn *dns.FQDN) bool {
	if fqdn.Name == "" {
		return false
	}

	name := strings.ToLower(strings.TrimSpace(fqdn.Name))
	fqdn.Name = name

	// only registered domain names can be added to the session scope
	if dom, err := publicsuffix.EffectiveTLDPlusOne(
		fqdn.Name); err != nil || !strings.EqualFold(fqdn.Name, dom) {
		return false
	}

	s.domLock.Lock()
	defer s.domLock.Unlock()

	if _, found := s.domains[name]; !found {
		s.domains[name] = fqdn
		return true
	}
	return false
}

func (s *Scope) AddDomain(d string) bool {
	return s.AddFQDN(&dns.FQDN{Name: d})
}

func (s *Scope) FQDNs() []*dns.FQDN {
	s.domLock.Lock()
	defer s.domLock.Unlock()

	var results []*dns.FQDN
	for _, v := range s.domains {
		if fqdn, ok := v.(*dns.FQDN); ok {
			results = append(results, fqdn)
		}
	}
	return results
}

func (s *Scope) Domains() []string {
	s.domLock.Lock()
	defer s.domLock.Unlock()

	var results []string
	for k := range s.domains {
		results = append(results, k)
	}
	return results
}

func (s *Scope) matchesDomain(fqdn *dns.FQDN) (oam.Asset, int) {
	s.domLock.Lock()
	defer s.domLock.Unlock()

	name := strings.ToLower(strings.TrimSpace(fqdn.Name))
	if name == "" {
		return nil, 0
	}

	for k, v := range s.domains {
		if strings.HasSuffix(name, k) {
			alen := len(name)
			klen := len(k)

			// check for exact match first to guard against out of bound index
			if alen == klen || (alen > klen && name[alen-klen-1] == '.') {
				return v, 100
			}
		}
	}
	return nil, 0
}
