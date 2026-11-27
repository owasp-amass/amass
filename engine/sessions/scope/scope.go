// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package scope

import (
	"net/netip"
	"strings"

	amassdns "github.com/owasp-amass/amass/v5/internal/net/dns"
	oam "github.com/owasp-amass/open-asset-model"
	oamcert "github.com/owasp-amass/open-asset-model/certificate"
	oamcon "github.com/owasp-amass/open-asset-model/contact"
	oamdns "github.com/owasp-amass/open-asset-model/dns"
	oamgen "github.com/owasp-amass/open-asset-model/general"
	oamnet "github.com/owasp-amass/open-asset-model/network"
	oamorg "github.com/owasp-amass/open-asset-model/org"
	oamreg "github.com/owasp-amass/open-asset-model/registration"
	oamurl "github.com/owasp-amass/open-asset-model/url"
)

// Add adds the scope entry the asset gives, if any: a domain name, address,
// netblock, autonomous system, organization or street address.
func (s *Scope) Add(a oam.Asset) bool {
	if e := entryOf(a); e != nil {
		return s.addEntry(e, false, true)
	}
	return false
}

// entryOf is the scope entry an asset gives, or nil.
func entryOf(a oam.Asset) oam.Asset {
	switch v := a.(type) {
	case *oamdns.FQDN, *oamnet.IPAddress, *oamnet.Netblock, *oamnet.AutonomousSystem, *oamorg.Organization,
		*oamcon.StreetAddress:
		return v
	case *oamgen.Identifier:
		if domain, found := getEmailDomain(v); found {
			return &oamdns.FQDN{Name: domain}
		}
	case *oamreg.DomainRecord:
		return &oamdns.FQDN{Name: v.Domain}
	case *oamreg.IPNetRecord:
		if nb := cidrEntry(v.CIDR.String()); nb != nil {
			return nb
		}
	case *oamreg.AutnumRecord:
		return &oamnet.AutonomousSystem{Number: v.Number}
	case *oamcert.TLSCertificate:
		if re := amassdns.AnySubdomainRegex(); re.MatchString(v.SubjectCommonName) {
			return &oamdns.FQDN{Name: v.SubjectCommonName}
		}
	case *oamurl.URL:
		if ip, err := netip.ParseAddr(v.Host); err == nil {
			if e := addressEntry(ip.String()); e != nil {
				return e
			}
		} else {
			return &oamdns.FQDN{Name: v.Host}
		}
	}
	return nil
}

func (s *Scope) IsAssetInScope(a oam.Asset, conf int) (oam.Asset, int) {
	// Check blacklist first
	if s.IsBlacklisted(a) {
		return nil, 0
	}

	var accuracy int
	var match oam.Asset

	switch v := a.(type) {
	case *oamdns.FQDN:
		match, accuracy = s.matchesDomain(v)
	case *oamgen.Identifier:
		if domain, found := getEmailDomain(v); found {
			match, accuracy = s.matchesDomain(&oamdns.FQDN{Name: domain})
		}
	case *oamnet.IPAddress:
		match, accuracy = s.addressInScope(v)
	case *oamnet.Netblock:
		match, accuracy = s.matchesNetblock(v)
	case *oamnet.AutonomousSystem:
		match, accuracy = s.matchesAutonomousSystem(v)
	case *oamreg.DomainRecord:
		match, accuracy = s.matchesDomain(&oamdns.FQDN{Name: v.Domain})
		if match == nil || accuracy == 0 {
			match, accuracy = s.matchesOrg(&oamorg.Organization{ID: v.Name, Name: v.Name}, conf)
		}
	case *oamreg.IPNetRecord:
		match, accuracy = s.matchesNetblock(&oamnet.Netblock{CIDR: v.CIDR, Type: v.Type})
	case *oamreg.AutnumRecord:
		match, accuracy = s.matchesAutonomousSystem(&oamnet.AutonomousSystem{Number: v.Number})
		if match == nil || accuracy == 0 {
			match, accuracy = s.matchesOrg(&oamorg.Organization{ID: v.Name, Name: v.Name}, conf)
		}
	case *oamcert.TLSCertificate:
		if re := amassdns.AnySubdomainRegex(); re.MatchString(v.SubjectCommonName) {
			match, accuracy = s.matchesDomain(&oamdns.FQDN{Name: v.SubjectCommonName})
		}
	case *oamurl.URL:
		match, accuracy = s.matchesDomain(&oamdns.FQDN{Name: v.Host})
	case *oamorg.Organization:
		match, accuracy = s.matchesOrg(v, conf)
	case *oamcon.StreetAddress:
		match, accuracy = s.matchesStreetAddress(v, conf)
	case *oamcon.Phone:
		match, accuracy = s.matchesPhone(v)
	}

	return match, accuracy
}

func getEmailDomain(email *oamgen.Identifier) (string, bool) {
	if email == nil || email.Type != oamgen.EmailAddress {
		return "", false
	}

	parts := strings.Split(email.ID, "@")

	if len(parts) != 2 {
		return "", false
	}

	return parts[1], true
}

func (s *Scope) AddBlacklist(name string) {
	s.blLock.Lock()
	defer s.blLock.Unlock()

	key := strings.ToLower(strings.TrimSpace(name))
	if key != "" {
		s.blacklist[key] = true
	}
}

func (s *Scope) IsBlacklisted(a oam.Asset) bool {
	s.blLock.Lock()
	defer s.blLock.Unlock()

	var name string
	switch v := a.(type) {
	case *oamdns.FQDN:
		name = strings.ToLower(v.Name)
	case *oamurl.URL:
		name = strings.ToLower(v.Host)
	default:
		return false
	}

	if name == "" {
		return false
	}

	for bl := range s.blacklist {
		if strings.HasSuffix(name, bl) {
			nlen := len(name)
			blen := len(bl)
			if nlen == blen || (nlen > blen && name[nlen-blen-1] == '.') {
				return true
			}
		}
	}
	return false
}
