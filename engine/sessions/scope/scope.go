// Copyright © by Jeff Foley 2017-2025. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package scope

import (
	"net/netip"
	"strings"

	oam "github.com/owasp-amass/open-asset-model"
	oamcert "github.com/owasp-amass/open-asset-model/certificate"
	"github.com/owasp-amass/open-asset-model/contact"
	oamdns "github.com/owasp-amass/open-asset-model/dns"
	"github.com/owasp-amass/open-asset-model/general"
	oamnet "github.com/owasp-amass/open-asset-model/network"
	"github.com/owasp-amass/open-asset-model/org"
	oamreg "github.com/owasp-amass/open-asset-model/registration"
	oamurl "github.com/owasp-amass/open-asset-model/url"
)

func (s *Scope) Add(a oam.Asset) bool {
	var newentry bool

	switch v := a.(type) {
	case *oamdns.FQDN:
		newentry = s.AddFQDN(v)
	case *general.Identifier:
		if domain, found := getEmailDomain(v); found {
			newentry = s.AddFQDN(&oamdns.FQDN{Name: domain})
		}
	case *oamnet.IPAddress:
		newentry = s.AddIPAddress(v)
	case *oamnet.Netblock:
		newentry = s.AddNetblock(v)
	case *oamnet.AutonomousSystem:
		newentry = s.AddAutonomousSystem(v)
	case *oamreg.DomainRecord:
		newentry = s.AddDomain(v.Domain)
	case *oamreg.IPNetRecord:
		newentry = s.AddCIDR(v.CIDR.String())
	case *oamreg.AutnumRecord:
		n1 := s.AddOrg(v.Name)
		n2 := s.AddASN(v.Number)
		newentry = n1 || n2
	case *oamcert.TLSCertificate:
		newentry = s.AddDomain(v.SubjectCommonName)
	case *oamurl.URL:
		if ip, err := netip.ParseAddr(v.Host); err == nil {
			newentry = s.AddAddress(ip.String())
		} else {
			newentry = s.AddDomain(v.Host)
		}
	case *org.Organization:
		newentry = s.AddOrganization(v)
	case *contact.Location:
		newentry = s.AddLocation(v)
	}

	return newentry
}

func (s *Scope) IsAssetInScope(a oam.Asset, conf int) (oam.Asset, int) {
	var accuracy int
	var match oam.Asset

	switch v := a.(type) {
	case *oamdns.FQDN:
		match, accuracy = s.matchesDomain(v)
	case *general.Identifier:
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
			match, accuracy = s.matchesOrg(&org.Organization{Name: v.Name}, conf)
		}
	case *oamreg.IPNetRecord:
		match, accuracy = s.matchesNetblock(&oamnet.Netblock{CIDR: v.CIDR, Type: v.Type})
	case *oamreg.AutnumRecord:
		match, accuracy = s.matchesAutonomousSystem(&oamnet.AutonomousSystem{Number: v.Number})
		if match == nil || accuracy == 0 {
			match, accuracy = s.matchesOrg(&org.Organization{Name: v.Name}, conf)
		}
	case *oamcert.TLSCertificate:
		match, accuracy = s.matchesDomain(&oamdns.FQDN{Name: v.SubjectCommonName})
	case *oamurl.URL:
		match, accuracy = s.matchesDomain(&oamdns.FQDN{Name: v.Host})
	case *org.Organization:
		match, accuracy = s.matchesOrg(v, conf)
	case *contact.Location:
		match, accuracy = s.matchesLocation(v, conf)
	}

	return match, accuracy
}

func (s *Scope) isBadField(field string) bool {
	badstrs := []string{"registration", "registry", "redact", "private", "privacy", "available", "domain", "proxy", "liability"}

	for _, bad := range badstrs {
		if strings.Contains(field, bad) {
			return true
		}
	}
	return false
}

func getEmailDomain(email *general.Identifier) (string, bool) {
	if email == nil || email.Type != general.EmailAddress {
		return "", false
	}

	parts := strings.Split(email.EntityID, "@")

	if len(parts) != 2 {
		return "", false
	}

	return parts[1], true
}
