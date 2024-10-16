// Copyright © by Jeff Foley 2017-2024. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package scope

import (
	"net/netip"
	"strings"

	oam "github.com/owasp-amass/open-asset-model"
	oamnet "github.com/owasp-amass/open-asset-model/network"
)

func (s *Scope) AddIPAddress(ip *oamnet.IPAddress) bool {
	if _, conf := s.addressInScope(ip); conf > 0 {
		return false
	}

	s.addrLock.Lock()
	defer s.addrLock.Unlock()

	key := ip.Address.String()
	if _, found := s.addresses[key]; !found {
		s.addresses[key] = ip
		return true
	}
	return false
}

func (s *Scope) AddAddress(addr string) bool {
	ip := &oamnet.IPAddress{Address: netip.MustParseAddr(strings.TrimSpace(addr)), Type: "IPv4"}
	if ip.Address.Is6() {
		ip.Type = "IPv6"
	}
	return s.AddIPAddress(ip)
}

func (s *Scope) IPAddresses() []*oamnet.IPAddress {
	s.addrLock.Lock()
	defer s.addrLock.Unlock()

	var results []*oamnet.IPAddress
	for _, v := range s.addresses {
		if ip, ok := v.(*oamnet.IPAddress); ok {
			results = append(results, ip)
		}
	}
	return results
}

func (s *Scope) Addresses() []string {
	s.addrLock.Lock()
	defer s.addrLock.Unlock()

	var results []string
	for k := range s.addresses {
		results = append(results, k)
	}
	return results
}

func (s *Scope) addressInScope(ip *oamnet.IPAddress) (oam.Asset, int) {
	for _, nb := range s.Netblocks() {
		if nb.CIDR.Contains(ip.Address) {
			return nb, 100
		}
	}
	for _, addr := range s.IPAddresses() {
		if addr.Type == ip.Type && addr.Address.Compare(ip.Address) == 0 {
			return addr, 100
		}
	}
	return nil, 0
}

func (s *Scope) AddNetblock(nb *oamnet.Netblock) bool {
	s.netLock.Lock()
	defer s.netLock.Unlock()

	key := nb.CIDR.String()
	if _, found := s.networks[key]; !found {
		s.networks[key] = nb
		return true
	}
	return false
}

func (s *Scope) AddCIDR(cidr string) bool {
	nb := &oamnet.Netblock{CIDR: netip.MustParsePrefix(strings.TrimSpace(cidr)), Type: "IPv4"}
	if nb.CIDR.Addr().Is6() {
		nb.Type = "IPv6"
	}
	return s.AddNetblock(nb)
}

func (s *Scope) Netblocks() []*oamnet.Netblock {
	s.netLock.Lock()
	defer s.netLock.Unlock()

	var results []*oamnet.Netblock
	for _, v := range s.networks {
		if nb, ok := v.(*oamnet.Netblock); ok {
			results = append(results, nb)
		}
	}
	return results
}

func (s *Scope) CIDRs() []string {
	s.netLock.Lock()
	defer s.netLock.Unlock()

	var results []string
	for k := range s.networks {
		results = append(results, k)
	}
	return results
}

func (s *Scope) matchesNetblock(nb *oamnet.Netblock) (oam.Asset, int) {
	s.netLock.Lock()
	defer s.netLock.Unlock()

	key := nb.CIDR.String()
	if a, found := s.networks[key]; found {
		return a, 100
	}

	return nil, 0
}

func (s *Scope) AddAutonomousSystem(as *oamnet.AutonomousSystem) bool {
	s.asLock.Lock()
	defer s.asLock.Unlock()

	key := as.Number
	if _, found := s.autsystems[key]; !found {
		s.autsystems[key] = as
		return true
	}
	return false
}

func (s *Scope) AddASN(asn int) bool {
	return s.AddAutonomousSystem(&oamnet.AutonomousSystem{Number: asn})
}

func (s *Scope) AutonomousSystems() []*oamnet.AutonomousSystem {
	s.asLock.Lock()
	defer s.asLock.Unlock()

	var results []*oamnet.AutonomousSystem
	for _, v := range s.autsystems {
		if as, ok := v.(*oamnet.AutonomousSystem); ok {
			results = append(results, as)
		}
	}
	return results
}

func (s *Scope) ASNs() []int {
	s.asLock.Lock()
	defer s.asLock.Unlock()

	var results []int
	for k := range s.autsystems {
		results = append(results, k)
	}
	return results
}

func (s *Scope) matchesAutonomousSystem(as *oamnet.AutonomousSystem) (oam.Asset, int) {
	s.asLock.Lock()
	defer s.asLock.Unlock()

	key := as.Number
	if a, found := s.autsystems[key]; found {
		return a, 100
	}

	return nil, 0
}
