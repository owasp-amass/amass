// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package scope

import (
	"net/netip"
	"strings"

	oam "github.com/owasp-amass/open-asset-model"
	oamnet "github.com/owasp-amass/open-asset-model/network"
)

// AddIPAddress adds an address to the scope, unless a netblock in it holds
// the address.
func (s *Scope) AddIPAddress(ip *oamnet.IPAddress) bool {
	return s.addEntry(ip, false, true)
}

func (s *Scope) addIPAddress(ip *oamnet.IPAddress) bool {
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
	if ip := addressEntry(addr); ip != nil {
		return s.AddIPAddress(ip)
	}
	return false
}

// addressEntry is the scope entry for an address, or nil.
func addressEntry(addr string) *oamnet.IPAddress {
	a, err := netip.ParseAddr(strings.TrimSpace(addr))
	if err != nil {
		return nil
	}

	ip := &oamnet.IPAddress{Address: a, Type: "IPv4"}
	if ip.Address.Is6() {
		ip.Type = "IPv6"
	}
	return ip
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

// AddNetblock adds a netblock to the scope.
func (s *Scope) AddNetblock(nb *oamnet.Netblock) bool {
	return s.addEntry(nb, false, true)
}

func (s *Scope) addNetblock(nb *oamnet.Netblock) bool {
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
	if nb := cidrEntry(cidr); nb != nil {
		return s.AddNetblock(nb)
	}
	return false
}

// cidrEntry is the scope entry for a CIDR, or nil.
func cidrEntry(cidr string) *oamnet.Netblock {
	p, err := netip.ParsePrefix(strings.TrimSpace(cidr))
	if err != nil {
		return nil
	}

	nb := &oamnet.Netblock{CIDR: p, Type: "IPv4"}
	if nb.CIDR.Addr().Is6() {
		nb.Type = "IPv6"
	}
	return nb
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

// matchesNetblock returns the scope netblock that is the netblock or holds
// it: a range inside an in-scope CIDR is in scope.
func (s *Scope) matchesNetblock(nb *oamnet.Netblock) (oam.Asset, int) {
	s.netLock.Lock()
	defer s.netLock.Unlock()

	key := nb.CIDR.String()
	if a, found := s.networks[key]; found {
		return a, 100
	}
	for _, a := range s.networks {
		if p, ok := a.(*oamnet.Netblock); ok && p.CIDR.Bits() <= nb.CIDR.Bits() &&
			p.CIDR.Contains(nb.CIDR.Addr()) {
			return a, 100
		}
	}

	return nil, 0
}

// AddAutonomousSystem adds an autonomous system to the scope.
func (s *Scope) AddAutonomousSystem(as *oamnet.AutonomousSystem) bool {
	return s.addEntry(as, false, true)
}

func (s *Scope) addAutonomousSystem(as *oamnet.AutonomousSystem) bool {
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
