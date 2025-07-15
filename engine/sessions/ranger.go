// Copyright © by Jeff Foley 2017-2025. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package sessions

import (
	"net"
	"sync"

	et "github.com/owasp-amass/amass/v5/engine/types"
	"github.com/yl2chen/cidranger"
)

type CIDRangerEntry struct {
	Net *net.IPNet
	ASN int
	Src *et.Source
}

func (r *CIDRangerEntry) Network() net.IPNet {
	return *r.Net
}

func (r *CIDRangerEntry) AutonomousSystem() int {
	return r.ASN
}

func (r *CIDRangerEntry) Source() *et.Source {
	return r.Src
}

type amassRanger struct {
	sync.Mutex
	ranger cidranger.Ranger
}

func (r *amassRanger) Insert(entry cidranger.RangerEntry) error {
	r.Lock()
	defer r.Unlock()

	return r.ranger.Insert(entry)
}

func (r *amassRanger) Remove(network net.IPNet) (cidranger.RangerEntry, error) {
	r.Lock()
	defer r.Unlock()

	return r.ranger.Remove(network)
}

func (r *amassRanger) Contains(ip net.IP) (bool, error) {
	r.Lock()
	defer r.Unlock()

	return r.ranger.Contains(ip)
}

func (r *amassRanger) ContainingNetworks(ip net.IP) ([]cidranger.RangerEntry, error) {
	r.Lock()
	defer r.Unlock()

	return r.ranger.ContainingNetworks(ip)
}

func (r *amassRanger) CoveredNetworks(network net.IPNet) ([]cidranger.RangerEntry, error) {
	r.Lock()
	defer r.Unlock()

	return r.ranger.CoveredNetworks(network)
}

func (r *amassRanger) Len() int {
	r.Lock()
	defer r.Unlock()

	return r.ranger.Len()
}

func NewAmassRanger() cidranger.Ranger {
	return &amassRanger{ranger: cidranger.NewPCTrieRanger()}
}
