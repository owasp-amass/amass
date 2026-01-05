// Copyright © by Jeff Foley 2017-2025. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package scope

import (
	"sync"
	"time"

	"github.com/owasp-amass/amass/v5/config"
	oam "github.com/owasp-amass/open-asset-model"
)

type Scope struct {
	startTime time.Time

	orgLock sync.Mutex
	orgs    map[string]oam.Asset

	domLock sync.Mutex
	domains map[string]oam.Asset

	addrLock  sync.Mutex
	addresses map[string]oam.Asset

	netLock  sync.Mutex
	networks map[string]oam.Asset

	asLock     sync.Mutex
	autsystems map[int]oam.Asset

	locLock   sync.Mutex
	locations map[string]oam.Asset

	blLock    sync.Mutex
	blacklist map[string]bool

	//finLock      sync.Mutex
	fingerprints map[string]map[string]*Fingerprint
}

func New(startTime time.Time) *Scope {
	return &Scope{
		startTime:    startTime,
		orgs:         make(map[string]oam.Asset),
		domains:      make(map[string]oam.Asset),
		addresses:    make(map[string]oam.Asset),
		networks:     make(map[string]oam.Asset),
		autsystems:   make(map[int]oam.Asset),
		locations:    make(map[string]oam.Asset),
		blacklist:    make(map[string]bool),
		fingerprints: make(map[string]map[string]*Fingerprint),
	}
}

func CreateFromConfigScope(config *config.Config, startTime time.Time) *Scope {
	scope := New(startTime)

	for _, d := range config.Domains() {
		scope.AddDomain(d)
	}
	for _, addr := range config.Scope.Addresses {
		scope.AddAddress(addr.String())
	}
	for _, cidr := range config.Scope.CIDRs {
		scope.AddCIDR(cidr.String())
	}
	for _, asn := range config.Scope.ASNs {
		scope.AddASN(asn)
	}
	for _, bl := range config.Scope.Blacklist {
		scope.AddBlacklist(bl)
	}
	return scope
}
