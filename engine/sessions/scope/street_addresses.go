// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package scope

import (
	"fmt"
	"strings"

	"github.com/owasp-amass/amass/v5/internal/graph"
	oam "github.com/owasp-amass/open-asset-model"
	oamcon "github.com/owasp-amass/open-asset-model/contact"
)

// matchesPhone matches a phone against the session's phone seeds.
func (s *Scope) matchesPhone(ph *oamcon.Phone) (oam.Asset, int) {
	if s.Session == nil || s.Session.Config() == nil {
		return nil, 0
	}
	if s.Session.Config().IsPhoneInScope(ph.E164) || s.Session.Config().IsPhoneInScope(ph.Raw) {
		return ph, 100
	}
	return nil, 0
}

// AddStreetAddress adds a street address to the scope.
func (s *Scope) AddStreetAddress(loc *oamcon.StreetAddress) bool {
	return s.addEntry(loc, false, true)
}

func (s *Scope) addStreetAddress(loc *oamcon.StreetAddress) bool {
	key := strings.ToLower(loc.Address)
	if key == "" {
		return false
	}

	s.streetLock.Lock()
	defer s.streetLock.Unlock()

	if _, found := s.streetAddresses[key]; !found {
		s.streetAddresses[key] = loc
		return true
	}
	return false
}

func (s *Scope) StreetAddresses() []*oamcon.StreetAddress {
	s.streetLock.Lock()
	defer s.streetLock.Unlock()

	var results []*oamcon.StreetAddress
	for _, v := range s.streetAddresses {
		if loc, ok := v.(*oamcon.StreetAddress); ok {
			results = append(results, loc)
		}
	}
	return results
}

// matchesStreetAddress returns the scope street address the address is: the
// same building number, street, city and province (accuracy 100), or the same
// address written differently, "5801 Smith Avenue" and "5801 Smith Ave, Suite
// 3110B" (graph.StreetAddressKeyOf; nearMatchAccuracy, when that is at least
// conf).
func (s *Scope) matchesStreetAddress(loc *oamcon.StreetAddress, conf int) (oam.Asset, int) {
	if loc.BuildingNumber == "" {
		return nil, 0
	}

	key := graph.StreetAddressKeyOf(loc.BuildingNumber, loc.StreetName, loc.Address, loc.PostalCode)
	var near oam.Asset
	for _, loc2 := range s.StreetAddresses() {
		if loc.BuildingNumber != loc2.BuildingNumber {
			continue
		}

		lstr1 := fmt.Sprintf("%s %s %s %s", loc.BuildingNumber, loc.StreetName, loc.City, loc.Province)
		lstr2 := fmt.Sprintf("%s %s %s %s", loc2.BuildingNumber, loc2.StreetName, loc2.City, loc2.Province)
		if strings.EqualFold(lstr1, lstr2) {
			return loc2, 100
		}
		if near == nil && key != "" &&
			key == graph.StreetAddressKeyOf(loc2.BuildingNumber, loc2.StreetName, loc2.Address, loc2.PostalCode) {
			near = loc2
		}
	}
	if near != nil && nearMatchAccuracy >= conf {
		return near, nearMatchAccuracy
	}
	return nil, 0
}
