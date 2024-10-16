// Copyright © by Jeff Foley 2017-2024. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package scope

import (
	"math"
	"strings"

	"github.com/adrg/strutil"
	"github.com/adrg/strutil/metrics"
	oam "github.com/owasp-amass/open-asset-model"
	"github.com/owasp-amass/open-asset-model/org"
)

func (s *Scope) AddOrganization(o *org.Organization) bool {
	key := strings.ToLower(o.Name)
	if s.isBadField(key) {
		return false
	}

	s.orgLock.Lock()
	defer s.orgLock.Unlock()

	if _, found := s.orgs[key]; !found {
		s.orgs[key] = o
		return true
	}
	return false
}

func (s *Scope) AddOrg(o string) bool {
	return s.AddOrganization(&org.Organization{Name: o})
}

func (s *Scope) Organizations() []*org.Organization {
	s.orgLock.Lock()
	defer s.orgLock.Unlock()

	var results []*org.Organization
	for _, v := range s.orgs {
		if o, ok := v.(*org.Organization); ok {
			results = append(results, o)
		}
	}
	return results
}

func (s *Scope) matchesOrg(o *org.Organization, conf int) (oam.Asset, int) {
	for _, v := range s.Organizations() {
		if strings.EqualFold(o.Name, v.Name) {
			return v, 100
		}

		swg := metrics.NewSmithWatermanGotoh()
		swg.CaseSensitive = false
		swg.GapPenalty = -0.1
		swg.Substitution = metrics.MatchMismatch{
			Match:    1,
			Mismatch: -0.5,
		}

		if sim := strutil.Similarity(o.Name, v.Name, swg); sim >= float64(conf) {
			return v, int(math.Round(sim))
		}
	}
	return nil, 0
}
