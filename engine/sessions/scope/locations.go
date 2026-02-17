// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package scope

import (
	"fmt"
	"math"
	"strings"

	"github.com/adrg/strutil"
	"github.com/adrg/strutil/metrics"
	oam "github.com/owasp-amass/open-asset-model"
	oamcon "github.com/owasp-amass/open-asset-model/contact"
)

func (s *Scope) AddLocation(loc *oamcon.Location) bool {
	key := strings.ToLower(loc.Address)
	if key == "" {
		return false
	}

	s.locLock.Lock()
	defer s.locLock.Unlock()

	if _, found := s.locations[key]; !found {
		s.locations[key] = loc
		return true
	}
	return false
}

func (s *Scope) Locations() []*oamcon.Location {
	s.locLock.Lock()
	defer s.locLock.Unlock()

	var results []*oamcon.Location
	for _, v := range s.locations {
		if loc, ok := v.(*oamcon.Location); ok {
			results = append(results, loc)
		}
	}
	return results
}

func (s *Scope) matchesLocation(loc *oamcon.Location, conf int) (oam.Asset, int) {
	if loc.BuildingNumber == "" {
		return nil, 0
	}

	var bconf int
	var best oam.Asset
	for _, loc2 := range s.Locations() {
		if loc.BuildingNumber != loc2.BuildingNumber {
			continue
		}

		lstr1 := fmt.Sprintf("%s %s %s %s", loc.BuildingNumber, loc.StreetName, loc.City, loc.Province)
		lstr2 := fmt.Sprintf("%s %s %s %s", loc2.BuildingNumber, loc2.StreetName, loc2.City, loc2.Province)
		if strings.EqualFold(lstr1, lstr2) {
			return loc2, 100
		}

		swg := metrics.NewSmithWatermanGotoh()
		swg.CaseSensitive = false
		swg.GapPenalty = -0.1
		swg.Substitution = metrics.MatchMismatch{
			Match:    1,
			Mismatch: -0.5,
		}

		if sim := strutil.Similarity(lstr1, lstr2, swg); sim >= float64(conf) && sim > float64(bconf) {
			best = loc2
			bconf = int(math.Round(sim))
		}
	}
	return best, bconf
}
