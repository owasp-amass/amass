// Copyright © by Jeff Foley 2017-2024. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package scope

import (
	"strings"

	oam "github.com/owasp-amass/open-asset-model"
	oamfin "github.com/owasp-amass/open-asset-model/fingerprint"
)

func (s *Scope) AddFingerprint(fin *oamfin.Fingerprint) bool {
	s.finLock.Lock()
	defer s.finLock.Unlock()

	ftype := strings.ToLower(fin.Type)
	if _, found := s.fingerprints[ftype]; !found {
		s.fingerprints[ftype] = make(map[string]oam.Asset)
	}

	key := strings.ToLower(fin.Value)
	if _, found := s.fingerprints[ftype][key]; !found {
		s.fingerprints[ftype][key] = fin
		return true
	}
	return false
}

func (s *Scope) Fingerprints() []*oamfin.Fingerprint {
	s.finLock.Lock()
	defer s.finLock.Unlock()

	var results []*oamfin.Fingerprint
	for _, m := range s.fingerprints {
		for _, v := range m {
			if fin, ok := v.(*oamfin.Fingerprint); ok {
				results = append(results, fin)
			}
		}
	}
	return results
}

func (s *Scope) matchesFin(fin *oamfin.Fingerprint) (oam.Asset, int) {
	for _, v := range s.Fingerprints() {
		if v.Type == fin.Type && strings.EqualFold(v.Value, fin.Value) {
			return v, 100
		}
	}
	return nil, 0
}
