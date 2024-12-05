// Copyright © by Jeff Foley 2017-2024. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package scope

type Fingerprint struct {
	Type  string
	Value string
}

/*
func (s *Scope) AddFingerprint(fin *Fingerprint) bool {
	s.finLock.Lock()
	defer s.finLock.Unlock()

	ftype := strings.ToLower(fin.Type)
	if _, found := s.fingerprints[ftype]; !found {
		s.fingerprints[ftype] = make(map[string]*Fingerprint)
	}

	if _, found := s.fingerprints[ftype][fin.Value]; !found {
		s.fingerprints[ftype][fin.Value] = fin
		return true
	}
	return false
}

func (s *Scope) Fingerprints() []*Fingerprint {
	s.finLock.Lock()
	defer s.finLock.Unlock()

	var results []*Fingerprint
	for _, m := range s.fingerprints {
		for _, v := range m {
			results = append(results, v)
		}
	}
	return results
}

func (s *Scope) matchesFin(fin *Fingerprint) (oam.Asset, int) {
	for _, v := range s.Fingerprints() {
		if v.Type == fin.Type && strings.EqualFold(v.Value, fin.Value) {
			return nil, 100
		}
	}
	return nil, 0
}
*/
