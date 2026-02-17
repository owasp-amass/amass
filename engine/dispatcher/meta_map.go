// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package dispatcher

import (
	"errors"
	"sync"

	"github.com/caffix/stringset"
)

type metaMap struct {
	sync.RWMutex
	entries map[string]map[string]any
}

func newMetaMap() *metaMap {
	return &metaMap{entries: make(map[string]map[string]any)}
}

func (mm *metaMap) InsertEntry(sid, eid string, meta any) error {
	mm.Lock()
	defer mm.Unlock()

	if sid == "" || eid == "" {
		return errors.New("session and entity ID must be provided")
	}

	if _, found := mm.entries[sid]; !found {
		mm.entries[sid] = make(map[string]any)
	}

	mm.entries[sid][eid] = meta
	return nil
}

func (mm *metaMap) GetEntry(sid, eid string) (any, error) {
	mm.RLock()
	defer mm.RUnlock()

	if sid == "" || eid == "" {
		return nil, errors.New("session and entity ID must be provided")
	}

	smap, found := mm.entries[sid]
	if !found {
		return nil, errors.New("session ID not found in meta map")
	}

	meta, found := smap[eid]
	if !found {
		return nil, errors.New("meta data for the entity ID not found")
	}

	return meta, nil
}

func (mm *metaMap) DeleteSession(sid string) error {
	mm.Lock()
	defer mm.Unlock()

	mm.deleteSessionLocked(sid)
	return nil
}

func (mm *metaMap) deleteSessionLocked(sid string) {
	delete(mm.entries, sid)
}

func (mm *metaMap) DeleteSessionEntry(sid, eid string) error {
	mm.Lock()
	defer mm.Unlock()

	if sid == "" || eid == "" {
		return errors.New("session and entity ID must be provided")
	}

	smap, found := mm.entries[sid]
	if !found {
		return errors.New("session ID not found in meta map")
	}

	delete(smap, eid)
	return nil
}

func (mm *metaMap) RemoveInactiveSessions(sids []string) {
	mm.RLock()
	var msids []string
	for sid := range mm.entries {
		msids = append(msids, sid)
	}
	mm.RUnlock()

	if len(msids) == 0 {
		return
	}

	sset := stringset.New(sids...)
	mset := stringset.New(msids...)

	mset.Subtract(sset)
	if mset.Len() == 0 {
		return
	}

	mm.Lock()
	defer mm.Unlock()

	for _, sid := range mset.Slice() {
		mm.deleteSessionLocked(sid)
	}
}
