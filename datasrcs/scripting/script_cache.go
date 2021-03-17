// Copyright 2017-2021 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package scripting

import (
	"fmt"

	lua "github.com/yuin/gopher-lua"
)

func (s *Script) getCachedResponse(url string, ttl int) (string, error) {
	for _, db := range s.sys.GraphDatabases() {
		if resp, err := db.GetSourceData(s.String(), url, ttl); err == nil {
			return resp, err
		}
	}
	return "", fmt.Errorf("Failed to obtain a cached response for %s", url)
}

func (s *Script) setCachedResponse(url, resp string) error {
	for _, db := range s.sys.GraphDatabases() {
		if err := db.CacheSourceData(s.String(), s.SourceType, url, resp); err != nil {
			return err
		}
	}
	return nil
}

// Wrapper so that scripts can obtain cached data source responses.
func (s *Script) obtainResponse(L *lua.LState) int {
	lv := L.Get(1)
	if lv == nil {
		L.Push(lua.LNil)
		return 1
	}

	u, ok := lv.(lua.LString)
	if !ok {
		L.Push(lua.LNil)
		return 1
	}
	url := string(u)

	lv = L.Get(2)
	if lv == nil {
		L.Push(lua.LNil)
		return 1
	}

	t, ok := lv.(lua.LNumber)
	if !ok {
		L.Push(lua.LNil)
		return 1
	}

	ttl := int(t)
	if ttl <= 0 {
		L.Push(lua.LNil)
		return 1
	}

	if resp, err := s.getCachedResponse(url, ttl); err == nil {
		L.Push(lua.LString(resp))
		return 1
	}

	L.Push(lua.LNil)
	return 1
}

// Wrapper so that scripts can cache data source responses.
func (s *Script) cacheResponse(L *lua.LState) int {
	lv := L.Get(1)
	if lv == nil {
		return 0
	}

	u, ok := lv.(lua.LString)
	if !ok {
		return 0
	}

	lv = L.Get(2)
	if lv == nil {
		return 0
	}

	resp, ok := lv.(lua.LString)
	if !ok {
		return 0
	}

	_ = s.setCachedResponse(string(u), string(resp))
	return 0
}
