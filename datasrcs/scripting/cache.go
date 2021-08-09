// Copyright 2020-2021 Jeff Foley. All rights reserved.
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
		if err := db.CacheSourceData(s.String(), url, resp); err != nil {
			return err
		}
	}
	return nil
}

// Wrapper so that scripts can obtain cached data source responses.
func (s *Script) obtainResponse(L *lua.LState) int {
	var result string
	url := L.CheckString(1)
	ttl := L.CheckInt(2)

	if url != "" && ttl > 0 {
		if resp, err := s.getCachedResponse(url, ttl); err == nil {
			result = resp
		}
	}

	if result != "" {
		L.Push(lua.LString(result))
	} else {
		L.Push(lua.LNil)
	}
	return 1
}

// Wrapper so that scripts can cache data source responses.
func (s *Script) cacheResponse(L *lua.LState) int {
	url := L.CheckString(1)
	resp := L.CheckString(2)

	if url != "" && resp != "" {
		_ = s.setCachedResponse(url, resp)
	}

	return 0
}
