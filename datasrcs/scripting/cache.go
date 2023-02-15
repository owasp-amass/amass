// Copyright © by Jeff Foley 2017-2023. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package scripting

import (
	"context"
	"fmt"
	"time"

	lua "github.com/yuin/gopher-lua"
)

func (s *Script) getCachedResponse(ctx context.Context, url string, ttl int) (string, error) {
	for _, db := range s.sys.GraphDatabases() {
		tCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
		defer cancel()

		if resp, err := db.GetSourceData(tCtx, s.String(), url, ttl); err == nil {
			return resp, err
		}
	}
	return "", fmt.Errorf("failed to obtain a cached response for %s", url)
}

func (s *Script) setCachedResponse(ctx context.Context, url, resp string) error {
	for _, db := range s.sys.GraphDatabases() {
		tCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
		defer cancel()

		if err := db.CacheSourceData(tCtx, s.String(), url, resp); err != nil {
			return err
		}
	}
	return nil
}

// Wrapper so that scripts can obtain cached data source responses.
func (s *Script) obtainResponse(L *lua.LState) int {
	ctx, err := extractContext(L.CheckUserData(1))
	if err != nil {
		L.Push(lua.LNil)
		return 1
	}

	var result string
	url := L.CheckString(2)
	ttl := L.CheckInt(3)

	if url != "" && ttl > 0 {
		if resp, err := s.getCachedResponse(ctx, url, ttl); err == nil {
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
	ctx, err := extractContext(L.CheckUserData(1))
	if err != nil {
		return 0
	}

	url := L.CheckString(2)
	resp := L.CheckString(3)
	if url != "" && resp != "" {
		_ = s.setCachedResponse(ctx, url, resp)
	}
	return 0
}
