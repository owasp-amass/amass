// Copyright © by Jeff Foley 2017-2023. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package scripting

import (
	"context"
	"io"
	"strings"

	"github.com/OWASP/Amass/v3/net/http"
	lua "github.com/yuin/gopher-lua"
)

// Wrapper that allows scripts to make HTTP client requests.
func (s *Script) request(L *lua.LState) int {
	ctx, err := extractContext(L.CheckUserData(1))
	if err != nil || contextExpired(ctx) {
		L.Push(lua.LNil)
		L.Push(lua.LString("No user data parameter or context expired"))
		return 2
	}

	opt := L.CheckTable(2)
	if opt == nil {
		L.Push(lua.LNil)
		L.Push(lua.LString("No table parameter was provided"))
		return 2
	}

	var data string
	if method, ok := getStringField(L, opt, "method"); ok && strings.ToLower(method) == "post" {
		if d, ok := getStringField(L, opt, "data"); ok {
			data = d
		}
	}

	url, found := getStringField(L, opt, "url")
	if !found {
		L.Push(lua.LNil)
		L.Push(lua.LString("No URL found in the parameters"))
		return 2
	}

	hdrs := make(map[string]string)
	lv := L.GetField(opt, "headers")
	if tbl, ok := lv.(*lua.LTable); ok {
		tbl.ForEach(func(k, v lua.LValue) {
			hdrs[k.String()] = v.String()
		})
	}

	id, _ := getStringField(L, opt, "id")
	pass, _ := getStringField(L, opt, "pass")
	headers, body, status, err := s.req(ctx, url, data, hdrs, &http.BasicAuth{
		Username: id,
		Password: pass,
	})

	ht := L.NewTable()
	for k, v := range headers {
		ht.RawSetString(k, lua.LString(v))
	}

	L.Push(ht)
	L.Push(lua.LString(body))
	L.Push(lua.LNumber(status))
	if err != nil {
		L.Push(lua.LString(err.Error()))
	} else {
		L.Push(lua.LNil)
	}
	return 4
}

// Wrapper so that scripts can scrape the contents of a GET request for subdomain names in scope.
func (s *Script) scrape(L *lua.LState) int {
	ctx, err := extractContext(L.CheckUserData(1))
	if err != nil || contextExpired(ctx) {
		L.Push(lua.LFalse)
		return 1
	}

	opt := L.CheckTable(2)
	if opt == nil {
		L.Push(lua.LFalse)
		return 1
	}

	var data string
	if method, ok := getStringField(L, opt, "method"); ok && strings.ToLower(method) == "post" {
		if d, ok := getStringField(L, opt, "data"); ok {
			data = d
		}
	}

	url, found := getStringField(L, opt, "url")
	if !found {
		L.Push(lua.LFalse)
		return 1
	}

	hdrs := make(map[string]string)
	lv := L.GetField(opt, "headers")
	if tbl, ok := lv.(*lua.LTable); ok {
		tbl.ForEach(func(k, v lua.LValue) {
			hdrs[k.String()] = v.String()
		})
	}

	id, _ := getStringField(L, opt, "id")
	pass, _ := getStringField(L, opt, "pass")

	sucess := lua.LFalse
	if _, resp, status, err := s.req(ctx, url, data, hdrs, &http.BasicAuth{
		Username: id,
		Password: pass,
	}); err == nil && status >= 200 && status < 400 {
		if num := s.internalSendNames(ctx, resp); num > 0 {
			sucess = lua.LTrue
		}
	} else {
		s.sys.Config().Log.Print(s.String() + ": scrape: " + err.Error())
	}

	L.Push(sucess)
	return 1
}

func (s *Script) req(ctx context.Context, url, data string, hdrs http.Header, auth *http.BasicAuth) (http.Header, string, int, error) {
	cfg := s.sys.Config()
	// Check for cached responses first
	dsc := cfg.GetDataSourceConfig(s.String())
	if dsc != nil && dsc.TTL > 0 {
		if r, err := s.getCachedResponse(ctx, url+data, dsc.TTL); err == nil {
			// TODO: Headers and status codes eventually need to be cached as well
			return nil, r, 200, err
		}
	}

	var b io.Reader
	if data != "" {
		b = strings.NewReader(data)
	}

	numRateLimitChecks(s, s.seconds)
	headers, body, status, err := http.RequestWebPage(ctx, url, b, hdrs, auth)
	if err != nil {
		if cfg.Verbose {
			cfg.Log.Printf("%s: %s: %v", s.String(), url, err)
		}
	} else if dsc != nil && dsc.TTL > 0 && status == 200 {
		_ = s.setCachedResponse(ctx, url+data, body)
	}
	return headers, body, status, err
}

// Wrapper so that scripts can crawl for subdomain names in scope.
func (s *Script) crawl(L *lua.LState) int {
	cfg := s.sys.Config()
	ctx, err := extractContext(L.CheckUserData(1))
	if err != nil || contextExpired(ctx) {
		return 0
	}

	u := L.CheckString(2)
	if u != "" {
		var names []string
		max := L.CheckInt(3)

		names, err = http.Crawl(ctx, u, cfg.Domains(), max)
		if err == nil {
			for _, name := range names {
				genNewName(ctx, s.sys, s, http.CleanName(name))
			}
		}
	}

	if err != nil && cfg.Verbose {
		cfg.Log.Printf("%s: %s: %v", s.String(), u, err)
	}
	return 0
}
