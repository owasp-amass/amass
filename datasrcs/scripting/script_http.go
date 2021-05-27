// Copyright 2017-2021 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package scripting

import (
	"context"
	"fmt"
	"io"
	"strings"

	"github.com/OWASP/Amass/v3/filter"
	"github.com/OWASP/Amass/v3/net/http"
	"github.com/OWASP/Amass/v3/requests"
	"github.com/caffix/eventbus"
	lua "github.com/yuin/gopher-lua"
)

// Wrapper that allows scripts to make HTTP client requests.
func (s *Script) request(L *lua.LState) int {
	ctx, err := extractContext(L.CheckUserData(1))
	if err != nil {
		L.Push(lua.LNil)
		L.Push(lua.LString("The user data parameter was not provided"))
		return 2
	}

	opt := L.CheckTable(2)
	if opt == nil {
		L.Push(lua.LNil)
		L.Push(lua.LString("No table parameter was provided"))
		return 2
	}

	var data string
	if method, ok := getStringField(L, opt, "method"); ok && (method == "POST" || method == "post") {
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

	headers := make(map[string]string)
	lv := L.GetField(opt, "headers")
	if tbl, ok := lv.(*lua.LTable); ok {
		tbl.ForEach(func(k, v lua.LValue) {
			headers[k.String()] = v.String()
		})
	}

	id, _ := getStringField(L, opt, "id")
	pass, _ := getStringField(L, opt, "pass")

	page, err := s.req(ctx, url, data, headers, &http.BasicAuth{
		Username: id,
		Password: pass,
	})
	if err != nil {
		L.Push(lua.LString(page))
		L.Push(lua.LString(err.Error()))
		return 2
	}

	L.Push(lua.LString(page))
	L.Push(lua.LNil)
	return 2
}

// Wrapper so that scripts can scrape the contents of a GET request for subdomain names in scope.
func (s *Script) scrape(L *lua.LState) int {
	ctx, err := extractContext(L.CheckUserData(1))
	if err != nil {
		L.Push(lua.LFalse)
		return 1
	}

	cfg, _, err := requests.ContextConfigBus(ctx)
	if err != nil {
		L.Push(lua.LFalse)
		return 1
	}

	opt := L.CheckTable(2)
	if opt == nil {
		L.Push(lua.LFalse)
		return 1
	}

	url, found := getStringField(L, opt, "url")
	if !found {
		L.Push(lua.LFalse)
		return 1
	}

	headers := make(map[string]string)
	lv := L.GetField(opt, "headers")
	if tbl, ok := lv.(*lua.LTable); ok {
		tbl.ForEach(func(k, v lua.LValue) {
			headers[k.String()] = v.String()
		})
	}

	id, _ := getStringField(L, opt, "id")
	pass, _ := getStringField(L, opt, "pass")

	resp, err := s.req(ctx, url, "", headers, &http.BasicAuth{
		Username: id,
		Password: pass,
	})
	if err != nil {
		L.Push(lua.LFalse)
		return 1
	}

	found = false
	filter := filter.NewStringFilter()
	for _, name := range s.subre.FindAllString(resp, -1) {
		if d := cfg.WhichDomain(name); d == "" || d == name {
			continue
		}

		found = true
		if !filter.Duplicate(name) {
			genNewNameEvent(ctx, s.sys, s, http.CleanName(name))
		}
	}

	if found {
		L.Push(lua.LTrue)
	} else {
		L.Push(lua.LFalse)
	}
	return 1
}

func (s *Script) req(ctx context.Context, url, data string, headers map[string]string, auth *http.BasicAuth) (string, error) {
	cfg, bus, err := requests.ContextConfigBus(ctx)
	if err != nil {
		return "", err
	}

	// Check for cached responses first
	dsc := s.sys.Config().GetDataSourceConfig(s.String())
	if dsc != nil && dsc.TTL > 0 {
		if r, err := s.getCachedResponse(url+data, dsc.TTL); err == nil {
			return r, err
		}
	}

	var body io.Reader
	if data != "" {
		body = strings.NewReader(data)
	}

	numRateLimitChecks(s, s.seconds)
	resp, err := http.RequestWebPage(ctx, url, body, headers, auth)
	if err != nil {
		if cfg.Verbose {
			bus.Publish(requests.LogTopic, eventbus.PriorityHigh, fmt.Sprintf("%s: %s: %v", s.String(), url, err))
		}
	} else if dsc != nil && dsc.TTL > 0 {
		_ = s.setCachedResponse(url+data, resp)
	}

	return resp, err
}

// Wrapper so that scripts can crawl for subdomain names in scope.
func (s *Script) crawl(L *lua.LState) int {
	ctx, err := extractContext(L.CheckUserData(1))
	if err != nil {
		return 0
	}

	cfg, bus, err := requests.ContextConfigBus(ctx)
	if err != nil {
		return 0
	}

	lv := L.Get(2)
	if lv == nil {
		return 0
	}

	u, ok := lv.(lua.LString)
	if !ok {
		return 0
	}

	lv = L.Get(3)
	if lv == nil {
		return 0
	}

	max, ok := lv.(lua.LNumber)
	if !ok {
		return 0
	}

	names, err := http.Crawl(ctx, string(u), cfg.Domains(), int(max), nil)
	if err != nil {
		if cfg.Verbose {
			bus.Publish(requests.LogTopic, eventbus.PriorityHigh, fmt.Sprintf("%s: %s: %v", s.String(), u, err))
		}
		return 0
	}

	for _, name := range names {
		genNewNameEvent(ctx, s.sys, s, http.CleanName(name))
	}

	return 0
}
