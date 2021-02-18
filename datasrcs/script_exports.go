// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package datasrcs

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"regexp"
	"strings"
	"time"

	"github.com/OWASP/Amass/v3/config"
	amassnet "github.com/OWASP/Amass/v3/net"
	"github.com/OWASP/Amass/v3/net/http"
	"github.com/OWASP/Amass/v3/requests"
	"github.com/OWASP/Amass/v3/stringfilter"
	"github.com/caffix/eventbus"
	"github.com/caffix/stringset"
	lua "github.com/yuin/gopher-lua"
)

type contextWrapper struct {
	Ctx context.Context
}

// Converts Go Context to Lua UserData.
func (s *Script) contextToUserData(ctx context.Context) *lua.LUserData {
	L := s.luaState
	ud := L.NewUserData()

	ud.Value = &contextWrapper{Ctx: ctx}
	L.SetMetatable(ud, L.GetTypeMetatable("context"))
	return ud
}

func extractContext(udata *lua.LUserData) (context.Context, error) {
	if udata == nil {
		return nil, errors.New("Lua user data was nil")
	}

	val := udata.Value
	if val == nil {
		return nil, errors.New("The user data value was nil")
	}

	wrapper, ok := val.(*contextWrapper)
	if !ok {
		return nil, errors.New("The user data was not a script context wrapper")
	}

	ctx := wrapper.Ctx
	if err := checkContextExpired(ctx); err != nil {
		return nil, err
	}

	return ctx, nil
}

// Wrapper so that scripts can obtain the configuration for the current enumeration.
func (s *Script) config(L *lua.LState) int {
	ctx, err := extractContext(L.CheckUserData(1))
	if err != nil {
		L.Push(lua.LNil)
		return 1
	}

	cfg, _, err := ContextConfigBus(ctx)
	if err != nil {
		L.Push(lua.LNil)
		return 1
	}

	r := L.NewTable()
	if cfg.Active {
		r.RawSetString("mode", lua.LString("active"))
	} else if cfg.Passive {
		r.RawSetString("mode", lua.LString("passive"))
	} else {
		r.RawSetString("mode", lua.LString("normal"))
	}

	r.RawSetString("event_id", lua.LString(cfg.UUID.String()))
	r.RawSetString("max_dns_queries", lua.LNumber(cfg.MaxDNSQueries))

	scope := L.NewTable()
	tb := L.NewTable()
	for _, domain := range cfg.Domains() {
		tb.Append(lua.LString(domain))
	}
	scope.RawSetString("domains", tb)

	tb = L.NewTable()
	for _, sub := range cfg.Blacklist {
		tb.Append(lua.LString(sub))
	}
	scope.RawSetString("blacklist", tb)

	tb = L.NewTable()
	for _, rt := range cfg.RecordTypes {
		tb.Append(lua.LString(rt))
	}
	r.RawSetString("dns_record_types", tb)

	tb = L.NewTable()
	for _, resolver := range cfg.Resolvers {
		tb.Append(lua.LString(resolver))
	}
	r.RawSetString("resolvers", tb)

	tb = L.NewTable()
	for _, name := range cfg.ProvidedNames {
		tb.Append(lua.LString(name))
	}
	r.RawSetString("provided_names", tb)

	tb = L.NewTable()
	for _, addr := range cfg.Addresses {
		tb.Append(lua.LString(addr.String()))
	}
	scope.RawSetString("addresses", tb)

	tb = L.NewTable()
	for _, cidr := range cfg.CIDRs {
		tb.Append(lua.LString(cidr.String()))
	}
	scope.RawSetString("cidrs", tb)

	tb = L.NewTable()
	for _, asn := range cfg.ASNs {
		tb.Append(lua.LNumber(asn))
	}
	scope.RawSetString("asns", tb)

	tb = L.NewTable()
	for _, port := range cfg.Ports {
		tb.Append(lua.LNumber(port))
	}
	scope.RawSetString("ports", tb)
	r.RawSetString("scope", scope)

	tb = L.NewTable()
	tb.RawSetString("active", lua.LBool(cfg.BruteForcing))
	tb.RawSetString("recursive", lua.LBool(cfg.Recursive))
	tb.RawSetString("min_for_recursive", lua.LNumber(cfg.MinForRecursive))
	r.RawSetString("brute_forcing", tb)

	tb = L.NewTable()
	tb.RawSetString("active", lua.LBool(cfg.Alterations))
	tb.RawSetString("flip_words", lua.LBool(cfg.FlipWords))
	tb.RawSetString("flip_numbers", lua.LBool(cfg.FlipNumbers))
	tb.RawSetString("add_words", lua.LBool(cfg.AddWords))
	tb.RawSetString("add_numbers", lua.LBool(cfg.AddNumbers))
	tb.RawSetString("edit_distance", lua.LNumber(cfg.EditDistance))
	r.RawSetString("alterations", tb)

	L.Push(r)
	return 1
}

func (s *Script) dataSourceConfig(L *lua.LState) int {
	cfg := s.sys.Config().GetDataSourceConfig(s.String())
	if cfg == nil {
		L.Push(lua.LNil)
		return 1
	}

	tb := L.NewTable()
	tb.RawSetString("name", lua.LString(cfg.Name))
	if cfg.TTL != 0 {
		tb.RawSetString("ttl", lua.LNumber(cfg.TTL))
	}

	if creds := cfg.GetCredentials(); creds != nil {
		c := L.NewTable()

		c.RawSetString("name", lua.LString(creds.Name))
		if creds.Username != "" {
			c.RawSetString("username", lua.LString(creds.Username))
		}
		if creds.Password != "" {
			c.RawSetString("password", lua.LString(creds.Password))
		}
		if creds.Key != "" {
			c.RawSetString("key", lua.LString(creds.Key))
		}
		if creds.Secret != "" {
			c.RawSetString("secret", lua.LString(creds.Secret))
		}
		tb.RawSetString("credentials", c)
	}

	L.Push(tb)
	return 1
}

// Wrapper so that scripts can obtain the brute force wordlist for the current enumeration.
func (s *Script) bruteWordlist(L *lua.LState) int {
	ctx, err := extractContext(L.CheckUserData(1))
	if err != nil {
		L.Push(lua.LNil)
		return 1
	}

	cfg, _, err := ContextConfigBus(ctx)
	if err != nil {
		L.Push(lua.LNil)
		return 1
	}

	tb := L.NewTable()
	for _, word := range cfg.Wordlist {
		tb.Append(lua.LString(word))
	}

	L.Push(tb)
	return 1
}

// Wrapper so that scripts can obtain the alteration wordlist for the current enumeration.
func (s *Script) altWordlist(L *lua.LState) int {
	ctx, err := extractContext(L.CheckUserData(1))
	if err != nil {
		L.Push(lua.LNil)
		return 1
	}

	cfg, _, err := ContextConfigBus(ctx)
	if err != nil {
		L.Push(lua.LNil)
		return 1
	}

	tb := L.NewTable()
	for _, word := range cfg.AltWordlist {
		tb.Append(lua.LString(word))
	}

	L.Push(tb)
	return 1
}

// Wrapper so scripts can set the data source rate limit.
func (s *Script) setRateLimit(L *lua.LState) int {
	lv := L.Get(1)
	if lv == nil {
		return 0
	}

	if num, ok := lv.(lua.LNumber); ok {
		sec := int(num)

		s.seconds = sec
	}
	return 0
}

// Wrapper so scripts can block until past the data source rate limit.
func (s *Script) checkRateLimit(L *lua.LState) int {
	numRateLimitChecks(s, s.seconds)
	return 0
}

// Wrapper so that scripts can request the path to the Amass output directory.
func (s *Script) outputdir(L *lua.LState) int {
	var dir string

	ctx, err := extractContext(L.CheckUserData(1))
	if err != nil {
		L.Push(lua.LNil)
		return 1
	}

	cfg, _, err := ContextConfigBus(ctx)
	if err == nil {
		dir = config.OutputDirectory(cfg.Dir)
	}

	L.Push(lua.LString(dir))
	return 1
}

// Wrapper so that scripts can write messages to the Amass log.
func (s *Script) log(L *lua.LState) int {
	ctx, err := extractContext(L.CheckUserData(1))
	if err != nil {
		return 0
	}

	_, bus, err := ContextConfigBus(ctx)
	if err != nil {
		return 0
	}

	lv := L.Get(2)
	if lv == nil {
		return 0
	}

	if msg, ok := lv.(lua.LString); ok {
		bus.Publish(requests.LogTopic, eventbus.PriorityHigh, s.String()+": "+string(msg))
	}
	return 0
}

// Wrapper so that scripts can send discovered FQDNs to Amass.
func (s *Script) newName(L *lua.LState) int {
	ctx, err := extractContext(L.CheckUserData(1))
	if err != nil {
		return 0
	}

	lv := L.Get(2)
	if lv == nil {
		return 0
	}

	n, ok := lv.(lua.LString)
	if !ok {
		return 0
	}

	name := s.subre.FindString(string(n))
	if name == "" {
		return 0
	}

	genNewNameEvent(ctx, s.sys, s, http.CleanName(name))
	return 0
}

// Wrapper so that scripts can send discovered IP addresses to Amass.
func (s *Script) newAddr(L *lua.LState) int {
	ctx, err := extractContext(L.CheckUserData(1))
	if err != nil {
		return 0
	}

	cfg, bus, err := ContextConfigBus(ctx)
	if err != nil {
		return 0
	}

	lv := L.Get(2)
	if lv == nil {
		return 0
	}

	a, ok := lv.(lua.LString)
	if !ok {
		return 0
	}

	addr := string(a)
	if ip := net.ParseIP(addr); ip == nil {
		return 0
	}
	if reserved, _ := amassnet.IsReservedAddress(addr); reserved {
		return 0
	}

	lv = L.Get(3)
	if lv == nil {
		return 0
	}

	sub, ok := lv.(lua.LString)
	if !ok {
		return 0
	}

	name := string(sub)
	if domain := cfg.WhichDomain(name); domain != "" {
		bus.Publish(requests.NewAddrTopic, eventbus.PriorityHigh, &requests.AddrRequest{
			Address: addr,
			Domain:  domain,
			Tag:     s.SourceType,
			Source:  s.String(),
		})
	}
	return 0
}

// Wrapper so that scripts can send discovered ASNs to Amass.
func (s *Script) newASN(L *lua.LState) int {
	ctx, err := extractContext(L.CheckUserData(1))
	if err != nil {
		return 0
	}

	_, bus, err := ContextConfigBus(ctx)
	if err != nil {
		return 0
	}

	params := L.CheckTable(2)
	if params == nil {
		return 0
	}

	addr, found := getStringField(L, params, "addr")
	if !found {
		return 0
	}
	ip := net.ParseIP(addr)
	if ip == nil {
		return 0
	}
	asn, found := getNumberField(L, params, "asn")
	if !found {
		return 0
	}
	prefix, found := getStringField(L, params, "prefix")
	if !found {
		return 0
	}
	if reserved, _ := amassnet.IsReservedAddress(ip.String()); reserved {
		return 0
	}
	desc, found := getStringField(L, params, "desc")
	if !found {
		return 0
	}
	cc, _ := getStringField(L, params, "cc")
	registry, _ := getStringField(L, params, "registry")

	netblocks := stringset.New(prefix)
	lv := L.GetField(params, "netblocks")
	if tbl, ok := lv.(*lua.LTable); ok {
		tbl.ForEach(func(_, v lua.LValue) {
			netblocks.Insert(v.String())
		})
	}

	bus.Publish(requests.NewASNTopic, eventbus.PriorityHigh, &requests.ASNRequest{
		Address:        ip.String(),
		ASN:            int(asn),
		Prefix:         prefix,
		CC:             cc,
		Registry:       registry,
		AllocationDate: time.Now(),
		Description:    desc,
		Netblocks:      netblocks,
		Tag:            s.SourceType,
		Source:         s.String(),
	})
	return 0
}

// Wrapper so that scripts can send discovered associated domains to Amass.
func (s *Script) associated(L *lua.LState) int {
	ctx, err := extractContext(L.CheckUserData(1))
	if err != nil {
		return 0
	}

	_, bus, err := ContextConfigBus(ctx)
	if err != nil {
		return 0
	}

	lv := L.Get(2)
	if lv == nil {
		return 0
	}

	d, ok := lv.(lua.LString)
	if !ok {
		return 0
	}
	domain := string(d)

	lv = L.Get(3)
	if lv == nil {
		return 0
	}

	a, ok := lv.(lua.LString)
	if !ok {
		return 0
	}
	assoc := string(a)

	if domain != "" && assoc != "" {
		bus.Publish(requests.NewWhoisTopic, eventbus.PriorityHigh, &requests.WhoisRequest{
			Domain:     domain,
			NewDomains: []string{assoc},
			Tag:        s.SourceType,
			Source:     s.String(),
		})
	}
	return 0
}

// Wrapper that exposes a simple regular expression matching function.
func (s *Script) find(L *lua.LState) int {
	lv := L.Get(1)
	if lv == nil {
		L.Push(lua.LNil)
		return 1
	}

	str, ok := lv.(lua.LString)
	if !ok {
		L.Push(lua.LNil)
		return 1
	}

	lv = L.Get(2)
	if lv == nil {
		L.Push(lua.LNil)
		return 1
	}

	pattern, ok := lv.(lua.LString)
	if !ok {
		L.Push(lua.LNil)
		return 1
	}

	re, err := regexp.Compile(string(pattern))
	if err != nil {
		L.Push(lua.LNil)
		return 1
	}

	tb := L.NewTable()
	for _, name := range re.FindAllString(string(str), -1) {
		tb.Append(lua.LString(name))
	}

	L.Push(tb)
	return 1
}

// Wrapper that exposes a regular expression matching function that supports submatches.
func (s *Script) submatch(L *lua.LState) int {
	lv := L.Get(1)
	if lv == nil {
		L.Push(lua.LNil)
		return 1
	}

	str, ok := lv.(lua.LString)
	if !ok {
		L.Push(lua.LNil)
		return 1
	}

	lv = L.Get(2)
	if lv == nil {
		L.Push(lua.LNil)
		return 1
	}

	pattern, ok := lv.(lua.LString)
	if !ok {
		L.Push(lua.LNil)
		return 1
	}

	re, err := regexp.Compile(string(pattern))
	if err != nil {
		L.Push(lua.LNil)
		return 1
	}

	matches := re.FindStringSubmatch(string(str))
	if matches == nil {
		L.Push(lua.LNil)
		return 1
	}

	tb := L.NewTable()
	for _, match := range matches {
		tb.Append(lua.LString(match))
	}

	L.Push(tb)
	return 1
}

// Wrapper so that scripts can check if a subdomain name is in scope.
func (s *Script) inScope(L *lua.LState) int {
	ctx, err := extractContext(L.CheckUserData(1))
	if err != nil {
		L.Push(lua.LFalse)
		return 1
	}

	cfg, _, err := ContextConfigBus(ctx)
	if err != nil {
		L.Push(lua.LFalse)
		return 1
	}

	lv := L.Get(2)
	if sub, ok := lv.(lua.LString); ok && cfg.IsDomainInScope(string(sub)) {
		L.Push(lua.LTrue)
		return 1
	}

	L.Push(lua.LFalse)
	return 1
}

// Wrapper that allows scripts to make HTTP client requests.
func (s *Script) request(L *lua.LState) int {
	ctx, err := extractContext(L.CheckUserData(1))
	if err != nil {
		L.Push(lua.LNil)
		L.Push(lua.LString("The user data parameter was not provided"))
		return 2
	}

	cfg, bus, err := ContextConfigBus(ctx)
	if err != nil {
		L.Push(lua.LNil)
		L.Push(lua.LString("No config and event bus values in context"))
		return 2
	}

	opt := L.CheckTable(2)
	if opt == nil {
		L.Push(lua.LNil)
		L.Push(lua.LString("No table parameter was provided"))
		return 2
	}

	var body io.Reader
	if method, ok := getStringField(L, opt, "method"); ok && (method == "POST" || method == "post") {
		if data, ok := getStringField(L, opt, "data"); ok {
			body = strings.NewReader(data)
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

	page, err := http.RequestWebPage(ctx, url, body, headers,
		&http.BasicAuth{
			Username: id,
			Password: pass,
		})
	if err != nil {
		if cfg.Verbose {
			bus.Publish(requests.LogTopic, eventbus.PriorityHigh, fmt.Sprintf("%s: %s: %v", s.String(), url, err))
		}
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

	cfg, bus, err := ContextConfigBus(ctx)
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

	var resp string
	// Check for cached responses first
	dsc := s.sys.Config().GetDataSourceConfig(s.String())
	if dsc != nil && dsc.TTL > 0 {
		if r, err := s.getCachedResponse(url, dsc.TTL); err == nil {
			resp = r
		}
	}

	if resp == "" {
		resp, err = http.RequestWebPage(ctx, url, nil, headers,
			&http.BasicAuth{
				Username: id,
				Password: pass,
			})
		if err != nil {
			if cfg.Verbose {
				bus.Publish(requests.LogTopic, eventbus.PriorityHigh, fmt.Sprintf("%s: %s: %v", s.String(), url, err))
			}
			L.Push(lua.LFalse)
			return 1
		}

		if dsc != nil && dsc.TTL > 0 {
			_ = s.setCachedResponse(url, resp)
		}
	}

	found = false
	filter := stringfilter.NewStringFilter()
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

// Wrapper so that scripts can crawl for subdomain names in scope.
func (s *Script) crawl(L *lua.LState) int {
	ctx, err := extractContext(L.CheckUserData(1))
	if err != nil {
		return 0
	}

	cfg, bus, err := ContextConfigBus(ctx)
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

func getStringField(L *lua.LState, t lua.LValue, key string) (string, bool) {
	if lv := L.GetField(t, key); lv != nil {
		if s, ok := lv.(lua.LString); ok {
			return string(s), true
		}
	}
	return "", false
}

func getNumberField(L *lua.LState, t lua.LValue, key string) (float64, bool) {
	if lv := L.GetField(t, key); lv != nil {
		if n, ok := lv.(lua.LNumber); ok {
			return float64(n), true
		}
	}
	return 0, false
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
