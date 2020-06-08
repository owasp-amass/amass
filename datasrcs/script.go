// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package datasrcs

import (
	"context"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/OWASP/Amass/v3/config"
	"github.com/OWASP/Amass/v3/eventbus"
	"github.com/OWASP/Amass/v3/net/dns"
	"github.com/OWASP/Amass/v3/net/http"
	"github.com/OWASP/Amass/v3/requests"
	"github.com/OWASP/Amass/v3/systems"
	lua "github.com/yuin/gopher-lua"
	luajson "layeh.com/gopher-json"
)

type contextWrapper struct {
	Ctx context.Context
}

// Script is the Service that handles access to the Script data source.
type Script struct {
	requests.BaseService

	SourceType string
	luaState   *lua.LState
	// Script callback functions
	start      lua.LValue
	stop       lua.LValue
	vertical   lua.LValue
	horizontal lua.LValue
	address    lua.LValue
	asn        lua.LValue
	resolved   lua.LValue
}

// NewScript returns he object initialized, but not yet started.
func NewScript(script string, sys systems.System) *Script {
	s := new(Script)
	L := s.newLuaState(sys.Config())
	s.luaState = L

	// Load the script
	err := L.DoString(script)
	if err != nil {
		return nil
	}

	// Pull the script type from the script
	s.SourceType, err = s.scriptType()
	if err != nil {
		return nil
	}

	// Pull the script name from the script
	name, err := s.scriptName()
	if err != nil {
		return nil
	}
	s.BaseService = *requests.NewBaseService(s, name)

	// Acquire API authentication info and make it global in the script
	s.registerAPIKey(L, sys.Config())
	// Save references to the callbacks defined within the script
	s.getScriptCallbacks()
	return s
}

// Setup the Lua state with desired constraints and access to necessary functionality.
func (s *Script) newLuaState(cfg *config.Config) *lua.LState {
	L := lua.NewState()

	L.PreloadModule("json", luajson.Loader)
	L.SetGlobal("log", L.NewFunction(s.log))
	L.SetGlobal("year", L.NewFunction(s.year))
	L.SetGlobal("find", L.NewFunction(s.find))
	L.SetGlobal("submatch", L.NewFunction(s.submatch))
	L.SetGlobal("active", L.NewFunction(s.active))
	L.SetGlobal("newname", L.NewFunction(s.newName))
	L.SetGlobal("newaddr", L.NewFunction(s.newAddr))
	L.SetGlobal("inscope", L.NewFunction(s.inScope))
	L.SetGlobal("request", L.NewFunction(s.request))
	L.SetGlobal("scrape", L.NewFunction(s.scrape))
	L.SetGlobal("crawl", L.NewFunction(s.crawl))
	L.SetGlobal("setratelimit", L.NewFunction(s.setRateLimit))
	L.SetGlobal("checkratelimit", L.NewFunction(s.checkRateLimit))
	L.SetGlobal("subdomainre", lua.LString(dns.AnySubdomainRegexString()))
	return L
}

// Fetch provided API authentication information and provide to the script as a global table.
func (s *Script) registerAPIKey(L *lua.LState, cfg *config.Config) {
	api := cfg.GetAPIKey(s.String())
	if api == nil {
		return
	}

	tb := L.NewTable()
	if api.Username != "" {
		tb.RawSetString("username", lua.LString(api.Username))
	}
	if api.Password != "" {
		tb.RawSetString("password", lua.LString(api.Password))
	}
	if api.Key != "" {
		tb.RawSetString("key", lua.LString(api.Key))
	}
	if api.Secret != "" {
		tb.RawSetString("secret", lua.LString(api.Secret))
	}

	L.SetGlobal("api", tb)
}

// Save references to the script functions that serve as callbacks for Amass events.
func (s *Script) getScriptCallbacks() {
	L := s.luaState

	s.start = L.GetGlobal("start")
	s.stop = L.GetGlobal("stop")
	s.vertical = L.GetGlobal("vertical")
	s.horizontal = L.GetGlobal("horizontal")
	s.address = L.GetGlobal("address")
	s.asn = L.GetGlobal("asn")
	s.resolved = L.GetGlobal("resolved")
}

// Acquires the script name of the script by accessing the global variable.
func (s *Script) scriptName() (string, error) {
	L := s.luaState

	lv := L.GetGlobal("name")
	if lv.Type() == lua.LTNil {
		return "", errors.New("Script does not contain the 'name' global")
	}

	if str, ok := lv.(lua.LString); ok {
		return string(str), nil
	}

	return "", errors.New("The script global 'name' is not a string")
}

// Acquires the script type of the script by accessing the global variable.
func (s *Script) scriptType() (string, error) {
	L := s.luaState

	lv := L.GetGlobal("type")
	if lv.Type() == lua.LTNil {
		return "", errors.New("Script does not contain the 'type' global")
	}

	if str, ok := lv.(lua.LString); ok {
		return string(str), nil
	}

	return "", errors.New("The script global 'type' is not a string")
}

// Type implements the Service interface.
func (s *Script) Type() string {
	return s.SourceType
}

// OnStart implements the Service interface.
func (s *Script) OnStart() error {
	s.BaseService.OnStart()

	L := s.luaState
	if s.start.Type() == lua.LTNil {
		return nil
	}

	L.CallByParam(lua.P{
		Fn:      s.start,
		NRet:    0,
		Protect: true,
	})
	return nil
}

// OnStop implements the Service interface.
func (s *Script) OnStop() error {
	defer s.luaState.Close()

	L := s.luaState
	if s.stop.Type() == lua.LTNil {
		return nil
	}

	L.CallByParam(lua.P{
		Fn:      s.stop,
		NRet:    0,
		Protect: true,
	})
	return nil
}

// OnDNSRequest implements the Service interface.
func (s *Script) OnDNSRequest(ctx context.Context, req *requests.DNSRequest) {
	L := s.luaState

	if s.vertical.Type() == lua.LTNil {
		return
	}

	cfg := ctx.Value(requests.ContextConfig).(*config.Config)
	bus := ctx.Value(requests.ContextEventBus).(*eventbus.EventBus)
	if cfg == nil || bus == nil {
		return
	}

	s.CheckRateLimit()
	bus.Publish(requests.SetActiveTopic, eventbus.PriorityCritical, s.String())
	bus.Publish(requests.LogTopic, eventbus.PriorityHigh,
		fmt.Sprintf("Querying %s for %s subdomains", s.String(), req.Domain))

	L.CallByParam(lua.P{
		Fn:      s.vertical,
		NRet:    0,
		Protect: true,
	}, s.contextToUserData(ctx), lua.LString(req.Domain))
}

// OnSubdomainDiscovered implements the Service interface.
func (s *Script) OnSubdomainDiscovered(ctx context.Context, req *requests.DNSRequest, times int) {
	L := s.luaState

	if s.resolved.Type() == lua.LTNil {
		return
	}

	L.CallByParam(lua.P{
		Fn:      s.resolved,
		NRet:    0,
		Protect: true,
	}, s.contextToUserData(ctx), lua.LString(req.Name))
}

// OnAddrRequest implements the Service interface.
func (s *Script) OnAddrRequest(ctx context.Context, req *requests.AddrRequest) {
	L := s.luaState

	if s.address.Type() == lua.LTNil {
		return
	}

	L.CallByParam(lua.P{
		Fn:      s.address,
		NRet:    0,
		Protect: true,
	}, s.contextToUserData(ctx), lua.LString(req.Address))
}

// OnASNRequest implements the Service interface.
func (s *Script) OnASNRequest(ctx context.Context, req *requests.ASNRequest) {
	L := s.luaState

	if s.asn.Type() == lua.LTNil {
		return
	}

	L.CallByParam(lua.P{
		Fn:      s.asn,
		NRet:    0,
		Protect: true,
	}, s.contextToUserData(ctx), lua.LNumber(req.ASN))
}

// OnWhoisRequest implements the Service interface.
func (s *Script) OnWhoisRequest(ctx context.Context, req *requests.WhoisRequest) {
	L := s.luaState

	if s.horizontal.Type() == lua.LTNil {
		return
	}

	L.CallByParam(lua.P{
		Fn:      s.horizontal,
		NRet:    0,
		Protect: true,
	}, s.contextToUserData(ctx), lua.LString(req.Domain))
}

// Wrapper so scripts can set the data source rate limit.
func (s *Script) setRateLimit(L *lua.LState) int {
	lv := L.Get(1)

	if num, ok := lv.(lua.LNumber); ok {
		sec := int(num)

		s.SetRateLimit(time.Duration(sec) * time.Second)
	}

	return 0
}

// Wrapper so scripts can block until past the data source rate limit.
func (s *Script) checkRateLimit(L *lua.LState) int {
	s.CheckRateLimit()
	return 0
}

// Wrapper so scripts can signal Amass of script activity.
func (s *Script) active(L *lua.LState) int {
	c := L.CheckUserData(1).Value.(*contextWrapper)
	bus := c.Ctx.Value(requests.ContextEventBus).(*eventbus.EventBus)
	if bus != nil {
		bus.Publish(requests.SetActiveTopic, eventbus.PriorityCritical, s.String())
	}
	return 0
}

// Wrapper so that scripts can write messages to the Amass log.
func (s *Script) log(L *lua.LState) int {
	c := L.CheckUserData(1).Value.(*contextWrapper)
	bus := c.Ctx.Value(requests.ContextEventBus).(*eventbus.EventBus)
	if bus == nil {
		return 0
	}

	lv := L.Get(2)
	if msg, ok := lv.(lua.LString); ok {
		bus.Publish(requests.LogTopic, eventbus.PriorityHigh, string(msg))
	}
	return 0
}

// Wrapper so that scripts can send discovered FQDNs to Amass.
func (s *Script) newName(L *lua.LState) int {
	c := L.CheckUserData(1).Value.(*contextWrapper)
	cfg := c.Ctx.Value(requests.ContextConfig).(*config.Config)
	bus := c.Ctx.Value(requests.ContextEventBus).(*eventbus.EventBus)
	if cfg == nil || bus == nil {
		return 0
	}

	lv := L.Get(2)
	if n, ok := lv.(lua.LString); ok {
		name := string(n)

		if domain := cfg.WhichDomain(name); domain != "" {
			bus.Publish(requests.NewNameTopic, eventbus.PriorityHigh, &requests.DNSRequest{
				Name:   cleanName(name),
				Domain: domain,
				Tag:    s.SourceType,
				Source: s.String(),
			})
		}
	}
	return 0
}

// Wrapper so that scripts can send discovered IP addresses to Amass.
func (s *Script) newAddr(L *lua.LState) int {
	c := L.CheckUserData(1).Value.(*contextWrapper)
	cfg := c.Ctx.Value(requests.ContextConfig).(*config.Config)
	bus := c.Ctx.Value(requests.ContextEventBus).(*eventbus.EventBus)
	if cfg == nil || bus == nil {
		return 0
	}

	lv := L.Get(2)
	a, ok := lv.(lua.LString)
	if !ok {
		return 0
	}
	addr := string(a)

	lv = L.Get(3)
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

// Wrapper that exposes a simple regular expression matching function.
func (s *Script) find(L *lua.LState) int {
	lv := L.Get(1)

	str, ok := lv.(lua.LString)
	if !ok {
		L.Push(lua.LNil)
		return 1
	}

	lv = L.Get(2)
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

	str, ok := lv.(lua.LString)
	if !ok {
		L.Push(lua.LNil)
		return 1
	}

	lv = L.Get(2)
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

// Converts Go Content to Lua UserData.
func (s *Script) contextToUserData(ctx context.Context) *lua.LUserData {
	L := s.luaState
	ud := L.NewUserData()

	ud.Value = &contextWrapper{Ctx: ctx}
	L.SetMetatable(ud, L.GetTypeMetatable("context"))

	return ud
}

// Wrapper so that scripts can check if a subdomain name is in scope.
func (s *Script) inScope(L *lua.LState) int {
	c := L.CheckUserData(1).Value.(*contextWrapper)
	cfg := c.Ctx.Value(requests.ContextConfig).(*config.Config)
	if cfg == nil {
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
	opt := L.CheckTable(1)

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

	page, err := http.RequestWebPage(url, body, headers, id, pass)
	if err != nil {
		L.Push(lua.LNil)
		L.Push(lua.LString(err.Error()))
		return 2
	}

	L.Push(lua.LString(page))
	L.Push(lua.LNil)
	return 2
}

// Wrapper so that scripts can scrape the contents of a GET request for subdomain names in scope.
func (s *Script) scrape(L *lua.LState) int {
	c := L.CheckUserData(1).Value.(*contextWrapper)
	cfg := c.Ctx.Value(requests.ContextConfig).(*config.Config)
	bus := c.Ctx.Value(requests.ContextEventBus).(*eventbus.EventBus)
	if cfg == nil || bus == nil {
		return 0
	}

	lv := L.Get(2)
	u, ok := lv.(lua.LString)
	if !ok {
		return 0
	}

	page, err := http.RequestWebPage(string(u), nil, nil, "", "")
	if err != nil {
		bus.Publish(requests.LogTopic, eventbus.PriorityHigh, fmt.Sprintf("%s: %s: %v", s.String(), u, err))
		return 0
	}

	re := dns.AnySubdomainRegex()
	for _, n := range re.FindAllString(page, -1) {
		name := cleanName(n)

		if domain := cfg.WhichDomain(name); domain != "" {
			bus.Publish(requests.NewNameTopic, eventbus.PriorityHigh, &requests.DNSRequest{
				Name:   name,
				Domain: domain,
				Tag:    s.SourceType,
				Source: s.String(),
			})
		}
	}

	return 0
}

// Wrapper so that scripts can crawl for subdomain names in scope.
func (s *Script) crawl(L *lua.LState) int {
	c := L.CheckUserData(1).Value.(*contextWrapper)
	cfg := c.Ctx.Value(requests.ContextConfig).(*config.Config)
	bus := c.Ctx.Value(requests.ContextEventBus).(*eventbus.EventBus)
	if cfg == nil || bus == nil {
		return 0
	}

	lv := L.Get(2)
	u, ok := lv.(lua.LString)
	if !ok {
		return 0
	}

	names, err := crawl(c.Ctx, string(u))
	if err != nil {
		bus.Publish(requests.LogTopic, eventbus.PriorityHigh, fmt.Sprintf("%s: %s: %v", s.String(), u, err))
		return 0
	}

	for _, name := range names {
		if domain := cfg.WhichDomain(name); domain != "" {
			bus.Publish(requests.NewNameTopic, eventbus.PriorityHigh, &requests.DNSRequest{
				Name:   name,
				Domain: domain,
				Tag:    s.SourceType,
				Source: s.String(),
			})
		}
	}

	return 0
}

func getStringField(L *lua.LState, t lua.LValue, key string) (string, bool) {
	lv := L.GetField(t, key)
	if s, ok := lv.(lua.LString); ok {
		return string(s), true
	}
	return "", false
}

func getNumberField(L *lua.LState, t lua.LValue, key string) (float64, bool) {
	lv := L.GetField(t, key)
	if n, ok := lv.(lua.LNumber); ok {
		return float64(n), true
	}
	return 0, false
}

// Wrapper so that archive scripts can obtain the current year as a string.
func (s *Script) year(L *lua.LState) int {
	L.Push(lua.LString(strconv.Itoa(time.Now().Year())))
	return 1
}
