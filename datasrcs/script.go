// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package datasrcs

import (
	"context"
	"errors"
	"fmt"

	"github.com/OWASP/Amass/v3/config"
	"github.com/OWASP/Amass/v3/eventbus"
	"github.com/OWASP/Amass/v3/net/dns"
	"github.com/OWASP/Amass/v3/requests"
	"github.com/OWASP/Amass/v3/systems"
	luaurl "github.com/cjoudrey/gluaurl"
	lua "github.com/yuin/gopher-lua"
	luajson "layeh.com/gopher-json"
)

// Script is the Service that handles access to the Script data source.
type Script struct {
	requests.BaseService

	SourceType string
	sys        systems.System
	luaState   *lua.LState
	// Script callback functions
	start      lua.LValue
	stop       lua.LValue
	vertical   lua.LValue
	horizontal lua.LValue
	address    lua.LValue
	asn        lua.LValue
	resolved   lua.LValue
	subdomain  lua.LValue
}

// NewScript returns he object initialized, but not yet started.
func NewScript(script string, sys systems.System) *Script {
	s := &Script{sys: sys}
	L := s.newLuaState(sys.Config())
	s.luaState = L

	// Load the script
	err := L.DoString(script)
	if err != nil {
		msg := fmt.Sprintf("Script: Failed to load script: %v", err)

		sys.Config().Log.Print(msg)
		return nil
	}

	// Pull the script type from the script
	s.SourceType, err = s.scriptType()
	if err != nil {
		msg := fmt.Sprintf("Script: Failed to obtain the script type: %v", err)

		sys.Config().Log.Print(msg)
		return nil
	}

	// Pull the script name from the script
	name, err := s.scriptName()
	if err != nil {
		msg := fmt.Sprintf("Script: Failed to obtain the script name: %v", err)

		sys.Config().Log.Print(msg)
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

	L.PreloadModule("url", luaurl.Loader)
	L.PreloadModule("json", luajson.Loader)
	L.SetGlobal("config", L.NewFunction(s.config))
	L.SetGlobal("brute_wordlist", L.NewFunction(s.bruteWordlist))
	L.SetGlobal("alt_wordlist", L.NewFunction(s.altWordlist))
	L.SetGlobal("log", L.NewFunction(s.log))
	L.SetGlobal("find", L.NewFunction(s.find))
	L.SetGlobal("submatch", L.NewFunction(s.submatch))
	L.SetGlobal("active", L.NewFunction(s.active))
	L.SetGlobal("newname", L.NewFunction(s.newName))
	L.SetGlobal("newaddr", L.NewFunction(s.newAddr))
	L.SetGlobal("newasn", L.NewFunction(s.newASN))
	L.SetGlobal("associated", L.NewFunction(s.associated))
	L.SetGlobal("inscope", L.NewFunction(s.inScope))
	L.SetGlobal("request", L.NewFunction(s.request))
	L.SetGlobal("scrape", L.NewFunction(s.scrape))
	L.SetGlobal("crawl", L.NewFunction(s.crawl))
	L.SetGlobal("outputdir", L.NewFunction(s.outputdir))
	L.SetGlobal("setratelimit", L.NewFunction(s.setRateLimit))
	L.SetGlobal("checkratelimit", L.NewFunction(s.checkRateLimit))
	L.SetGlobal("obtain_response", L.NewFunction(s.obtainResponse))
	L.SetGlobal("cache_response", L.NewFunction(s.cacheResponse))
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
	if api.TTL != 0 {
		tb.RawSetString("ttl", lua.LNumber(api.TTL))
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
	s.subdomain = L.GetGlobal("subdomain")
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

	err := L.CallByParam(lua.P{
		Fn:      s.start,
		NRet:    0,
		Protect: true,
	})

	if err != nil {
		s.sys.Config().Log.Print(fmt.Sprintf("%s: start callback: %v", s.String(), err))
	}
	return nil
}

// OnStop implements the Service interface.
func (s *Script) OnStop() error {
	defer s.luaState.Close()

	L := s.luaState
	if s.stop.Type() == lua.LTNil {
		return nil
	}

	err := L.CallByParam(lua.P{
		Fn:      s.stop,
		NRet:    0,
		Protect: true,
	})
	if err != nil {
		estr := fmt.Sprintf("%s: stop callback: %v", s.String(), err)

		s.sys.Config().Log.Print(estr)
		return errors.New(estr)
	}

	return nil
}

// OnDNSRequest implements the Service interface.
func (s *Script) OnDNSRequest(ctx context.Context, req *requests.DNSRequest) {
	L := s.luaState

	if s.vertical.Type() == lua.LTNil || req == nil || req.Domain == "" {
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

	err := L.CallByParam(lua.P{
		Fn:      s.vertical,
		NRet:    0,
		Protect: true,
	}, s.contextToUserData(ctx), lua.LString(req.Domain))

	if err != nil {
		bus.Publish(requests.LogTopic, eventbus.PriorityHigh,
			fmt.Sprintf("%s: vertical callback: %v", s.String(), err))
	}
}

// OnResolved implements the Service interface.
func (s *Script) OnResolved(ctx context.Context, req *requests.DNSRequest) {
	L := s.luaState

	if s.resolved.Type() == lua.LTNil || req == nil || req.Name == "" || len(req.Records) == 0 {
		return
	}

	cfg := ctx.Value(requests.ContextConfig).(*config.Config)
	bus := ctx.Value(requests.ContextEventBus).(*eventbus.EventBus)
	if cfg == nil || bus == nil {
		return
	}

	records := L.NewTable()
	for _, rec := range req.Records {
		tb := L.NewTable()

		tb.RawSetString("rrname", lua.LString(rec.Name))
		tb.RawSetString("rrtype", lua.LNumber(rec.Type))
		tb.RawSetString("rrdata", lua.LString(rec.Data))
		records.Append(tb)
	}

	s.CheckRateLimit()
	err := L.CallByParam(lua.P{
		Fn:      s.resolved,
		NRet:    0,
		Protect: true,
	}, s.contextToUserData(ctx), lua.LString(req.Name), lua.LString(req.Domain), records)

	if err != nil {
		bus.Publish(requests.LogTopic, eventbus.PriorityHigh,
			fmt.Sprintf("%s: resolved callback: %v", s.String(), err))
	}
}

// OnSubdomainDiscovered implements the Service interface.
func (s *Script) OnSubdomainDiscovered(ctx context.Context, req *requests.DNSRequest, times int) {
	L := s.luaState

	if s.subdomain.Type() == lua.LTNil || req == nil || req.Name == "" {
		return
	}

	cfg := ctx.Value(requests.ContextConfig).(*config.Config)
	bus := ctx.Value(requests.ContextEventBus).(*eventbus.EventBus)
	if cfg == nil || bus == nil {
		return
	}

	s.CheckRateLimit()
	err := L.CallByParam(lua.P{
		Fn:      s.subdomain,
		NRet:    0,
		Protect: true,
	}, s.contextToUserData(ctx), lua.LString(req.Name), lua.LString(req.Domain), lua.LNumber(times))

	if err != nil {
		bus.Publish(requests.LogTopic, eventbus.PriorityHigh,
			fmt.Sprintf("%s: subdomain callback: %v", s.String(), err))
	}
}

// OnAddrRequest implements the Service interface.
func (s *Script) OnAddrRequest(ctx context.Context, req *requests.AddrRequest) {
	L := s.luaState

	if s.address.Type() == lua.LTNil || req == nil || req.Address == "" {
		return
	}

	cfg := ctx.Value(requests.ContextConfig).(*config.Config)
	bus := ctx.Value(requests.ContextEventBus).(*eventbus.EventBus)
	if cfg == nil || bus == nil {
		return
	}

	s.CheckRateLimit()
	bus.Publish(requests.SetActiveTopic, eventbus.PriorityCritical, s.String())

	err := L.CallByParam(lua.P{
		Fn:      s.address,
		NRet:    0,
		Protect: true,
	}, s.contextToUserData(ctx), lua.LString(req.Address))

	if err != nil {
		bus.Publish(requests.LogTopic, eventbus.PriorityHigh,
			fmt.Sprintf("%s: address callback: %v", s.String(), err))
	}
}

// OnASNRequest implements the Service interface.
func (s *Script) OnASNRequest(ctx context.Context, req *requests.ASNRequest) {
	L := s.luaState

	if s.asn.Type() == lua.LTNil || req == nil || req.Address == "" {
		return
	}

	cfg := ctx.Value(requests.ContextConfig).(*config.Config)
	bus := ctx.Value(requests.ContextEventBus).(*eventbus.EventBus)
	if cfg == nil || bus == nil {
		return
	}

	s.CheckRateLimit()
	bus.Publish(requests.SetActiveTopic, eventbus.PriorityCritical, s.String())

	err := L.CallByParam(lua.P{
		Fn:      s.asn,
		NRet:    0,
		Protect: true,
	}, s.contextToUserData(ctx), lua.LString(req.Address))

	if err != nil {
		bus.Publish(requests.LogTopic, eventbus.PriorityHigh,
			fmt.Sprintf("%s: asn callback: %v", s.String(), err))
	}
}

// OnWhoisRequest implements the Service interface.
func (s *Script) OnWhoisRequest(ctx context.Context, req *requests.WhoisRequest) {
	L := s.luaState

	if s.horizontal.Type() == lua.LTNil {
		return
	}

	cfg := ctx.Value(requests.ContextConfig).(*config.Config)
	bus := ctx.Value(requests.ContextEventBus).(*eventbus.EventBus)
	if cfg == nil || bus == nil {
		return
	}

	s.CheckRateLimit()
	bus.Publish(requests.SetActiveTopic, eventbus.PriorityCritical, s.String())

	err := L.CallByParam(lua.P{
		Fn:      s.horizontal,
		NRet:    0,
		Protect: true,
	}, s.contextToUserData(ctx), lua.LString(req.Domain))

	if err != nil {
		bus.Publish(requests.LogTopic, eventbus.PriorityHigh,
			fmt.Sprintf("%s: horizontal callback: %v", s.String(), err))
	}
}

func (s *Script) getCachedResponse(url string, ttl int) (string, error) {
	for _, db := range s.sys.GraphDatabases() {
		if resp, err := db.GetSourceData(s.String(), url, ttl); err == nil {
			// Allow the data source to accept another request immediately on cache hits
			s.ClearLast()
			return resp, err
		}
	}

	return "", fmt.Errorf("Failed to obtain a cached response for %s", url)
}

func (s *Script) setCachedResponse(url, resp string) error {
	for _, db := range s.sys.GraphDatabases() {
		db.CacheSourceData(s.String(), s.SourceType, url, resp)
	}

	return nil
}
