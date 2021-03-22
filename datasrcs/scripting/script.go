// Copyright 2017-2021 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package scripting

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"time"

	"github.com/OWASP/Amass/v3/config"
	"github.com/OWASP/Amass/v3/net/dns"
	"github.com/OWASP/Amass/v3/requests"
	"github.com/OWASP/Amass/v3/systems"
	"github.com/caffix/eventbus"
	"github.com/caffix/service"
	luaurl "github.com/cjoudrey/gluaurl"
	lua "github.com/yuin/gopher-lua"
	luajson "layeh.com/gopher-json"
)

// Script is the Service that handles access to the Script data source.
type Script struct {
	service.BaseService

	SourceType string
	sys        systems.System
	luaState   *lua.LState
	// Script callback functions
	start      lua.LValue
	stop       lua.LValue
	check      lua.LValue
	vertical   lua.LValue
	horizontal lua.LValue
	address    lua.LValue
	asn        lua.LValue
	resolved   lua.LValue
	subdomain  lua.LValue
	// Regexp to match any subdomain name
	subre   *regexp.Regexp
	seconds int
	cancel  context.CancelFunc
}

// NewScript returns he object initialized, but not yet started.
func NewScript(script string, sys systems.System) *Script {
	re, err := regexp.Compile(dns.AnySubdomainRegexString())
	if err != nil {
		return nil
	}

	ctx, cancel := context.WithCancel(context.Background())

	s := &Script{
		sys:    sys,
		subre:  re,
		cancel: cancel,
	}

	L := s.newLuaState(sys.Config())
	s.luaState = L
	L.SetContext(ctx)

	// Load the script
	if err := L.DoString(script); err != nil {
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
	s.BaseService = *service.NewBaseService(s, name)

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
	L.SetGlobal("datasrc_config", L.NewFunction(s.dataSourceConfig))
	L.SetGlobal("brute_wordlist", L.NewFunction(s.bruteWordlist))
	L.SetGlobal("alt_wordlist", L.NewFunction(s.altWordlist))
	L.SetGlobal("log", L.NewFunction(s.log))
	L.SetGlobal("find", L.NewFunction(s.find))
	L.SetGlobal("submatch", L.NewFunction(s.submatch))
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

// Save references to the script functions that serve as callbacks for Amass events.
func (s *Script) getScriptCallbacks() {
	L := s.luaState

	s.start = L.GetGlobal("start")
	s.stop = L.GetGlobal("stop")
	s.check = L.GetGlobal("check")
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

// Description implements the Service interface.
func (s *Script) Description() string {
	return s.SourceType
}

// OnStart implements the Service interface.
func (s *Script) OnStart() error {
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

	s.SetRateLimit(1)
	return s.checkConfig()
}

// OnStop implements the Service interface.
func (s *Script) OnStop() error {
	defer func() {
		s.cancel()
		s.luaState.Close()
	}()

	L := s.luaState
	if s.stop.Type() == lua.LTNil {
		return nil
	}

	for L.Status(L) == "running" {
		time.Sleep(250 * time.Millisecond)
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

func (s *Script) checkConfig() error {
	L := s.luaState

	if s.check.Type() == lua.LTNil {
		return nil
	}

	err := L.CallByParam(lua.P{
		Fn:      s.check,
		NRet:    1,
		Protect: true,
	})
	if err != nil {
		estr := fmt.Sprintf("%s: check callback: %v", s.String(), err)

		s.sys.Config().Log.Print(estr)
		return errors.New(estr)
	}

	ret := L.Get(-1)
	L.Pop(1)

	passed, ok := ret.(lua.LBool)
	if ok && bool(passed) {
		return nil
	}

	estr := fmt.Sprintf("%s: check callback failed for the configuration", s.String())
	s.sys.Config().Log.Print(estr)
	return errors.New(estr)
}

// OnRequest implements the Service interface.
func (s *Script) OnRequest(ctx context.Context, args service.Args) {
	var check bool

	switch req := args.(type) {
	case *requests.DNSRequest:
		if s.vertical.Type() != lua.LTNil && req != nil && req.Domain != "" {
			s.dnsRequest(ctx, req)
			check = true
		}
	case *requests.ResolvedRequest:
		if s.resolved.Type() != lua.LTNil && req != nil && req.Name != "" && len(req.Records) > 0 {
			s.resolvedRequest(ctx, req)
			check = true
		}
	case *requests.SubdomainRequest:
		if s.subdomain.Type() != lua.LTNil && req != nil && req.Name != "" {
			s.subdomainRequest(ctx, req)
			check = true
		}
	case *requests.AddrRequest:
		if s.address.Type() != lua.LTNil && req != nil && req.Address != "" {
			s.addrRequest(ctx, req)
			check = true
		}
	case *requests.ASNRequest:
		if s.asn.Type() != lua.LTNil && req != nil && (req.Address != "" || req.ASN != 0) {
			s.asnRequest(ctx, req)
			check = true
		}
	case *requests.WhoisRequest:
		if s.horizontal.Type() != lua.LTNil {
			s.whoisRequest(ctx, req)
			check = true
		}
	}

	if check {
		numRateLimitChecks(s, s.seconds)
	}
}

func (s *Script) dnsRequest(ctx context.Context, req *requests.DNSRequest) {
	L := s.luaState

	if err := checkContextExpired(ctx); err != nil {
		return
	}

	_, bus, err := requests.ContextConfigBus(ctx)
	if err != nil {
		return
	}

	bus.Publish(requests.LogTopic, eventbus.PriorityHigh,
		fmt.Sprintf("Querying %s for %s subdomains", s.String(), req.Domain))

	err = L.CallByParam(lua.P{
		Fn:      s.vertical,
		NRet:    0,
		Protect: true,
	}, s.contextToUserData(ctx), lua.LString(req.Domain))

	if err != nil {
		bus.Publish(requests.LogTopic, eventbus.PriorityHigh,
			fmt.Sprintf("%s: vertical callback: %v", s.String(), err))
	}
}

func (s *Script) resolvedRequest(ctx context.Context, req *requests.ResolvedRequest) {
	L := s.luaState

	if err := checkContextExpired(ctx); err != nil {
		return
	}

	_, bus, err := requests.ContextConfigBus(ctx)
	if err != nil {
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

	err = L.CallByParam(lua.P{
		Fn:      s.resolved,
		NRet:    0,
		Protect: true,
	}, s.contextToUserData(ctx), lua.LString(req.Name), lua.LString(req.Domain), records)

	if err != nil {
		bus.Publish(requests.LogTopic, eventbus.PriorityHigh,
			fmt.Sprintf("%s: resolved callback: %v", s.String(), err))
	}
}

func (s *Script) subdomainRequest(ctx context.Context, req *requests.SubdomainRequest) {
	L := s.luaState

	if err := checkContextExpired(ctx); err != nil {
		return
	}

	_, bus, err := requests.ContextConfigBus(ctx)
	if err != nil {
		return
	}

	err = L.CallByParam(lua.P{
		Fn:      s.subdomain,
		NRet:    0,
		Protect: true,
	}, s.contextToUserData(ctx), lua.LString(req.Name), lua.LString(req.Domain), lua.LNumber(req.Times))

	if err != nil {
		bus.Publish(requests.LogTopic, eventbus.PriorityHigh,
			fmt.Sprintf("%s: subdomain callback: %v", s.String(), err))
	}
}

func (s *Script) addrRequest(ctx context.Context, req *requests.AddrRequest) {
	L := s.luaState

	if err := checkContextExpired(ctx); err != nil {
		return
	}

	_, bus, err := requests.ContextConfigBus(ctx)
	if err != nil {
		return
	}

	err = L.CallByParam(lua.P{
		Fn:      s.address,
		NRet:    0,
		Protect: true,
	}, s.contextToUserData(ctx), lua.LString(req.Address))

	if err != nil {
		bus.Publish(requests.LogTopic, eventbus.PriorityHigh,
			fmt.Sprintf("%s: address callback: %v", s.String(), err))
	}
}

func (s *Script) asnRequest(ctx context.Context, req *requests.ASNRequest) {
	L := s.luaState

	if err := checkContextExpired(ctx); err != nil {
		return
	}

	_, bus, err := requests.ContextConfigBus(ctx)
	if err != nil {
		return
	}

	err = L.CallByParam(lua.P{
		Fn:      s.asn,
		NRet:    0,
		Protect: true,
	}, s.contextToUserData(ctx), lua.LString(req.Address), lua.LNumber(req.ASN))

	if err != nil {
		bus.Publish(requests.LogTopic, eventbus.PriorityHigh,
			fmt.Sprintf("%s: asn callback: %v", s.String(), err))
	}
}

func (s *Script) whoisRequest(ctx context.Context, req *requests.WhoisRequest) {
	L := s.luaState

	if err := checkContextExpired(ctx); err != nil {
		return
	}

	_, bus, err := requests.ContextConfigBus(ctx)
	if err != nil {
		return
	}

	err = L.CallByParam(lua.P{
		Fn:      s.horizontal,
		NRet:    0,
		Protect: true,
	}, s.contextToUserData(ctx), lua.LString(req.Domain))

	if err != nil {
		bus.Publish(requests.LogTopic, eventbus.PriorityHigh,
			fmt.Sprintf("%s: horizontal callback: %v", s.String(), err))
	}
}
