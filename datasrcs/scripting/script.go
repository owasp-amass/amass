// Copyright © by Jeff Foley 2017-2023. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

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
	"github.com/caffix/queue"
	"github.com/caffix/service"
	luaurl "github.com/cjoudrey/gluaurl"
	lua "github.com/yuin/gopher-lua"
	luajson "layeh.com/gopher-json"
)

// Script callback functions
type callbacks struct {
	Start      lua.LValue
	Stop       lua.LValue
	Check      lua.LValue
	Vertical   lua.LValue
	Horizontal lua.LValue
	Address    lua.LValue
	Asn        lua.LValue
	Resolved   lua.LValue
	Subdomain  lua.LValue
}

// Script is the Service that handles access to the Script data source.
type Script struct {
	service.BaseService
	start      chan struct{}
	startRet   chan error
	stop       chan struct{}
	SourceType string
	sys        systems.System
	luaState   *lua.LState
	cbs        *callbacks
	subre      *regexp.Regexp
	seconds    int
	ctx        context.Context
	cancel     context.CancelFunc
	queue      queue.Queue
}

// NewScript returns the object initialized, but not yet started.
func NewScript(script string, sys systems.System) *Script {
	re, err := regexp.Compile(dns.AnySubdomainRegexString())
	if err != nil {
		return nil
	}

	s := &Script{
		start:    make(chan struct{}, 1),
		startRet: make(chan error, 1),
		stop:     make(chan struct{}, 1),
		sys:      sys,
		subre:    re,
		queue:    queue.NewQueue(),
	}
	s.ctx, s.cancel = context.WithCancel(context.Background())
	L := s.newLuaState(sys.Config())

	// Load the script
	if err := L.DoString(script); err != nil {
		sys.Config().Log.Printf("Script: Failed to load the %s script: %v", script, err)
		return nil
	}
	// Pull the script name from the script
	name, err := s.scriptName()
	if err != nil {
		sys.Config().Log.Printf("Script: Failed to obtain the %s script name: %v", script, err)
		return nil
	}
	// Pull the script type from the script
	s.SourceType, err = s.scriptType()
	if err != nil {
		sys.Config().Log.Printf("Script: Failed to obtain the %s script type: %v", script, err)
		return nil
	}

	s.BaseService = *service.NewBaseService(s, name)
	s.assignCallbacks()
	go s.manageOutput()
	go s.requests()
	return s
}

// Setup the Lua state with desired constraints and access to necessary functionality.
func (s *Script) newLuaState(cfg *config.Config) *lua.LState {
	L := lua.NewState(lua.Options{
		CallStackSize:       120,
		MinimizeStackMemory: true,
		RegistrySize:        32,
		RegistryMaxSize:     1024 * 100,
		RegistryGrowStep:    32,
	})
	s.luaState = L

	registerSocketType(L)
	L.PreloadModule("url", luaurl.Loader)
	L.PreloadModule("json", luajson.Loader)
	L.SetGlobal("config", L.NewFunction(s.config))
	L.SetGlobal("datasrc_config", L.NewFunction(s.dataSourceConfig))
	L.SetGlobal("brute_wordlist", L.NewFunction(s.bruteWordlist))
	L.SetGlobal("alt_wordlist", L.NewFunction(s.altWordlist))
	L.SetGlobal("log", L.NewFunction(s.log))
	L.SetGlobal("find", L.NewFunction(s.find))
	L.SetGlobal("submatch", L.NewFunction(s.submatch))
	L.SetGlobal("mtime", L.NewFunction(s.modDateTime))
	L.SetGlobal("new_name", L.NewFunction(s.newName))
	L.SetGlobal("send_names", L.NewFunction(s.sendNames))
	L.SetGlobal("new_addr", L.NewFunction(s.newAddr))
	L.SetGlobal("new_asn", L.NewFunction(s.newASN))
	L.SetGlobal("associated", L.NewFunction(s.associated))
	L.SetGlobal("in_scope", L.NewFunction(s.inScope))
	L.SetGlobal("request", L.NewFunction(s.request))
	L.SetGlobal("scrape", L.NewFunction(s.scrape))
	L.SetGlobal("crawl", L.NewFunction(s.crawl))
	L.SetGlobal("resolve", L.NewFunction(s.resolve))
	L.SetGlobal("output_dir", L.NewFunction(s.outputdir))
	L.SetGlobal("set_rate_limit", L.NewFunction(s.setRateLimit))
	L.SetGlobal("check_rate_limit", L.NewFunction(s.checkRateLimit))
	L.SetGlobal("subdomain_regex", lua.LString(dns.AnySubdomainRegexString()))
	return L
}

// Save references to the script functions that serve as callbacks for Amass events.
func (s *Script) assignCallbacks() {
	L := s.luaState

	s.cbs = &callbacks{
		Start:      L.GetGlobal("start"),
		Stop:       L.GetGlobal("stop"),
		Check:      L.GetGlobal("check"),
		Vertical:   L.GetGlobal("vertical"),
		Horizontal: L.GetGlobal("horizontal"),
		Address:    L.GetGlobal("address"),
		Asn:        L.GetGlobal("asn"),
		Resolved:   L.GetGlobal("resolved"),
		Subdomain:  L.GetGlobal("subdomain"),
	}
}

// Acquires the script name of the script by accessing the global variable.
func (s *Script) scriptName() (string, error) {
	lv := s.luaState.GetGlobal("name")

	if lv.Type() == lua.LTNil {
		return "", errors.New("Script does not contain the 'name' global")
	}
	if str, ok := lv.(lua.LString); ok {
		return string(str), nil
	}
	return "", errors.New("the script global 'name' is not a string")
}

// Acquires the script type of the script by accessing the global variable.
func (s *Script) scriptType() (string, error) {
	lv := s.luaState.GetGlobal("type")

	if lv.Type() == lua.LTNil {
		return "", errors.New("Script does not contain the 'type' global")
	}
	if str, ok := lv.(lua.LString); ok {
		return string(str), nil
	}
	return "", errors.New("the script global 'type' is not a string")
}

// Description implements the Service interface.
func (s *Script) Description() string {
	return s.SourceType
}

// OnStart implements the Service interface.
func (s *Script) OnStart() error {
	s.start <- struct{}{}
	return <-s.startRet
}

// OnStop implements the Service interface.
func (s *Script) OnStop() error {
	s.stop <- struct{}{}
	return nil
}

func (s *Script) manageOutput() {
loop:
	for {
		select {
		case <-s.Done():
			break loop
		case <-s.ctx.Done():
			break loop
		case <-s.queue.Signal():
			if element, ok := s.queue.Next(); ok {
				select {
				case <-s.Done():
					break loop
				case <-s.ctx.Done():
					break loop
				case s.Output() <- element:
				}
			}
		}
	}
	// Empty the queue
	s.queue.Process(func(e interface{}) {})
	// Empty the output channel
	for {
		select {
		case <-s.Output():
		default:
			return
		}
	}
}

func (s *Script) requests() {
	ready := make(chan struct{}, 1)
	t := time.NewTimer(100 * time.Millisecond)
	defer t.Stop()
loop:
	for {
		select {
		case <-s.Done():
			break loop
		case <-s.ctx.Done():
			break loop
		case <-s.start:
			s.startScript()
		case <-s.stop:
			s.stopScript()
		case <-ready:
			select {
			case in := <-s.Input():
				s.dispatch(in)
			default:
			}
		case <-t.C:
			if s.queue.Len() == 0 {
				select {
				case ready <- struct{}{}:
				default:
				}
			}
			t.Reset(100 * time.Millisecond)
		}
	}
	// Empty the input channel
	for {
		select {
		case <-s.Input():
		default:
			return
		}
	}
}

func (s *Script) startScript() {
	if L := s.luaState; s.cbs.Start.Type() != lua.LTNil {
		err := L.CallByParam(lua.P{
			Fn:      s.cbs.Start,
			NRet:    0,
			Protect: true,
		})
		if err != nil {
			s.sys.Config().Log.Printf("%s: start callback: %v", s.String(), err)
			s.startRet <- err
			return
		}
	}

	if s.seconds > 0 {
		s.SetRateLimit(1)
	}

	s.startRet <- s.checkConfig()
}

func (s *Script) checkConfig() error {
	L := s.luaState

	if s.cbs.Check.Type() == lua.LTNil {
		return nil
	}

	err := L.CallByParam(lua.P{
		Fn:      s.cbs.Check,
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

func (s *Script) stopScript() {
	s.cancel()

	if L := s.luaState; s.cbs.Stop.Type() != lua.LTNil {
		err := L.CallByParam(lua.P{
			Fn:      s.cbs.Stop,
			NRet:    0,
			Protect: true,
		})
		if err != nil {
			err = fmt.Errorf("%s: stop callback: %v", s.String(), err)
			s.sys.Config().Log.Print(err.Error())
		}
	}

	s.luaState.Close()
	s.luaState = nil
}

func (s *Script) dispatch(in interface{}) {
	switch req := in.(type) {
	case *requests.DNSRequest:
		if s.cbs.Vertical.Type() != lua.LTNil && req != nil && req.Domain != "" {
			s.CheckRateLimit()
			s.dnsRequest(s.ctx, req)
		}
	case *requests.ResolvedRequest:
		if s.cbs.Resolved.Type() != lua.LTNil && req != nil && req.Name != "" && len(req.Records) > 0 {
			s.CheckRateLimit()
			s.resolvedRequest(s.ctx, req)
		}
	case *requests.SubdomainRequest:
		if s.cbs.Subdomain.Type() != lua.LTNil && req != nil && req.Name != "" {
			s.CheckRateLimit()
			s.subdomainRequest(s.ctx, req)
		}
	case *requests.AddrRequest:
		if s.cbs.Address.Type() != lua.LTNil && req != nil && req.Address != "" {
			s.CheckRateLimit()
			s.addrRequest(s.ctx, req)
		}
	case *requests.ASNRequest:
		if s.cbs.Asn.Type() != lua.LTNil && req != nil && (req.Address != "" || req.ASN != 0) {
			s.CheckRateLimit()
			s.asnRequest(s.ctx, req)
		}
	case *requests.WhoisRequest:
		if s.cbs.Horizontal.Type() != lua.LTNil {
			s.CheckRateLimit()
			s.whoisRequest(s.ctx, req)
		}
	}
}

func (s *Script) dnsRequest(ctx context.Context, req *requests.DNSRequest) {
	L := s.luaState

	if contextExpired(ctx) {
		return
	}

	s.sys.Config().Log.Printf("Querying %s for %s subdomains", s.String(), req.Domain)

	err := L.CallByParam(lua.P{
		Fn:      s.cbs.Vertical,
		NRet:    0,
		Protect: true,
	}, s.contextToUserData(ctx), lua.LString(req.Domain))
	if err != nil {
		s.sys.Config().Log.Printf("%s: vertical callback: %v", s.String(), err)
	}
}

func (s *Script) resolvedRequest(ctx context.Context, req *requests.ResolvedRequest) {
	L := s.luaState

	if contextExpired(ctx) {
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

	err := L.CallByParam(lua.P{
		Fn:      s.cbs.Resolved,
		NRet:    0,
		Protect: true,
	}, s.contextToUserData(ctx), lua.LString(req.Name), lua.LString(req.Domain), records)
	if err != nil {
		s.sys.Config().Log.Printf("%s: resolved callback: %v", s.String(), err)
	}
}

func (s *Script) subdomainRequest(ctx context.Context, req *requests.SubdomainRequest) {
	L := s.luaState

	if contextExpired(ctx) {
		return
	}

	err := L.CallByParam(lua.P{
		Fn:      s.cbs.Subdomain,
		NRet:    0,
		Protect: true,
	}, s.contextToUserData(ctx), lua.LString(req.Name), lua.LString(req.Domain), lua.LNumber(req.Times))
	if err != nil {
		s.sys.Config().Log.Printf("%s: subdomain callback: %v", s.String(), err)
	}
}

func (s *Script) addrRequest(ctx context.Context, req *requests.AddrRequest) {
	L := s.luaState

	if contextExpired(ctx) {
		return
	}

	err := L.CallByParam(lua.P{
		Fn:      s.cbs.Address,
		NRet:    0,
		Protect: true,
	}, s.contextToUserData(ctx), lua.LString(req.Address))
	if err != nil {
		s.sys.Config().Log.Printf("%s: address callback: %v", s.String(), err)
	}
}

func (s *Script) asnRequest(ctx context.Context, req *requests.ASNRequest) {
	L := s.luaState

	if contextExpired(ctx) {
		return
	}

	err := L.CallByParam(lua.P{
		Fn:      s.cbs.Asn,
		NRet:    0,
		Protect: true,
	}, s.contextToUserData(ctx), lua.LString(req.Address), lua.LNumber(req.ASN))
	if err != nil {
		s.sys.Config().Log.Printf("%s: asn callback: %v", s.String(), err)
	}
}

func (s *Script) whoisRequest(ctx context.Context, req *requests.WhoisRequest) {
	L := s.luaState

	if contextExpired(ctx) {
		return
	}

	err := L.CallByParam(lua.P{
		Fn:      s.cbs.Horizontal,
		NRet:    0,
		Protect: true,
	}, s.contextToUserData(ctx), lua.LString(req.Domain))
	if err != nil {
		s.sys.Config().Log.Printf("%s: horizontal callback: %v", s.String(), err)
	}
}
