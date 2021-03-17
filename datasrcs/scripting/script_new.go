// Copyright 2017-2021 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package scripting

import (
	"context"
	"net"
	"time"

	amassnet "github.com/OWASP/Amass/v3/net"
	"github.com/OWASP/Amass/v3/net/http"
	"github.com/OWASP/Amass/v3/requests"
	"github.com/OWASP/Amass/v3/systems"
	"github.com/caffix/eventbus"
	"github.com/caffix/service"
	"github.com/caffix/stringset"
	lua "github.com/yuin/gopher-lua"
)

func genNewNameEvent(ctx context.Context, sys systems.System, srv service.Service, name string) {
	cfg, bus, err := requests.ContextConfigBus(ctx)
	if err != nil {
		return
	}

	if domain := cfg.WhichDomain(name); domain != "" {
		bus.Publish(requests.NewNameTopic, eventbus.PriorityHigh, &requests.DNSRequest{
			Name:   name,
			Domain: domain,
			Tag:    srv.Description(),
			Source: srv.String(),
		})
	}
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

	cfg, bus, err := requests.ContextConfigBus(ctx)
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

	_, bus, err := requests.ContextConfigBus(ctx)
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

	_, bus, err := requests.ContextConfigBus(ctx)
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
