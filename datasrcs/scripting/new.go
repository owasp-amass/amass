// Copyright 2020-2021 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package scripting

import (
	"context"
	"net"
	"time"

	amassnet "github.com/OWASP/Amass/v3/net"
	"github.com/OWASP/Amass/v3/net/http"
	"github.com/OWASP/Amass/v3/requests"
	"github.com/caffix/eventbus"
	"github.com/caffix/service"
	"github.com/caffix/stringset"
	lua "github.com/yuin/gopher-lua"
)

func genNewNameEvent(ctx context.Context, srv service.Service, name string) {
	if cfg, bus, err := requests.ContextConfigBus(ctx); err == nil {
		if domain := cfg.WhichDomain(name); domain != "" {
			bus.Publish(requests.NewNameTopic, eventbus.PriorityHigh, &requests.DNSRequest{
				Name:   name,
				Domain: domain,
				Tag:    srv.Description(),
				Source: srv.String(),
			})
		}
	}
}

// Wrapper so that scripts can send a discovered FQDN to Amass.
func (s *Script) newName(L *lua.LState) int {
	if ctx, err := extractContext(L.CheckUserData(1)); err == nil {
		if n := L.CheckString(2); n != "" {
			if name := s.subre.FindString(n); name != "" {
				genNewNameEvent(ctx, s, name)
			}
		}
	}
	return 0
}

// Wrapper so that scripts can send FQDNs found in the content to Amass.
func (s *Script) sendNames(L *lua.LState) int {
	var num int

	if ctx, err := extractContext(L.CheckUserData(1)); err == nil {
		if content := L.CheckString(2); content != "" {
			num = s.internalSendNames(ctx, content)
		}
	}

	L.Push(lua.LNumber(num))
	return 1
}

func (s *Script) internalSendNames(ctx context.Context, content string) int {
	filter := stringset.New()
	defer filter.Close()

	for _, name := range s.subre.FindAllString(string(content), -1) {
		if n := http.CleanName(name); n != "" && !filter.Has(n) {
			filter.Insert(n)
			genNewNameEvent(ctx, s, n)
		}
	}

	return filter.Len()
}

// Wrapper so that scripts can send discovered IP addresses to Amass.
func (s *Script) newAddr(L *lua.LState) int {
	ip := net.ParseIP(L.CheckString(2))

	if ip == nil {
		return 0
	}
	if reserved, _ := amassnet.IsReservedAddress(ip.String()); reserved {
		return 0
	}

	if ctx, err := extractContext(L.CheckUserData(1)); err == nil {
		cfg, bus, err := requests.ContextConfigBus(ctx)

		if name := L.CheckString(3); err == nil && name != "" {
			if domain := cfg.WhichDomain(name); domain != "" {
				bus.Publish(requests.NewAddrTopic, eventbus.PriorityHigh, &requests.AddrRequest{
					Address: ip.String(),
					Domain:  domain,
					Tag:     s.SourceType,
					Source:  s.String(),
				})
			}
		}
	}

	return 0
}

// Wrapper so that scripts can send discovered ASNs to Amass.
func (s *Script) newASN(L *lua.LState) int {
	if ctx, err := extractContext(L.CheckUserData(1)); err == nil {
		_, bus, err := requests.ContextConfigBus(ctx)

		if params := L.CheckTable(2); err == nil && params != nil {
			addr, _ := getStringField(L, params, "addr")
			ip := net.ParseIP(addr)
			if ip == nil {
				return 0
			}

			addr = ip.String()
			if reserved, _ := amassnet.IsReservedAddress(addr); reserved {
				return 0
			}

			asn, _ := getNumberField(L, params, "asn")
			prefix, _ := getStringField(L, params, "prefix")
			desc, _ := getStringField(L, params, "desc")
			if asn == 0 || prefix == "" || desc == "" {
				return 0
			}

			_, cidr, err := net.ParseCIDR(prefix)
			if err != nil {
				return 0
			}

			netblocks := []string{cidr.String()}
			lv := L.GetField(params, "netblocks")
			if tbl, ok := lv.(*lua.LTable); ok {
				tbl.ForEach(func(_, v lua.LValue) {
					if _, cidr, err := net.ParseCIDR(v.String()); err == nil {
						netblocks = append(netblocks, cidr.String())
					}
				})
			}

			cc, _ := getStringField(L, params, "cc")
			registry, _ := getStringField(L, params, "registry")
			bus.Publish(requests.NewASNTopic, eventbus.PriorityHigh, &requests.ASNRequest{
				Address:        addr,
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
		}
	}
	return 0
}

// Wrapper so that scripts can send discovered associated domains to Amass.
func (s *Script) associated(L *lua.LState) int {
	if ctx, err := extractContext(L.CheckUserData(1)); err == nil {
		_, bus, err := requests.ContextConfigBus(ctx)

		if domain, assoc := L.CheckString(2), L.CheckString(3); err == nil && domain != "" && assoc != "" {
			bus.Publish(requests.NewWhoisTopic, eventbus.PriorityHigh, &requests.WhoisRequest{
				Domain:     domain,
				NewDomains: []string{assoc},
				Tag:        s.SourceType,
				Source:     s.String(),
			})
		}
	}
	return 0
}
