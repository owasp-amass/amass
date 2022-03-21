// Copyright © by Jeff Foley 2020-2022. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package scripting

import (
	"context"
	"net"
	"time"

	amassnet "github.com/OWASP/Amass/v3/net"
	"github.com/OWASP/Amass/v3/net/http"
	"github.com/OWASP/Amass/v3/requests"
	"github.com/OWASP/Amass/v3/systems"
	bf "github.com/tylertreat/BoomFilters"
	lua "github.com/yuin/gopher-lua"
)

func genNewName(ctx context.Context, sys systems.System, script *Script, name string) {
	if domain := sys.Config().WhichDomain(name); domain != "" {
		select {
		case <-ctx.Done():
		case <-script.Done():
		default:
			script.queue.Append(&requests.DNSRequest{
				Name:   name,
				Domain: domain,
				Tag:    script.Description(),
				Source: script.String(),
			})
		}
	}
}

// Wrapper so that scripts can send a discovered FQDN to Amass.
func (s *Script) newName(L *lua.LState) int {
	if ctx, err := extractContext(L.CheckUserData(1)); err == nil && !contextExpired(ctx) {
		if n := L.CheckString(2); n != "" {
			if name := s.subre.FindString(n); name != "" {
				genNewName(ctx, s.sys, s, name)
			}
		}
	}
	return 0
}

// Wrapper so that scripts can send FQDNs found in the content to Amass.
func (s *Script) sendNames(L *lua.LState) int {
	var num int

	if ctx, err := extractContext(L.CheckUserData(1)); err == nil && !contextExpired(ctx) {
		if content := L.CheckString(2); content != "" {
			num = s.internalSendNames(ctx, content)
		}
	}

	L.Push(lua.LNumber(num))
	return 1
}

func (s *Script) internalSendNames(ctx context.Context, content string) int {
	filter := bf.NewDefaultStableBloomFilter(1000, 0.01)
	defer filter.Reset()

	var count int
	for _, name := range s.subre.FindAllString(string(content), -1) {
		if n := http.CleanName(name); n != "" && !filter.TestAndAdd([]byte(n)) {
			genNewName(ctx, s.sys, s, n)
			count++
		}
	}
	return count
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
	if ctx, err := extractContext(L.CheckUserData(1)); err == nil && !contextExpired(ctx) {
		if name := L.CheckString(3); err == nil && name != "" {
			if domain := s.sys.Config().WhichDomain(name); domain != "" {
				select {
				case <-ctx.Done():
				case <-s.Done():
				default:
					s.queue.Append(&requests.AddrRequest{
						Address: ip.String(),
						Domain:  domain,
						Tag:     s.SourceType,
						Source:  s.String(),
					})
				}
			}
		}
	}
	return 0
}

// Wrapper so that scripts can send discovered ASNs to Amass.
func (s *Script) newASN(L *lua.LState) int {
	if ctx, err := extractContext(L.CheckUserData(1)); err == nil && !contextExpired(ctx) {
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
			s.sys.Cache().Update(&requests.ASNRequest{
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
	if ctx, err := extractContext(L.CheckUserData(1)); err == nil && !contextExpired(ctx) {
		if domain, assoc := L.CheckString(2), L.CheckString(3); err == nil && domain != "" && assoc != "" {
			select {
			case <-ctx.Done():
			case <-s.Done():
			default:
				s.queue.Append(&requests.WhoisRequest{
					Domain:     domain,
					NewDomains: []string{assoc},
					Tag:        s.SourceType,
					Source:     s.String(),
				})
			}
		}
	}
	return 0
}
