// Copyright © by Jeff Foley 2017-2023. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package scripting

import (
	"github.com/caffix/service"
	"github.com/owasp-amass/amass/v4/format"
	"github.com/owasp-amass/config/config"
	lua "github.com/yuin/gopher-lua"
)

// Wrapper so that scripts can obtain the configuration for the current enumeration.
func (s *Script) config(L *lua.LState) int {
	cfg := s.sys.Config()

	r := L.NewTable()
	r.RawSetString("version", lua.LString(format.Version))

	if cfg.Active {
		r.RawSetString("mode", lua.LString("active"))
	} else if cfg.Passive {
		r.RawSetString("mode", lua.LString("passive"))
	} else {
		r.RawSetString("mode", lua.LString("normal"))
	}

	r.RawSetString("max_dns_queries", lua.LNumber(cfg.MaxDNSQueries))

	scope := L.NewTable()
	tb := L.NewTable()
	for _, domain := range cfg.Domains() {
		tb.Append(lua.LString(domain))
	}
	scope.RawSetString("domains", tb)

	tb = L.NewTable()
	for _, sub := range cfg.Scope.Blacklist {
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
	for _, addr := range cfg.Scope.Addresses {
		tb.Append(lua.LString(addr.String()))
	}
	scope.RawSetString("addresses", tb)

	tb = L.NewTable()
	for _, cidr := range cfg.Scope.CIDRs {
		tb.Append(lua.LString(cidr.String()))
	}
	scope.RawSetString("cidrs", tb)

	tb = L.NewTable()
	for _, asn := range cfg.Scope.ASNs {
		tb.Append(lua.LNumber(asn))
	}
	scope.RawSetString("asns", tb)

	tb = L.NewTable()
	for _, port := range cfg.Scope.Ports {
		tb.Append(lua.LNumber(port))
	}
	scope.RawSetString("ports", tb)
	r.RawSetString("scope", scope)

	tb = L.NewTable()
	tb.RawSetString("active", lua.LBool(cfg.BruteForcing))
	tb.RawSetString("recursive", lua.LBool(cfg.Recursive))
	tb.RawSetString("min_for_recursive", lua.LNumber(cfg.MinForRecursive))
	tb.RawSetString("max_depth", lua.LNumber(cfg.MaxDepth))
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
	dsc := s.sys.Config().DataSrcConfigs
	if dsc == nil {
		L.Push(lua.LNil)
		return 1
	}

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

	if creds := dsc.GetCredentials(cfg.Name); creds != nil {
		c := L.NewTable()

		c.RawSetString("name", lua.LString(creds.Name))
		if creds.Username != "" {
			c.RawSetString("username", lua.LString(creds.Username))
		}
		if creds.Password != "" {
			c.RawSetString("password", lua.LString(creds.Password))
		}
		if creds.Apikey != "" {
			c.RawSetString("key", lua.LString(creds.Apikey))
		}
		if creds.Secret != "" {
			c.RawSetString("secret", lua.LString(creds.Secret))
		}
		tb.RawSetString("credentials", c)
	}

	L.Push(tb)
	return 1
}

// Wrapper so that scripts can check if a subdomain name is in scope.
func (s *Script) inScope(L *lua.LState) int {
	result := lua.LFalse

	if _, err := extractContext(L.CheckUserData(1)); err == nil {
		if sub := L.CheckString(2); sub != "" && s.sys.Config().IsDomainInScope(sub) {
			result = lua.LTrue
		}
	}
	L.Push(result)
	return 1
}

// Wrapper so that scripts can obtain the brute force wordlist for the current enumeration.
func (s *Script) bruteWordlist(L *lua.LState) int {
	tb := L.NewTable()

	if _, err := extractContext(L.CheckUserData(1)); err == nil {
		for _, word := range s.sys.Config().Wordlist {
			tb.Append(lua.LString(word))
		}
	}

	L.Push(tb)
	return 1
}

// Wrapper so that scripts can obtain the alteration wordlist for the current enumeration.
func (s *Script) altWordlist(L *lua.LState) int {
	tb := L.NewTable()

	if _, err := extractContext(L.CheckUserData(1)); err == nil {
		for _, word := range s.sys.Config().AltWordlist {
			tb.Append(lua.LString(word))
		}
	}

	L.Push(tb)
	return 1
}

// Wrapper so scripts can set the data source rate limit.
func (s *Script) setRateLimit(L *lua.LState) int {
	s.seconds = L.CheckInt(1)
	return 0
}

func numRateLimitChecks(srv service.Service, num int) {
	for i := 0; i < num; i++ {
		srv.CheckRateLimit()
	}
}

// Wrapper so scripts can block until past the data source rate limit.
func (s *Script) checkRateLimit(L *lua.LState) int {
	numRateLimitChecks(s, s.seconds)
	return 0
}

// Wrapper so that scripts can request the path to the Amass output directory.
func (s *Script) outputdir(L *lua.LState) int {
	var dir string

	if _, err := extractContext(L.CheckUserData(1)); err == nil {
		dir = config.OutputDirectory(s.sys.Config().Dir)
	}

	if dir != "" {
		L.Push(lua.LString(dir))
	} else {
		L.Push(lua.LNil)
	}
	return 1
}
