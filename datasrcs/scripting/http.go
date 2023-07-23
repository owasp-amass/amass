// Copyright © by Jeff Foley 2017-2023. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package scripting

import (
	"context"
	"net/url"
	"strings"
	"time"

	"github.com/owasp-amass/amass/v4/net/dns"
	"github.com/owasp-amass/amass/v4/net/http"
	lua "github.com/yuin/gopher-lua"
)

// Wrapper that allows scripts to make HTTP client requests.
func (s *Script) request(L *lua.LState) int {
	ctx, err := extractContext(L.CheckUserData(1))
	if err != nil {
		L.Push(lua.LNil)
		L.Push(lua.LString("No user data parameter or context expired"))
		return 2
	}

	opt := L.CheckTable(2)
	if opt == nil {
		L.Push(lua.LNil)
		L.Push(lua.LString("No table parameter was provided"))
		return 2
	}

	url, found := getStringField(L, opt, "url")
	if !found {
		L.Push(lua.LNil)
		L.Push(lua.LString("No URL found in the parameters"))
		return 2
	}

	var hdr http.Header
	if lv := L.GetField(opt, "header"); lv != nil {
		if tbl, ok := lv.(*lua.LTable); ok {
			hdr = make(http.Header)
			tbl.ForEach(func(k, v lua.LValue) {
				hdr[k.String()] = v.String()
			})
		}
	}

	var body string
	if method, ok := getStringField(L, opt, "method"); ok && strings.ToLower(method) == "post" {
		if d, ok := getStringField(L, opt, "body"); ok {
			body = d
		}
	}

	id, _ := getStringField(L, opt, "id")
	pass, _ := getStringField(L, opt, "pass")
	resp, err := s.req(ctx, url, body, hdr, &http.BasicAuth{
		Username: id,
		Password: pass,
	})

	if err != nil || resp == nil {
		L.Push(lua.LNil)
		estr := "no HTTP response"
		if err != nil {
			estr = err.Error()
		}
		L.Push(lua.LString(estr))
	} else {
		L.Push(responseToTable(L, resp))
		L.Push(lua.LNil)
	}
	return 2
}

func responseToTable(L *lua.LState, resp *http.Response) *lua.LTable {
	r := L.NewTable()

	r.RawSetString("status", lua.LString(resp.Status))
	r.RawSetString("status_code", lua.LNumber(resp.StatusCode))
	r.RawSetString("proto", lua.LString(resp.Proto))
	r.RawSetString("proto_major", lua.LNumber(resp.ProtoMajor))
	r.RawSetString("proto_minor", lua.LNumber(resp.ProtoMinor))

	hdrs := L.NewTable()
	for k, v := range resp.Header {
		hdrs.RawSetString(k, lua.LString(v))
	}
	r.RawSetString("header", hdrs)

	r.RawSetString("body", lua.LString(resp.Body))
	r.RawSetString("length", lua.LNumber(resp.Length))

	if resp.TLS != nil {
		tls := L.NewTable()

		tls.RawSetString("version", lua.LNumber(resp.TLS.Version))
		tls.RawSetString("handshake_complete", lua.LBool(resp.TLS.HandshakeComplete))
		tls.RawSetString("server_name", lua.LString(resp.TLS.ServerName))

		if len(resp.TLS.PeerCertificates) > 0 {
			certs := L.NewTable()

			for _, cert := range resp.TLS.PeerCertificates {
				c := L.NewTable()

				c.RawSetString("version", lua.LNumber(cert.Version))
				c.RawSetString("common_name", lua.LString(dns.RemoveAsteriskLabel(cert.Subject.CommonName)))

				if len(cert.DNSNames) > 0 {
					san := L.NewTable()

					for _, name := range cert.DNSNames {
						n := dns.RemoveAsteriskLabel(name)

						san.Append(lua.LString(n))
					}
					c.RawSetString("subject_alternate_names", san)
				}
				certs.Append(c)
			}
			tls.RawSetString("certificates", certs)
		}

		r.RawSetString("tls", tls)
	}
	return r
}

// Wrapper so that scripts can scrape the contents of a GET request for subdomain names in scope.
func (s *Script) scrape(L *lua.LState) int {
	ctx, err := extractContext(L.CheckUserData(1))
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

	var hdr http.Header
	if lv := L.GetField(opt, "header"); lv != nil {
		if tbl, ok := lv.(*lua.LTable); ok {
			hdr = make(http.Header)
			tbl.ForEach(func(k, v lua.LValue) {
				hdr[k.String()] = v.String()
			})
		}
	}

	var body string
	if method, ok := getStringField(L, opt, "method"); ok && strings.ToLower(method) == "post" {
		if d, ok := getStringField(L, opt, "body"); ok {
			body = d
		}
	}

	id, _ := getStringField(L, opt, "id")
	pass, _ := getStringField(L, opt, "pass")

	sucess := lua.LFalse
	if resp, err := s.req(ctx, url, body, hdr, &http.BasicAuth{
		Username: id,
		Password: pass,
	}); err == nil {
		if resp != nil && resp.StatusCode >= 200 && resp.StatusCode < 400 {
			if num := s.internalSendNames(ctx, resp.Body); num > 0 {
				sucess = lua.LTrue
			}
		}
	} else {
		s.sys.Config().Log.Print(s.String() + ": scrape: " + err.Error())
	}

	L.Push(sucess)
	return 1
}

func (s *Script) req(ctx context.Context, url, data string, hdr http.Header, auth *http.BasicAuth) (*http.Response, error) {
	method := "GET"
	if data != "" {
		method = "POST"
	}

	numRateLimitChecks(s, s.seconds)
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()

	resp, err := http.RequestWebPage(ctx, &http.Request{
		URL:    url,
		Method: method,
		Header: hdr,
		Body:   data,
		Auth:   auth,
	})
	if err != nil {
		cfg := s.sys.Config()

		if cfg.Verbose {
			cfg.Log.Printf("%s: %s: %v", s.String(), url, err)
		}
	}
	return resp, err
}

// Wrapper so that scripts can crawl for subdomain names in scope.
func (s *Script) crawl(L *lua.LState) int {
	cfg := s.sys.Config()
	ctx, err := extractContext(L.CheckUserData(1))
	if err != nil {
		return 0
	}

	u := L.CheckString(2)
	if u == "" {
		return 0
	}

	max := L.CheckInt(3)
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()

	err = http.Crawl(ctx, u, cfg.Domains(), max, func(req *http.Request, resp *http.Response) {
		if u, err := url.Parse(req.URL); err == nil {
			s.newNameWithContext(ctx, http.CleanName(u.Hostname()))
		}
		s.internalSendNames(ctx, resp.Body)

		if resp.TLS != nil && len(resp.TLS.PeerCertificates) > 0 {
			for _, name := range http.NamesFromCert(resp.TLS.PeerCertificates[0]) {
				s.newNameWithContext(ctx, http.CleanName(name))
			}
		}
		for k, v := range resp.Header {
			if k == "Content-Security-Policy" ||
				k == "Content-Security-Policy-Report-Only" ||
				k == "X-Content-Security-Policy" || k == "X-Webkit-CSP" {
				s.internalSendNames(ctx, v)
			}
		}
	})

	if err != nil && cfg.Verbose {
		cfg.Log.Printf("%s: %s: %v", s.String(), u, err)
	}
	return 0
}
