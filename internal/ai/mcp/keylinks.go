// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"errors"
	"fmt"
	"html/template"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/owasp-amass/amass/v5/config"
	"github.com/owasp-amass/amass/v5/internal/collect"
)

// KeyLinks issues one-time pages where a user enters a data source's
// credentials in a browser. The credentials go from the form to the
// datasources file and never reach the assistant: the assistant only sees
// the link. A link works once and expires after TTL.
type KeyLinks struct {
	// BaseURL is how the user's browser reaches this server, such as
	// http://127.0.0.1:18090.
	BaseURL string
	// Path is the datasources file credentials are written to.
	Path string
	TTL  time.Duration
	Now  func() time.Time

	mu    sync.Mutex
	links map[string]keyLink
}

type keyLink struct {
	source  string
	expires time.Time
}

const (
	keyLinkPrefix     = "/datasource-key/"
	defaultKeyLinkTTL = 15 * time.Minute
	maxKeyLinks       = 64
)

func (k *KeyLinks) now() time.Time {
	if k.Now != nil {
		return k.Now()
	}

	return time.Now()
}

// New issues a link for one data source.
func (k *KeyLinks) New(source string) (string, time.Time, error) {
	source = strings.TrimSpace(source)
	if source == "" || strings.ContainsAny(source, "\n\r:#/?") || len(source) > 64 {
		return "", time.Time{}, errors.New("invalid data source name")
	}
	if k.BaseURL == "" {
		return "", time.Time{}, errors.New("the server does not know its public URL (AMASS_AI_MCP_PUBLIC_URL)")
	}

	id := newSessionID()
	if id == "" {
		return "", time.Time{}, errors.New("could not create a link")
	}

	ttl := k.TTL
	if ttl <= 0 {
		ttl = defaultKeyLinkTTL
	}

	expires := k.now().Add(ttl)
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.links == nil {
		k.links = map[string]keyLink{}
	}
	for t, l := range k.links {
		if k.now().After(l.expires) {
			delete(k.links, t)
		}
	}
	if len(k.links) >= maxKeyLinks {
		return "", time.Time{}, errors.New("too many open key links; wait for them to expire")
	}

	k.links[id] = keyLink{source: source, expires: expires}
	return strings.TrimSuffix(k.BaseURL, "/") + keyLinkPrefix + id, expires, nil
}

// peek returns a live link without using it.
func (k *KeyLinks) peek(id string) (keyLink, bool) {
	k.mu.Lock()
	defer k.mu.Unlock()
	l, ok := k.links[id]
	if !ok || k.now().After(l.expires) {
		delete(k.links, id)
		return keyLink{}, false
	}

	return l, true
}

// take uses a link up.
func (k *KeyLinks) take(id string) (keyLink, bool) {
	k.mu.Lock()
	defer k.mu.Unlock()
	l, ok := k.links[id]
	delete(k.links, id)
	if !ok || k.now().After(l.expires) {
		return keyLink{}, false
	}

	return l, true
}

var keyPage = template.Must(template.New("key").Parse(`<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="referrer" content="no-referrer"><title>Amass data source key</title>
<style>body{font:16px system-ui,sans-serif;max-width:32rem;margin:3rem auto;padding:0 1rem;color:#1d1d1f}
label{display:block;margin:.8rem 0 .2rem}input{width:100%;padding:.5rem;font:inherit;box-sizing:border-box}
button{margin-top:1.2rem;padding:.6rem 1.2rem;font:inherit}.note{color:#555;font-size:.9rem}</style></head>
<body>{{if .Done}}<h1>Saved</h1><p>The credentials for <b>{{.Source}}</b> were stored. New enumerations use them.
You can close this page.</p>{{else if .Error}}<h1>Not saved</h1><p>{{.Error}}</p>{{else}}
<h1>{{.Source}} credentials</h1>
<p class="note">These go straight to the Amass datasources file, not to your assistant. Fill in what
{{.Source}} gives you; most sources need only an API key.</p>
<form method="post" autocomplete="off">
<label for="apikey">API key</label><input id="apikey" name="apikey" type="password">
<label for="secret">Secret (if the source has one)</label><input id="secret" name="secret" type="password">
<label for="username">Username (if needed)</label><input id="username" name="username">
<label for="password">Password (if needed)</label><input id="password" name="password" type="password">
<label for="account">Account label</label><input id="account" name="account" value="account">
<button type="submit">Save</button></form>{{end}}</body></html>`))

// ServeHTTP serves the key form and stores what it posts.
func (k *KeyLinks) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'")
	if !validOrigin(r) {
		http.Error(w, "origin forbidden", http.StatusForbidden)
		return
	}

	id := strings.TrimPrefix(r.URL.Path, keyLinkPrefix)
	page := struct {
		Source, Error string
		Done          bool
	}{}
	switch r.Method {
	case http.MethodGet:
		l, ok := k.peek(id)
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			page.Error = "This link has expired or was already used. Ask your assistant for a new one."
		}

		page.Source = l.source
	case http.MethodPost:
		r.Body = http.MaxBytesReader(w, r.Body, 16<<10)
		if err := r.ParseForm(); err != nil {
			http.Error(w, "bad form", http.StatusBadRequest)
			return
		}

		l, ok := k.take(id)
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			page.Error = "This link has expired or was already used. Ask your assistant for a new one."
			break
		}

		page.Source = l.source
		cred := config.Credentials{Apikey: strings.TrimSpace(r.PostForm.Get("apikey")),
			Secret: strings.TrimSpace(r.PostForm.Get("secret")), Username: strings.TrimSpace(r.PostForm.Get("username")),
			Password: r.PostForm.Get("password")}
		if err := collect.SetDataSourceCredentials(k.Path, l.source, r.PostForm.Get("account"), cred); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			page.Error = fmt.Sprintf("The credentials were not stored: %v. Ask your assistant for a new link.", err)
			break
		}

		page.Done = true
	default:
		w.Header().Set("Allow", "GET, POST")
		http.Error(w, "use GET or POST", http.StatusMethodNotAllowed)
		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = keyPage.Execute(w, page)
}
