// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"errors"
	"html/template"
	"net/http"
	"strings"
	"sync"
	"time"
)

// ApprovalLinks lets a user approve an action in a browser when their
// assistant cannot show an approval dialog. The assistant gets only a link;
// nothing happens until the user opens it and presses Approve, which a model
// fetching the page cannot do: approval is a form POST from a local page.
type ApprovalLinks struct {
	BaseURL string
	TTL     time.Duration
	Now     func() time.Time

	mu      sync.Mutex
	pending map[string]*pendingApproval
}

type pendingApproval struct {
	message string
	act     func() (string, error)
	expires time.Time
}

const (
	approvalPrefix     = "/approve/"
	defaultApprovalTTL = 15 * time.Minute
	maxApprovals       = 64
)

func (a *ApprovalLinks) now() time.Time {
	if a.Now != nil {
		return a.Now()
	}

	return time.Now()
}

// New records an action awaiting approval and returns its link.
func (a *ApprovalLinks) New(message string, act func() (string, error)) (string, time.Time, error) {
	if a.BaseURL == "" {
		return "", time.Time{}, errors.New("the server does not know its public URL (AMASS_MCP_PUBLIC_URL)")
	}

	id := newSessionID()
	if id == "" {
		return "", time.Time{}, errors.New("could not create a link")
	}

	ttl := a.TTL
	if ttl <= 0 {
		ttl = defaultApprovalTTL
	}

	expires := a.now().Add(ttl)

	a.mu.Lock()
	defer a.mu.Unlock()
	if a.pending == nil {
		a.pending = map[string]*pendingApproval{}
	}
	for k, p := range a.pending {
		if a.now().After(p.expires) {
			delete(a.pending, k)
		}
	}
	if len(a.pending) >= maxApprovals {
		return "", time.Time{}, errors.New("too many actions await approval; wait for them to expire")
	}

	a.pending[id] = &pendingApproval{message: message, act: act, expires: expires}
	return strings.TrimSuffix(a.BaseURL, "/") + approvalPrefix + id, expires, nil
}

func (a *ApprovalLinks) get(id string, take bool) (*pendingApproval, bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	p, ok := a.pending[id]
	if take {
		delete(a.pending, id)
	}
	if !ok || a.now().After(p.expires) {
		delete(a.pending, id)
		return nil, false
	}

	return p, true
}

var approvalPage = template.Must(template.New("approve").Parse(`<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="referrer" content="no-referrer"><title>Approve an Amass action</title>
<style>body{font:16px system-ui,sans-serif;max-width:36rem;margin:3rem auto;padding:0 1rem;color:#1d1d1f}
pre{white-space:pre-wrap;background:#f4f4f6;padding:1rem;border-radius:6px;font:inherit}
button{margin:1rem .6rem 0 0;padding:.6rem 1.4rem;font:inherit}</style></head><body>
{{if .Result}}<h1>{{.Title}}</h1><pre>{{.Result}}</pre><p>You can close this page and return to your assistant.</p>
{{else}}<h1>Your assistant asks to:</h1><pre>{{.Message}}</pre>
<form method="post"><button name="decision" value="approve" type="submit">Approve</button>
<button name="decision" value="decline" type="submit">Decline</button></form>{{end}}</body></html>`))

// ServeHTTP shows an action and carries out the user's decision once.
func (a *ApprovalLinks) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'")
	if !validOrigin(r) {
		http.Error(w, "origin forbidden", http.StatusForbidden)
		return
	}

	id := strings.TrimPrefix(r.URL.Path, approvalPrefix)
	page := struct{ Message, Title, Result string }{}
	gone := "This link has expired or was already used. Ask your assistant again if the action is still wanted."
	switch r.Method {
	case http.MethodGet:
		p, ok := a.get(id, false)
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			page.Title, page.Result = "Nothing to approve", gone
			break
		}

		page.Message = p.message
	case http.MethodPost:
		r.Body = http.MaxBytesReader(w, r.Body, 4<<10)
		if err := r.ParseForm(); err != nil {
			http.Error(w, "bad form", http.StatusBadRequest)
			return
		}

		p, ok := a.get(id, true)
		switch {
		case !ok:
			w.WriteHeader(http.StatusNotFound)
			page.Title, page.Result = "Nothing to approve", gone
		case r.PostForm.Get("decision") != "approve":
			page.Title, page.Result = "Declined", "Nothing was done."
		default:
			out, err := p.act()
			if err != nil {
				page.Title, page.Result = "Approved, but it failed", err.Error()
			} else {
				page.Title, page.Result = "Approved", out
			}
		}
	default:
		w.Header().Set("Allow", "GET, POST")
		http.Error(w, "use GET or POST", http.StatusMethodNotAllowed)
		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = approvalPage.Execute(w, page)
}
