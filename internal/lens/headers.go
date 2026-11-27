// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package lens

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/owasp-amass/amass/v5/internal/graph"
)

// LensHeaders asks how a domain or organization's web services are hardened
// by their HTTP response headers.
const LensHeaders = "headers"

var headersLens = SubjectLens{
	Name:    LensHeaders,
	Command: "headers",
	Description: "Show the HTTP security headers of a domain or organization's web services: HSTS, CSP, " +
		"clickjacking and MIME-sniffing protection, and cookie flags, and which are missing or weak. Read-only",
	Examples: []string{"Does <domain> set HSTS and a content security policy?",
		"Which of <organization>'s sites set insecure cookies?"},
	Find: func(ctx context.Context, g graph.Graph, schema graph.SchemaCatalog, root graph.Asset,
		opts Options) (Report, error) {
		return FindHeaders(ctx, g, schema, root, opts.Limits)
	},
}

// Header finding kinds, most severe first.
const (
	HeaderInsecureCookie = "insecure_cookie"
	HeaderNoHSTS         = "no_hsts"
	HeaderNoCSP          = "no_content_security_policy"
	HeaderNoFrameGuard   = "no_clickjacking_protection"
	HeaderNoSniffGuard   = "no_content_type_options"
)

// HeadersReport is the result of the headers lens.
type HeadersReport struct {
	lensBase
	Services []ServiceHeaders `json:"services"`
	Findings []HeadersFinding `json:"findings,omitempty"`
}

// ServiceHeaders is one web service's hardening posture.
type ServiceHeaders struct {
	Host    string   `json:"host"`
	HTTPS   bool     `json:"https"`
	Missing []string `json:"missing,omitempty"`
}

// HeadersFinding is a hardening gap on one service.
type HeadersFinding struct {
	Kind   string `json:"kind"`
	Host   string `json:"host"`
	Detail string `json:"detail"`
}

// FindHeaders reports the HTTP security headers of the web services a domain
// or organization controls, and which hardening headers are missing. It reads
// the response headers already stored on each service; it makes no requests.
func FindHeaders(ctx context.Context, g graph.Graph, schema graph.SchemaCatalog, root graph.Asset,
	limits LensLimits) (HeadersReport, error) {
	out := HeadersReport{}
	s, err := newScope(ctx, g, schema, root, limits, "headers")
	if err != nil {
		return out, err
	}

	seen := map[string]bool{}
	for _, id := range s.order {
		if s.spent() {
			break
		}

		host := s.owned[id]
		if host.Type != "FQDN" {
			continue
		}
		steps, err := s.w.steps(host)
		if err != nil {
			return out, err
		}
		for _, st := range steps {
			if !st.forward || st.other.Type != "Service" || seen[st.other.ID] {
				continue
			}
			if graph.ContentString(st.other, "service_type") != "web-service" {
				continue
			}

			headers, cookies := webServiceHeaders(st.other)
			// Only a service whose response was captured can be judged.
			if len(headers) == 0 && len(cookies) == 0 {
				continue
			}
			seen[st.other.ID] = true

			https, err := s.w.servesTLS(st.other)
			if err != nil {
				return out, err
			}

			sh := ServiceHeaders{Host: graph.FQDNName(host), HTTPS: https}
			for _, f := range evaluateHeaders(headers, cookies, https) {
				// Only a missing hardening header names a header; other gaps
				// (an insecure cookie) are reported as findings alone.
				if f.header != "" {
					sh.Missing = append(sh.Missing, f.header)
				}
				out.Findings = append(out.Findings, HeadersFinding{Kind: f.kind, Host: sh.Host, Detail: f.detail})
			}
			sort.Strings(sh.Missing)
			out.Services = append(out.Services, sh)
		}
	}

	sort.Slice(out.Services, func(i, j int) bool { return out.Services[i].Host < out.Services[j].Host })
	out.lensBase = s.base()
	return out, nil
}

// servesTLS reports whether a service presents a TLS certificate, which marks
// it as HTTPS (so an absent HSTS header counts).
func (w *lensWalker) servesTLS(service graph.Asset) (bool, error) {
	steps, err := w.steps(service)
	if err != nil {
		return false, err
	}
	for _, s := range steps {
		if s.forward && s.edge.Label == "certificate" {
			return true, nil
		}
	}
	return false, nil
}

// serviceHeaders returns a service's stored response headers, lowercased and
// joined, with the Set-Cookie values returned separately.
func webServiceHeaders(svc graph.Asset) (map[string]string, []string) {
	data, err := json.Marshal(svc.Content)
	if err != nil {
		return nil, nil
	}

	var f struct {
		Attributes map[string][]string `json:"attributes"`
	}
	if json.Unmarshal(data, &f) != nil {
		return nil, nil
	}

	h := map[string]string{}
	var cookies []string
	for key, values := range f.Attributes {
		lk := strings.ToLower(strings.TrimSpace(key))
		if lk == "set-cookie" {
			cookies = append(cookies, values...)
			continue
		}
		h[lk] = strings.ToLower(strings.TrimSpace(strings.Join(values, " ")))
	}
	return h, cookies
}

type headerGap struct {
	kind   string
	header string
	detail string
}

// evaluateHeaders returns the hardening gaps in a service's response headers.
func evaluateHeaders(h map[string]string, cookies []string, https bool) []headerGap {
	var out []headerGap
	csp := h["content-security-policy"]

	if csp == "" {
		out = append(out, headerGap{HeaderNoCSP, "Content-Security-Policy",
			"no Content-Security-Policy, so the browser applies no script or content restrictions"})
	}
	if h["x-content-type-options"] == "" {
		out = append(out, headerGap{HeaderNoSniffGuard, "X-Content-Type-Options",
			"no X-Content-Type-Options: nosniff, so the browser may MIME-sniff responses"})
	}
	if h["x-frame-options"] == "" && !strings.Contains(csp, "frame-ancestors") {
		out = append(out, headerGap{HeaderNoFrameGuard, "X-Frame-Options",
			"no X-Frame-Options and no CSP frame-ancestors, so the page can be framed for clickjacking"})
	}
	if https && h["strict-transport-security"] == "" {
		out = append(out, headerGap{HeaderNoHSTS, "Strict-Transport-Security",
			"no HSTS on an HTTPS service, so a browser can be downgraded to plaintext"})
	}
	for _, c := range cookies {
		secure, httpOnly := false, false
		for _, part := range strings.Split(c, ";") {
			switch strings.ToLower(strings.TrimSpace(part)) {
			case "secure":
				secure = true
			case "httponly":
				httpOnly = true
			}
		}
		if !secure || !httpOnly {
			out = append(out, headerGap{HeaderInsecureCookie, "",
				"a Set-Cookie is missing the Secure or HttpOnly flag"})
			break
		}
	}
	return out
}

func (r HeadersReport) Text() string {
	var b strings.Builder
	subject := graph.AssetLabel(r.Root)
	if len(r.Owners) > 0 {
		subject += " and " + strings.Join(r.Owners, ", ")
	}

	fmt.Fprintf(&b, "HTTP security headers of %s, from %d controlled asset(s) (%d reads).\n",
		subject, r.Footprint, r.Reads)
	b.WriteString(r.summarizedNote())
	if len(r.Services) == 0 {
		b.WriteString("\nNo web service with stored response headers.\n")
		return b.String()
	}

	for _, s := range r.Services {
		if len(s.Missing) == 0 {
			fmt.Fprintf(&b, "\n%s: all checked hardening headers present\n", s.Host)
			continue
		}
		fmt.Fprintf(&b, "\n%s: missing %s\n", s.Host, strings.Join(s.Missing, ", "))
	}

	b.WriteString(r.partialNote() + "\n")
	return b.String()
}

func (r HeadersReport) Facts() []string {
	var out []string
	for _, f := range r.Findings {
		out = append(out, f.Kind+" "+f.Host)
	}
	return out
}
