// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package lens

import (
	"context"
	"fmt"
	"net/url"
	"sort"
	"strings"

	"github.com/owasp-amass/amass/v5/internal/graph"
)

// LensWeb asks for the web presence of a domain or organization: the URLs it
// controls, the host and address each reaches, and the web applications
// recognized on them. The answer is built in Go from stored URLs; nothing is
// written and no page is fetched.
const LensWeb = "web"

// webExamples bounds the example endpoints kept per summary.
const webExamples = 50

var webLens = SubjectLens{
	Name:    LensWeb,
	Command: "web",
	Description: "List the web presence of a domain or organization: its website URLs and endpoints, the host " +
		"and address each reaches, and the web applications recognized on them. Read-only",
	Examples: []string{"What web endpoints does <domain> expose?",
		"Which web applications run on <organization>'s sites?",
		"What are <domain>'s websites and where do they point?"},
	Find: func(ctx context.Context, g graph.Graph, schema graph.SchemaCatalog, root graph.Asset,
		opts Options) (Report, error) {
		return FindWeb(ctx, g, schema, root, opts.Limits)
	},
}

// WebEndpoint is one URL the subject controls, with where it points.
type WebEndpoint struct {
	URL    string `json:"url"`
	Host   string `json:"host,omitempty"`
	Scheme string `json:"scheme,omitempty"`
	// Addresses are the IPs the URL is stored as reaching; Service is the
	// "host:port" of a service stored on it, when either is recorded.
	Addresses []string `json:"addresses,omitempty"`
	Service   string   `json:"service,omitempty"`
}

// WebReport is the result of the web lens.
type WebReport struct {
	lensBase
	// Endpoints are URLs on the subject's own registered domains; External
	// are URLs on other domains (social profiles, third-party policy or
	// hosting pages) that the subject still controls.
	Endpoints []WebEndpoint `json:"endpoints"`
	External  []WebEndpoint `json:"external,omitempty"`
	// Applications are the web applications recognized on the subject's sites
	// from the stored URLs.
	Applications []WebApplication `json:"applications,omitempty"`
	Total        int              `json:"total"`
}

// FindWeb lists the URLs a domain or organization controls, where each
// points, and the web applications recognized on them. It reads only.
func FindWeb(ctx context.Context, g graph.Graph, schema graph.SchemaCatalog, root graph.Asset,
	limits LensLimits) (WebReport, error) {
	g = graph.Cached(g)
	var out WebReport
	s, err := newScope(ctx, g, schema, root, limits, LensWeb)
	if err != nil {
		return out, err
	}

	ordered, err := s.ownedURLs()
	if err != nil {
		return out, err
	}
	for _, u := range ordered {
		ep, err := s.webEndpoint(u)
		if err != nil {
			return out, err
		}
		out.Total++
		// A URL on one of the subject's own registered domains is its own web
		// surface; one on another domain is an off-domain presence.
		if ep.Host != "" && s.ownDomains[graph.RegisteredDomain(ep.Host)] {
			out.Endpoints = append(out.Endpoints, ep)
		} else {
			out.External = append(out.External, ep)
		}
	}

	out.Applications = identifyWebApplications(ordered)
	sortEndpoints(out.Endpoints)
	sortEndpoints(out.External)
	sort.Slice(out.Applications, func(i, j int) bool {
		if out.Applications[i].Site != out.Applications[j].Site {
			return out.Applications[i].Site < out.Applications[j].Site
		}
		return out.Applications[i].Product < out.Applications[j].Product
	})
	if len(out.Endpoints) > webExamples {
		out.Endpoints = out.Endpoints[:webExamples]
	}
	if len(out.External) > webExamples {
		out.External = out.External[:webExamples]
	}
	out.lensBase = s.base()
	return out, nil
}

// ownedURLs returns the URL assets the subject controls: those in the
// footprint, and those linked forward from an owned asset by an edge the
// footprint walk does not follow (a service's security.txt pages, for
// example). The order is stable so reports do not shuffle between runs.
func (s *scope) ownedURLs() ([]graph.Asset, error) {
	urls := map[string]graph.Asset{}
	for _, id := range s.order {
		if s.spent() {
			break
		}
		a := s.owned[id]
		if a.Type == "URL" {
			urls[a.ID] = a
			continue
		}
		steps, err := s.w.steps(a)
		if err != nil {
			return nil, err
		}
		for _, st := range steps {
			if st.forward && st.other.Type == "URL" {
				urls[st.other.ID] = st.other
			}
		}
	}

	ordered := make([]graph.Asset, 0, len(urls))
	for _, u := range urls {
		ordered = append(ordered, u)
	}
	sort.Slice(ordered, func(i, j int) bool { return ordered[i].ID < ordered[j].ID })
	return ordered, nil
}

// webEndpoint builds an endpoint from a stored URL: its host and scheme, and
// the addresses and service it is stored as reaching.
func (s *scope) webEndpoint(u graph.Asset) (WebEndpoint, error) {
	ep := WebEndpoint{
		URL:    urlRaw(u),
		Host:   graph.ContentString(u, "host"),
		Scheme: graph.ContentString(u, "scheme"),
	}
	// Fall back to the raw URL when the host or scheme is not stored
	// separately, so classification and display work either way.
	if (ep.Host == "" || ep.Scheme == "") && ep.URL != "" {
		if parsed, err := url.Parse(ep.URL); err == nil {
			if ep.Host == "" {
				ep.Host = parsed.Hostname()
			}
			if ep.Scheme == "" {
				ep.Scheme = parsed.Scheme
			}
		}
	}

	steps, err := s.w.steps(u)
	if err != nil {
		return ep, err
	}
	for _, st := range steps {
		if !st.forward {
			continue
		}
		switch st.other.Type {
		case "IPAddress":
			if ip := graph.ContentString(st.other, "address"); ip != "" {
				graph.AddUnique(&ep.Addresses, ip)
			}
		case "Service":
			if ep.Service == "" {
				ep.Service = graph.AssetLabel(st.other)
			}
		}
	}
	sort.Strings(ep.Addresses)
	return ep, nil
}

// urlRaw returns a URL asset's stored string, falling back to its key.
func urlRaw(u graph.Asset) string {
	if raw := graph.ContentString(u, "url"); raw != "" {
		return raw
	}
	return graph.AssetLabel(u)
}

func sortEndpoints(eps []WebEndpoint) {
	sort.Slice(eps, func(i, j int) bool { return eps[i].URL < eps[j].URL })
}

// Text implements Report.
func (r WebReport) Text() string {
	var b strings.Builder
	subject := graph.AssetLabel(r.Root)
	if len(r.Owners) > 0 {
		subject += " and " + strings.Join(r.Owners, ", ")
	}

	fmt.Fprintf(&b, "Web presence of %s: %d URL(s) — %d on its own domains, %d off-domain (%d reads).\n",
		subject, r.Total, len(r.Endpoints), len(r.External), r.Reads)
	b.WriteString(r.summarizedNote())

	if r.Total == 0 {
		b.WriteString("\nNo stored URL is controlled by the subject.\n")
		return b.String()
	}

	if len(r.Endpoints) > 0 {
		b.WriteString("\nEndpoints on its own domains:\n")
		for _, e := range r.Endpoints {
			writeEndpoint(&b, e)
		}
	}
	if len(r.External) > 0 {
		b.WriteString("\nOff-domain URLs (social profiles, third-party pages):\n")
		for _, e := range r.External {
			writeEndpoint(&b, e)
		}
	}

	if len(r.Applications) > 0 {
		b.WriteString("\nWeb applications recognized:\n")
		for _, a := range r.Applications {
			fmt.Fprintf(&b, "  %s: %s", a.Site, a.Product)
			if a.Vendor != "" {
				fmt.Fprintf(&b, " (%s)", a.Vendor)
			}
			var vers []string
			for _, id := range a.Identified {
				vers = append(vers, id.Version)
			}
			if len(vers) > 0 {
				fmt.Fprintf(&b, " %s", strings.Join(vers, ", "))
			}
			b.WriteString("\n")
		}
	}

	b.WriteString("\nThese are stored URLs, not a live crawl." + r.partialNote() + "\n")
	return b.String()
}

func writeEndpoint(b *strings.Builder, e WebEndpoint) {
	fmt.Fprintf(b, "  %s", e.URL)
	if len(e.Addresses) > 0 {
		fmt.Fprintf(b, " -> %s", strings.Join(e.Addresses, ", "))
	}
	if e.Service != "" {
		fmt.Fprintf(b, " [%s]", e.Service)
	}
	b.WriteString("\n")
}

// Facts implements Report.
func (r WebReport) Facts() []string {
	out := make([]string, 0, len(r.Endpoints)+len(r.Applications))
	for _, e := range r.Endpoints {
		out = append(out, "web endpoint "+e.URL)
	}
	for _, a := range r.Applications {
		out = append(out, a.Product+" on "+a.Site)
	}
	return out
}
