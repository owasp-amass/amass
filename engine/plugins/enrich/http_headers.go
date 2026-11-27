// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package enrich

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/owasp-amass/amass/v5/engine/plugins/support"
	et "github.com/owasp-amass/amass/v5/engine/types"
	amassdns "github.com/owasp-amass/amass/v5/internal/net/dns"
	dbt "github.com/owasp-amass/asset-db/types"
	oam "github.com/owasp-amass/open-asset-model"
	oamdns "github.com/owasp-amass/open-asset-model/dns"
	"github.com/owasp-amass/open-asset-model/general"
	"github.com/owasp-amass/open-asset-model/platform"
	oamurl "github.com/owasp-amass/open-asset-model/url"
)

// headerRefs records what a web service's stored response headers name:
//   - the hosts its Content-Security-Policy lets it load content from
//     (Service --content_source--> FQDN), a map of the third parties the
//     site depends on;
//   - the origins CORS Access-Control-Allow-Origin and CSP frame-ancestors
//     let call or embed it (Service --allowed_origin--> FQDN), often the
//     organization's sibling sites;
//   - where it sends browser reports (Service --report_endpoint--> URL);
//   - internal host names that proxy and backend headers leak (Via,
//     X-Backend-Server, …), kept only when in scope.
//
// It reads the headers the HTTP probe already stored on the Service and sends
// no request. In-scope names are dispatched as ordinary findings; the rest are
// stored as context and not expanded.
type headerRefs struct {
	name   string
	log    *slog.Logger
	source *et.Source
}

// NewHeaderRefs returns the plugin that records what response headers name.
func NewHeaderRefs() et.Plugin {
	return &headerRefs{
		name: "HTTP-Header-References",
		source: &et.Source{
			Name:       "HTTP-Header-References",
			Confidence: 90,
		},
	}
}

func (hr *headerRefs) Name() string {
	return hr.name
}

func (hr *headerRefs) Start(r et.Registry) error {
	hr.log = r.Log().WithGroup("plugin").With("name", hr.name)

	if err := r.RegisterHandler(&et.Handler{
		Plugin:       hr,
		Name:         hr.name + "-Handler",
		Position:     12,
		MaxInstances: support.MidHandlerInstances,
		Transforms:   []string{string(oam.FQDN), string(oam.URL)},
		EventType:    oam.Service,
		Callback:     hr.check,
	}); err != nil {
		return err
	}

	hr.log.Info("Plugin started")
	return nil
}

func (hr *headerRefs) Stop() {
	hr.log.Info("Plugin stopped")
}

func (hr *headerRefs) check(e *et.Event) error {
	serv, ok := e.Entity.Asset.(*platform.Service)
	if !ok {
		return errors.New("failed to extract the Service asset")
	}

	refs := parseHeaderRefs(serv.Attributes)
	if refs.empty() {
		return nil
	}

	ctx, cancel := context.WithTimeout(e.Session.Ctx(), 20*time.Second)
	defer cancel()

	for _, h := range refs.contentSources {
		hr.linkHost(ctx, e, "content_source", h)
	}
	for _, h := range refs.allowedOrigins {
		hr.linkHost(ctx, e, "allowed_origin", h)
	}
	for _, u := range refs.reportEndpoints {
		if ent, err := e.Session.DB().CreateAsset(ctx, u); err == nil && ent != nil {
			support.AddSource(ctx, e.Session, ent, hr.source)
			hr.link(ctx, e, "report_endpoint", ent)
		}
	}
	for _, h := range refs.leaked {
		fqdn := &oamdns.FQDN{Name: h}
		if _, conf := e.Session.Scope().IsAssetInScope(fqdn, 0); conf == 0 {
			continue
		}
		if ent, err := e.Session.DB().CreateAsset(ctx, fqdn); err == nil && ent != nil {
			support.AddSource(ctx, e.Session, ent, hr.source)
			hr.dispatch(e, ent, h)
		}
	}
	return nil
}

// linkHost stores a host a header names, links it from the Service by label,
// and dispatches it when it is in scope.
func (hr *headerRefs) linkHost(ctx context.Context, e *et.Event, label, host string) {
	fqdn := &oamdns.FQDN{Name: host}
	ent, err := e.Session.DB().CreateAsset(ctx, fqdn)
	if err != nil || ent == nil {
		return
	}
	support.AddSource(ctx, e.Session, ent, hr.source)
	hr.link(ctx, e, label, ent)
	if _, conf := e.Session.Scope().IsAssetInScope(fqdn, 0); conf > 0 {
		hr.dispatch(e, ent, host)
	}
}

func (hr *headerRefs) link(ctx context.Context, e *et.Event, label string, to *dbt.Entity) {
	_, _ = support.Relate(ctx, e.Session, e.Entity, &general.SimpleRelation{Name: label}, to, hr.source)
}

func (hr *headerRefs) dispatch(e *et.Event, ent *dbt.Entity, name string) {
	_ = e.Dispatcher.DispatchEvent(&et.Event{Name: name, Entity: ent, Session: e.Session})
	e.Session.Log().Info("name found in response headers", "name", name,
		slog.Group("plugin", "name", hr.name, "handler", hr.name+"-Handler"))
}

// maxHeaderRefs bounds the names one kind of reference contributes from one
// service: a policy listing hundreds of hosts says little about each.
const maxHeaderRefs = 50

// headerReferences is what a response's headers name.
type headerReferences struct {
	contentSources  []string
	allowedOrigins  []string
	reportEndpoints []*oamurl.URL
	leaked          []string
}

func (r headerReferences) empty() bool {
	return len(r.contentSources)+len(r.allowedOrigins)+len(r.reportEndpoints)+len(r.leaked) == 0
}

// cspContentDirectives are the CSP fetch and navigation directives whose
// sources are hosts the page loads content from or submits to.
var cspContentDirectives = map[string]bool{
	"default-src": true, "script-src": true, "script-src-elem": true, "script-src-attr": true,
	"style-src": true, "style-src-elem": true, "style-src-attr": true, "img-src": true, "font-src": true,
	"connect-src": true, "media-src": true, "object-src": true, "frame-src": true, "child-src": true,
	"worker-src": true, "manifest-src": true, "prefetch-src": true, "form-action": true, "base-uri": true,
}

// leakHeaders are proxy and backend headers that can carry internal host
// names.
var leakHeaders = []string{"Via", "X-Backend-Server", "X-Backend", "X-Served-By", "X-Upstream", "X-Server",
	"X-Host", "X-Forwarded-Server"}

// parseHeaderRefs reads what a response's headers name.
func parseHeaderRefs(headers map[string][]string) headerReferences {
	h := http.Header{}
	for k, vals := range headers {
		for _, v := range vals {
			h.Add(k, v)
		}
	}

	content, origins, reports := newNameSet(), newNameSet(), map[string]*oamurl.URL{}
	addReport := func(raw string) {
		if u := support.WebURL(raw); u != nil && u.Host != "" && len(reports) < maxHeaderRefs {
			reports[u.Raw] = u
		}
	}

	for _, key := range []string{"Content-Security-Policy", "Content-Security-Policy-Report-Only"} {
		for _, policy := range h.Values(key) {
			for _, directive := range strings.Split(policy, ";") {
				fields := strings.Fields(directive)
				if len(fields) < 2 {
					continue
				}
				name := strings.ToLower(fields[0])
				for _, src := range fields[1:] {
					switch {
					case cspContentDirectives[name]:
						content.add(sourceHost(src))
					case name == "frame-ancestors":
						origins.add(sourceHost(src))
					case name == "report-uri":
						addReport(src)
					}
				}
			}
		}
	}

	for _, v := range h.Values("Access-Control-Allow-Origin") {
		for _, o := range strings.Split(v, ",") {
			origins.add(sourceHost(o))
		}
	}

	for _, v := range h.Values("Report-To") {
		var groups []struct {
			Endpoints []struct {
				URL string `json:"url"`
			} `json:"endpoints"`
		}
		// several groups may be sent as one comma-joined value
		if json.Unmarshal([]byte("["+v+"]"), &groups) == nil {
			for _, g := range groups {
				for _, ep := range g.Endpoints {
					addReport(ep.URL)
				}
			}
		}
	}
	for _, v := range h.Values("Reporting-Endpoints") {
		for _, member := range strings.Split(v, ",") {
			if _, val, ok := strings.Cut(member, "="); ok {
				addReport(strings.Trim(strings.TrimSpace(val), `"`))
			}
		}
	}

	leaked := newNameSet()
	for _, key := range leakHeaders {
		for _, v := range h.Values(key) {
			for _, part := range strings.Split(v, ",") {
				for _, tok := range strings.Fields(part) {
					leaked.add(amassdns.HostName(strings.Trim(tok, "()[];")))
				}
			}
		}
	}

	out := headerReferences{contentSources: content.list(), allowedOrigins: origins.list(), leaked: leaked.list()}
	keys := make([]string, 0, len(reports))
	for k := range reports {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		out.reportEndpoints = append(out.reportEndpoints, reports[k])
	}
	return out
}

// sourceHost returns the registered host a CSP source expression or CORS
// origin names, or "" for a keyword ('self', 'none', a nonce or hash), a
// scheme alone (https:, data:, blob:), a bare wildcard or anything else that
// names no host. A wildcard (*.example.com) names its base domain.
func sourceHost(src string) string {
	src = strings.TrimSpace(src)
	if src == "" || src == "*" || strings.HasPrefix(src, "'") || strings.EqualFold(src, "null") ||
		(strings.HasSuffix(src, ":") && !strings.Contains(src, "/")) {
		return ""
	}
	if i := strings.Index(src, "://"); i >= 0 {
		src = src[i+3:]
	}
	if i := strings.IndexAny(src, "/?#"); i >= 0 {
		src = src[:i]
	}
	if i := strings.LastIndexByte(src, ':'); i >= 0 && !strings.Contains(src[i:], "]") {
		src = src[:i]
	}
	return amassdns.HostName(strings.TrimPrefix(src, "*."))
}

// nameSet keeps names once each, in order, up to maxHeaderRefs.
type nameSet struct {
	seen  map[string]bool
	names []string
}

func newNameSet() *nameSet { return &nameSet{seen: map[string]bool{}} }

func (n *nameSet) add(name string) {
	if name == "" || n.seen[name] || len(n.names) >= maxHeaderRefs {
		return
	}
	n.seen[name] = true
	n.names = append(n.names, name)
}

func (n *nameSet) list() []string { return n.names }
