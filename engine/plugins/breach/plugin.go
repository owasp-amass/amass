// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

// Package breach records, for an in-scope email identifier, which known data
// breaches it appears in — the breach name, date and the categories of data
// exposed — from defensive breach-exposure sources (XposedOrNot by default,
// Have I Been Pwned with a key). This is a genuine observation from an outside
// authority, so it is stored (ai-design-principles.md, principle 10), as
// breach properties on the email Identifier.
//
// Metadata only: it records that an address was exposed, never the leaked
// secret. It is opt-in — a source runs only when the operator has enabled it
// in the data-source configuration (and a keyed source only with a key) — and
// it never expands scope.
package breach

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"strings"
	"time"

	"github.com/owasp-amass/amass/v5/engine/plugins/support"
	et "github.com/owasp-amass/amass/v5/engine/types"
	"github.com/owasp-amass/amass/v5/internal/graph"
	amasshttp "github.com/owasp-amass/amass/v5/internal/net/http"
	"github.com/owasp-amass/amass/v5/internal/semantics/breachsources"
	oam "github.com/owasp-amass/open-asset-model"
	oamgen "github.com/owasp-amass/open-asset-model/general"
	"golang.org/x/time/rate"
)

// breachTTL is how long an identifier is left before it is checked again.
// Breach data changes slowly, so a weekly re-check is ample.
const breachTTL = 7 * 24 * time.Hour

// fetcher fetches a source response; a field so tests can supply responses
// without the network.
type fetcher func(ctx context.Context, sess et.Session, reqURL, apiKey string) ([]byte, error)

type plugin struct {
	name   string
	log    *slog.Logger
	source *et.Source
	rlimit *rate.Limiter
	fetch  fetcher
}

// NewBreachExposure returns the breach-exposure plugin.
func NewBreachExposure() et.Plugin {
	p := &plugin{
		name:   "Breach-Exposure",
		rlimit: rate.NewLimiter(rate.Every(2*time.Second), 1),
		source: &et.Source{Name: "Breach-Exposure", Confidence: 90},
	}
	p.fetch = p.httpFetch
	return p
}

func (p *plugin) Name() string { return p.name }

func (p *plugin) Start(r et.Registry) error {
	p.log = r.Log().WithGroup("plugin").With("name", p.name)

	if err := r.RegisterHandler(&et.Handler{
		Plugin:       p,
		Name:         p.name + "-Handler",
		Position:     50,
		MaxInstances: support.MinHandlerInstances,
		Transforms:   []string{string(oam.Identifier)},
		EventType:    oam.Identifier,
		Callback:     p.check,
	}); err != nil {
		return err
	}

	p.log.Info("Plugin started")
	return nil
}

func (p *plugin) Stop() { p.log.Info("Plugin stopped") }

// check records the breach exposure of one in-scope email identifier, once
// per TTL.
func (p *plugin) check(e *et.Event) error {
	if e == nil || e.Entity == nil || e.Entity.Asset == nil {
		return nil
	}
	id, ok := e.Entity.Asset.(*oamgen.Identifier)
	if !ok {
		return errors.New("failed to extract the Identifier asset")
	}
	if id.Type != oamgen.EmailAddress || id.ID == "" {
		return nil
	}
	if emailDomain(id.ID) == "" {
		return nil
	}

	since, err := support.TTLStartTime(e.Session.Config(), string(oam.Identifier), string(oam.Identifier), p.name)
	if err != nil {
		return err
	}
	if support.AssetMonitoredWithinTTL(e.Session, e.Entity, p.source, since) {
		return nil
	}

	records := p.lookup(e.Session, id.ID)
	support.MarkAssetMonitored(e.Session, e.Entity, p.source)
	if len(records) == 0 {
		return nil
	}
	return p.record(e, records)
}

// lookup queries every enabled source for an email's breach exposure and
// returns the breaches found, one per breach name.
func (p *plugin) lookup(sess et.Session, email string) []graph.BreachInfo {
	var out []graph.BreachInfo
	seen := map[string]bool{}
	for _, src := range breachsources.Sources() {
		if src.EmailFormat == "" {
			continue
		}
		key, ok := p.credential(sess, src)
		if !ok {
			continue
		}
		for _, r := range p.querySource(sess, src, email, key) {
			if r.Breach == "" || seen[r.Breach] {
				continue
			}
			seen[r.Breach] = true
			out = append(out, r)
		}
	}
	return out
}

// credential reports whether a source is enabled and returns its API key. A
// source is enabled only when the operator has added it to the data-source
// configuration (opt-in); a keyed source additionally needs a key.
func (p *plugin) credential(sess et.Session, src breachsources.Source) (string, bool) {
	ds := sess.Config().GetDataSourceConfig(src.Name)
	if ds == nil {
		return "", false
	}
	if !src.RequiresKey {
		return "", true
	}
	for _, cr := range ds.Creds {
		if cr != nil && cr.Apikey != "" {
			return cr.Apikey, true
		}
	}
	return "", false
}

// querySource fetches and parses one source's email response into breach
// records, tagged with the source name.
func (p *plugin) querySource(sess et.Session, src breachsources.Source, email, key string) []graph.BreachInfo {
	reqURL := strings.ReplaceAll(src.EmailURL, "{email}", url.QueryEscape(email))

	ctx, cancel := context.WithTimeout(sess.Ctx(), 30*time.Second)
	defer cancel()

	data, err := p.fetch(ctx, sess, reqURL, key)
	if err != nil {
		p.log.Warn(fmt.Sprintf("%s lookup failed: %v", src.Name, err))
		return nil
	}
	records, err := breachsources.Parse(src.EmailFormat, data)
	if err != nil {
		p.log.Warn(fmt.Sprintf("%s response: %v", src.Name, err))
		return nil
	}

	out := make([]graph.BreachInfo, 0, len(records))
	for _, r := range records {
		out = append(out, graph.BreachInfo{Breach: r.Breach, Date: r.Date, DataClasses: r.DataClasses,
			Source: src.Name, Verified: r.Verified})
	}
	return out
}

// record stores the breaches as properties on the email identifier, one per
// breach, metadata only.
func (p *plugin) record(e *et.Event, records []graph.BreachInfo) error {
	ctx, cancel := context.WithTimeout(e.Session.Ctx(), 20*time.Second)
	defer cancel()

	for _, b := range records {
		value, err := graph.EncodeBreach(b)
		if err != nil {
			continue
		}
		if _, err := e.Session.DB().CreateEntityProperty(ctx, e.Entity,
			&oamgen.SimpleProperty{PropertyName: graph.BreachProperty, PropertyValue: value}); err != nil {
			return err
		}
	}
	support.AddSource(ctx, e.Session, e.Entity, p.source)

	p.log.Info("breach exposure recorded", "identifier", e.Entity.Asset.Key(),
		"breaches", len(records), slog.Group("plugin", "name", p.name, "handler", p.name+"-Handler"))
	return nil
}

// httpFetch fetches a source response over the shared HTTP client, paced and
// counted, adding the API key header when one is given.
func (p *plugin) httpFetch(ctx context.Context, sess et.Session, reqURL, apiKey string) ([]byte, error) {
	_ = support.WaitLimit(ctx, p.rlimit)
	sess.NetSem().Acquire()
	defer sess.NetSem().Release()

	req := &amasshttp.Request{URL: reqURL}
	if apiKey != "" {
		req.Header = amasshttp.Header{"hibp-api-key": {apiKey}}
	}
	resp, err := amasshttp.RequestWebPage(ctx, sess.Clients().General, req)
	if err != nil {
		return nil, err
	}
	return []byte(resp.Body), nil
}

// emailDomain returns the registered domain of an email address, or an empty
// string when it has none.
func emailDomain(email string) string {
	at := strings.LastIndex(email, "@")
	if at < 0 || at == len(email)-1 {
		return ""
	}
	return graph.RegisteredDomain(email[at+1:])
}
