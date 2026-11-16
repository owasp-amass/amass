// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

// Package cloud attributes an in-scope IP address to the public cloud or CDN
// provider that operates it, from the ranges the provider publishes itself.
// For an address that falls in a published range it records the provider as
// a Netblock -> provider -> Organization relationship on the published
// prefix, with the provider's region and service as properties. This is a
// hosting observation, not ownership: it says who operates the network, like
// an autonomous system announcing a block, and never that the provider owns
// the addresses' tenants (ai-design-principles.md, principle 8). It needs no
// model.
package cloud

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/owasp-amass/amass/v5/engine/plugins/support"
	"github.com/owasp-amass/amass/v5/engine/plugins/support/org"
	et "github.com/owasp-amass/amass/v5/engine/types"
	amasshttp "github.com/owasp-amass/amass/v5/internal/net/http"
	"github.com/owasp-amass/amass/v5/internal/semantics/cloudranges"
	dbt "github.com/owasp-amass/asset-db/types"
	oam "github.com/owasp-amass/open-asset-model"
	oamgen "github.com/owasp-amass/open-asset-model/general"
	oamnet "github.com/owasp-amass/open-asset-model/network"
	oamorg "github.com/owasp-amass/open-asset-model/org"
	"golang.org/x/time/rate"
)

// feedTTL is how long a built matcher is reused before the feeds are fetched
// again. The ranges change slowly and the feeds are large, so one refresh a
// day keeps every provider current without repeated downloads.
const feedTTL = 24 * time.Hour

// Property names recorded on a provider's netblock for the matched prefix.
const (
	propCloudRegion  = "cloud_region"
	propCloudService = "cloud_service"
)

// fetcher fetches a feed's bytes. It is a field so tests can supply feeds
// without the network.
type fetcher func(ctx context.Context, sess et.Session, url string) ([]byte, error)

type plugin struct {
	name   string
	log    *slog.Logger
	source *et.Source
	rlimit *rate.Limiter
	ttl    time.Duration
	fetch  fetcher

	mu      sync.Mutex
	matcher *cloudranges.Matcher
	built   time.Time
}

// NewCloudRanges returns the cloud and CDN range attribution plugin.
func NewCloudRanges() et.Plugin {
	p := &plugin{
		name:   "Cloud-Ranges",
		rlimit: rate.NewLimiter(rate.Every(time.Second), 1),
		ttl:    feedTTL,
		// A provider's own published feed is authoritative for the ranges it
		// operates.
		source: &et.Source{Name: "Cloud-Ranges", Confidence: 100},
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
		Transforms:   []string{string(oam.Netblock), string(oam.Organization)},
		EventType:    oam.IPAddress,
		Callback:     p.check,
	}); err != nil {
		return err
	}

	p.log.Info("Plugin started")
	return nil
}

func (p *plugin) Stop() { p.log.Info("Plugin stopped") }

// check attributes one in-scope address to its cloud or CDN provider, once
// per TTL.
func (p *plugin) check(e *et.Event) error {
	if e == nil || e.Entity == nil || e.Entity.Asset == nil {
		return nil
	}
	ip, ok := e.Entity.Asset.(*oamnet.IPAddress)
	if !ok {
		return errors.New("failed to extract the IPAddress asset")
	}
	// Only addresses the enumeration is scoped to are attributed, so the
	// writes stay bounded and relevant.
	if _, conf := e.Session.Scope().IsAssetInScope(ip, 0); conf <= 0 {
		return nil
	}

	since, err := support.TTLStartTime(e.Session.Config(), string(oam.IPAddress), string(oam.IPAddress), p.name)
	if err != nil {
		return err
	}
	if support.AssetMonitoredWithinTTL(e.Session, e.Entity, p.source, since) {
		return nil
	}

	m, err := p.ensureMatcher(e.Session)
	if err != nil {
		return err
	}
	support.MarkAssetMonitored(e.Session, e.Entity, p.source)

	match, ok := m.Match(ip.Address)
	if !ok {
		return nil
	}
	return p.record(e, match)
}

// ensureMatcher returns a matcher built from the provider feeds, rebuilding
// it when the current one is older than the TTL. A feed that cannot be
// fetched or parsed is skipped with a log line rather than failing the
// others, so one unreachable provider does not block attribution.
func (p *plugin) ensureMatcher(sess et.Session) (*cloudranges.Matcher, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.matcher != nil && time.Since(p.built) < p.ttl {
		return p.matcher, nil
	}

	m := cloudranges.NewMatcher()
	for _, provider := range cloudranges.Providers() {
		for _, feed := range provider.Feeds {
			if err := sess.Ctx().Err(); err != nil {
				return nil, err
			}

			data, err := p.fetch(sess.Ctx(), sess, feed.URL)
			if err != nil {
				p.log.Warn(fmt.Sprintf("cloud feed %s unreachable: %v", feed.URL, err))
				continue
			}
			prefixes, err := cloudranges.ParseFeed(feed, data)
			if err != nil {
				p.log.Warn(fmt.Sprintf("cloud feed %s: %v", feed.URL, err))
				continue
			}
			m.Add(provider, prefixes)
		}
	}

	p.matcher, p.built = m, time.Now()
	return p.matcher, nil
}

// record stores the provider attribution for a matched address: the
// published prefix as a netblock, the provider as a provider Organization on
// it, and the provider's region and service as properties.
func (p *plugin) record(e *et.Event, match cloudranges.Match) error {
	ctx, cancel := context.WithTimeout(e.Session.Ctx(), 30*time.Second)
	defer cancel()

	nbType := "IPv4"
	if match.Prefix.Addr().Is6() {
		nbType = "IPv6"
	}
	nbEnt, err := e.Session.DB().CreateAsset(ctx, &oamnet.Netblock{Type: nbType, CIDR: match.Prefix})
	if err != nil || nbEnt == nil {
		return fmt.Errorf("failed to create the provider netblock %s: %w", match.Prefix, err)
	}
	_, _ = e.Session.DB().CreateEntityProperty(ctx, nbEnt, &oamgen.SourceProperty{
		Source:     p.source.Name,
		Confidence: p.source.Confidence,
	})

	// The published prefix contains the matched address.
	if edge, err := e.Session.DB().CreateEdge(ctx, &dbt.Edge{
		Relation:   &oamgen.SimpleRelation{Name: "contains"},
		FromEntity: nbEnt,
		ToEntity:   e.Entity,
	}); err == nil && edge != nil {
		_, _ = e.Session.DB().CreateEdgeProperty(ctx, edge, &oamgen.SourceProperty{
			Source:     p.source.Name,
			Confidence: p.source.Confidence,
		})
	}

	// The provider operates the prefix: a provider Organization on the
	// netblock, reconciled with any organization of the same name already
	// stored. CreateOrgAsset validates the relation against the taxonomy.
	orgEnt, err := org.CreateOrgAsset(e.Session, nbEnt, &oamgen.SimpleRelation{Name: "provider"},
		&oamorg.Organization{Name: match.Organization}, p.source)
	if err != nil {
		return fmt.Errorf("failed to record provider %s: %w", match.Organization, err)
	}

	if match.Region != "" {
		_, _ = e.Session.DB().CreateEntityProperty(ctx, nbEnt, &oamgen.SimpleProperty{
			PropertyName: propCloudRegion, PropertyValue: match.Region})
	}
	if match.Service != "" {
		_, _ = e.Session.DB().CreateEntityProperty(ctx, nbEnt, &oamgen.SimpleProperty{
			PropertyName: propCloudService, PropertyValue: match.Service})
	}

	p.log.Info("relationship discovered", "from", match.Prefix.String(), "relation", "provider",
		"to", match.Organization, slog.Group("plugin", "name", p.name, "handler", p.name+"-Handler"))

	_ = e.Dispatcher.DispatchEvent(&et.Event{Name: nbEnt.Asset.Key(), Entity: nbEnt, Session: e.Session})
	if orgEnt != nil {
		_ = e.Dispatcher.DispatchEvent(&et.Event{Name: orgEnt.Asset.Key(), Entity: orgEnt, Session: e.Session})
	}
	return nil
}

// httpFetch fetches a feed over the session's shared HTTP client, paced by
// the plugin's rate limiter and counted by the network semaphore like any
// other outbound request.
func (p *plugin) httpFetch(ctx context.Context, sess et.Session, url string) ([]byte, error) {
	_ = support.WaitLimit(ctx, p.rlimit)
	sess.NetSem().Acquire()
	defer sess.NetSem().Release()

	resp, err := amasshttp.RequestWebPage(ctx, sess.Clients().General, &amasshttp.Request{URL: url})
	if err != nil {
		return nil, err
	}
	return []byte(resp.Body), nil
}
