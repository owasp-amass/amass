// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

// Package bucket probes public object-storage buckets that the enumeration has
// already observed — a name in the graph (a CNAME target or certificate SAN)
// whose host matches a provider in internal/semantics/bucket_providers.json.
// It never guesses bucket names and never lists or fetches objects: in active
// mode it makes a single paced request to the bucket root to tell whether the
// bucket exists, is missing (the subdomain-takeover case), or is world-readable,
// and records that as an observation. Recognition of a bucket endpoint from a
// stored name is left to the lenses (a computed conclusion); only the probe
// outcome is stored. See claude/unit4-bucket-discovery-spec.md.
package bucket

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/owasp-amass/amass/v5/engine/plugins/support"
	et "github.com/owasp-amass/amass/v5/engine/types"
	amasshttp "github.com/owasp-amass/amass/v5/internal/net/http"
	"github.com/owasp-amass/amass/v5/internal/semantics"
	dbt "github.com/owasp-amass/asset-db/types"
	oam "github.com/owasp-amass/open-asset-model"
	oamdns "github.com/owasp-amass/open-asset-model/dns"
	oamgen "github.com/owasp-amass/open-asset-model/general"
	"golang.org/x/time/rate"
)

// minBucketName is the shortest valid bucket/account name across the providers;
// it also screens out generic redirect labels such as GCS's "c" host.
const minBucketName = 3

type bucketProbe struct {
	name   string
	log    *slog.Logger
	rlimit *rate.Limiter
	source *et.Source
}

func NewBucketProbe() et.Plugin {
	return &bucketProbe{
		name:   "BucketProbe",
		rlimit: rate.NewLimiter(rate.Every(2*time.Second), 1),
		source: &et.Source{Name: "BucketProbe", Confidence: 80},
	}
}

func (p *bucketProbe) Name() string { return p.name }

func (p *bucketProbe) Start(r et.Registry) error {
	p.log = r.Log().WithGroup("plugin").With("name", p.name)

	if err := r.RegisterHandler(&et.Handler{
		Plugin:       p,
		Name:         p.name + "-Handler",
		Position:     43,
		MaxInstances: support.MidHandlerInstances,
		Transforms:   []string{string(oam.Service)},
		EventType:    oam.FQDN,
		Callback:     p.check,
	}); err != nil {
		return err
	}

	p.log.Info("Plugin started")
	return nil
}

func (p *bucketProbe) Stop() { p.log.Info("Plugin stopped") }

func (p *bucketProbe) check(e *et.Event) error {
	fqdn, ok := e.Entity.Asset.(*oamdns.FQDN)
	if !ok {
		return nil
	}

	// Observed-name mining only: act only when this name is itself a known bucket
	// endpoint already in the graph (reached from the scope as a CNAME target or
	// cert SAN). No name guessing, no permutation.
	prov, bucket, ok := semantics.MatchBucketHost(fqdn.Name)
	if !ok || len(bucket) < minBucketName {
		return nil
	}

	// The existence/listing request is a light active probe: active mode only,
	// paced, rate-limited and TTL-guarded, like the service probes.
	if !e.Session.Config().Active {
		return nil
	}

	since, err := support.TTLStartTime(e.Session.Config(), string(oam.FQDN), string(oam.Service), p.name)
	if err != nil {
		return err
	}
	if support.AssetMonitoredWithinTTL(e.Session, e.Entity, p.source, since) {
		return nil
	}
	support.MarkAssetMonitored(e.Session, e.Entity, p.source)

	p.probe(e, e.Entity, fqdn.Name, prov, bucket)
	return nil
}

// probe makes the single bucket-root request and records the outcome.
func (p *bucketProbe) probe(e *et.Event, host *dbt.Entity, name string, prov semantics.BucketProvider, bucket string) {
	url := strings.ReplaceAll(prov.Endpoint, "{host}", name)
	url = strings.ReplaceAll(url, "{bucket}", bucket)

	if err := support.PaceProbe(e, name); err != nil {
		return
	}
	_ = support.WaitLimit(e.Session.Ctx(), p.rlimit)

	method := prov.Method
	if method == "" {
		method = "GET"
	}

	e.Session.NetSem().Acquire()
	ctx, cancel := context.WithTimeout(e.Session.Ctx(), 15*time.Second)
	resp, err := amasshttp.RequestWebPage(ctx, e.Session.Clients().Probe, &amasshttp.Request{URL: url, Method: method})
	cancel()
	e.Session.NetSem().Release()
	if err != nil || resp == nil {
		return
	}

	status := classify(prov, resp)
	if status == "" {
		return
	}

	p.store(e, host, name, prov, bucket, status)
}

// classify maps a bucket-root response to exists, public or absent, using the
// provider's signatures from the catalog.
func classify(prov semantics.BucketProvider, resp *amasshttp.Response) string {
	switch {
	case matchSig(prov.PublicListing, resp):
		return "public"
	case matchSig(prov.NotFound, resp):
		return "absent"
	case resp.StatusCode == 403 || (resp.StatusCode >= 200 && resp.StatusCode < 400):
		// A 2xx/3xx that is not a not-found, or an AccessDenied, is a bucket that
		// exists but is not open.
		return "exists"
	}

	return ""
}

// matchSig reports whether resp satisfies every constraint the signature sets
// (status and/or body substring).
func matchSig(sig semantics.BucketSignature, resp *amasshttp.Response) bool {
	if len(sig.Status) == 0 && len(sig.BodyContains) == 0 {
		return false
	}
	if len(sig.Status) > 0 {
		ok := false
		for _, s := range sig.Status {
			if s == resp.StatusCode {
				ok = true
				break
			}
		}
		if !ok {
			return false
		}
	}
	if len(sig.BodyContains) > 0 {
		ok := false
		for _, sub := range sig.BodyContains {
			if strings.Contains(resp.Body, sub) {
				ok = true
				break
			}
		}
		if !ok {
			return false
		}
	}

	return true
}

// store records the probe outcome on the bucket host (for the dangling lens's
// takeover confirmation) and, for a live bucket, materializes an object-storage
// Service as attack-surface inventory.
func (p *bucketProbe) store(e *et.Event, host *dbt.Entity, name string, prov semantics.BucketProvider,
	bucket, status string) {
	ctx, cancel := context.WithTimeout(e.Session.Ctx(), 15*time.Second)
	defer cancel()

	p.property(ctx, e, host, "bucket_status", status)
	p.property(ctx, e, host, "bucket_provider", prov.Organization)
	p.property(ctx, e, host, "bucket_name", bucket)

	if status == "exists" || status == "public" {
		serv := support.ServiceWithIdentifier(name, "tcp", 443)
		serv.Type = "object-storage"

		portrel := &oamgen.PortRelation{Name: "tcp_port_443", PortNumber: 443, Protocol: "TCP"}
		s, err := support.CreateServiceAsset(e.Session, host, portrel, serv, nil)
		if err == nil && s != nil {
			p.property(ctx, e, s, "provider", prov.Organization)
			p.property(ctx, e, s, "bucket", bucket)
			p.property(ctx, e, s, "public", fmt.Sprintf("%t", status == "public"))

			findings := []*support.Finding{{
				From: host, FromName: host.Asset.Key(), To: s, ToName: "Service: " + serv.ID, Rel: portrel,
			}}
			support.ProcessAssetsWithSource(e, findings, p.source, p.name, p.name+"-Handler")
		}
	}

	e.Session.Log().Info("bucket probed", "host", name, "provider", prov.Key, "bucket", bucket, "status", status,
		slog.Group("plugin", "name", p.name, "handler", p.name+"-Handler"))
}

func (p *bucketProbe) property(ctx context.Context, e *et.Event, entity *dbt.Entity, name, value string) {
	if value == "" {
		return
	}
	_, _ = e.Session.DB().CreateEntityProperty(ctx, entity,
		&oamgen.SimpleProperty{PropertyName: name, PropertyValue: value})
}
