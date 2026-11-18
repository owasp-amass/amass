// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/url"
	"strings"
	"time"

	"github.com/owasp-amass/amass/v5/engine/plugins/support"
	et "github.com/owasp-amass/amass/v5/engine/types"
	amassdns "github.com/owasp-amass/amass/v5/internal/net/dns"
	amasshttp "github.com/owasp-amass/amass/v5/internal/net/http"
	dbt "github.com/owasp-amass/asset-db/types"
	oam "github.com/owasp-amass/open-asset-model"
	oamcert "github.com/owasp-amass/open-asset-model/certificate"
	oamcontact "github.com/owasp-amass/open-asset-model/contact"
	oamdns "github.com/owasp-amass/open-asset-model/dns"
	oamgen "github.com/owasp-amass/open-asset-model/general"
	oamorg "github.com/owasp-amass/open-asset-model/org"
	"golang.org/x/time/rate"
)

// crtshOrg is a horizontal-discovery collector: for an in-scope Organization it
// asks crt.sh for the certificates whose subject Organization (O=) is that org,
// and records each as a TLSCertificate tied to the org by a subject contact,
// with its common-name FQDN. Those certificates are the evidence the
// related-domains lens turns into candidate apex domains for review — this
// collector never adds anything to scope itself (ai-design-principles.md,
// principles 10 & 13). Unlike the vertical crt.sh collector (triggered on an
// FQDN to find subdomains), this is triggered on an Organization.
type crtshOrg struct {
	name   string
	log    *slog.Logger
	rlimit *rate.Limiter
	source *et.Source
}

// crtshOrgMaxCerts bounds the certificates stored for one organization, so a
// large or over-broad O= match cannot force unbounded writes.
const crtshOrgMaxCerts = 500

func NewCrtshOrg() et.Plugin {
	return &crtshOrg{
		name:   "crt.sh-Organization",
		rlimit: rate.NewLimiter(rate.Every(2*time.Second), 1),
		source: &et.Source{Name: "crt.sh", Confidence: 100},
	}
}

func (c *crtshOrg) Name() string { return c.name }

func (c *crtshOrg) Start(r et.Registry) error {
	c.log = r.Log().WithGroup("plugin").With("name", c.name)

	if err := r.RegisterHandler(&et.Handler{
		Plugin:       c,
		Name:         c.name + "-Handler",
		Position:     48,
		MaxInstances: support.MidHandlerInstances,
		Transforms:   []string{string(oam.TLSCertificate), string(oam.FQDN), string(oam.ContactRecord)},
		EventType:    oam.Organization,
		Callback:     c.check,
	}); err != nil {
		return err
	}

	c.log.Info("Plugin started")
	return nil
}

func (c *crtshOrg) Stop() { c.log.Info("Plugin stopped") }

func (c *crtshOrg) check(e *et.Event) error {
	o, ok := e.Entity.Asset.(*oamorg.Organization)
	if !ok {
		return errors.New("failed to cast the Organization asset")
	}
	// Horizontal discovery only runs when scope expansion is allowed.
	if e.Session.Config().Rigid || strings.TrimSpace(o.Name) == "" {
		return nil
	}

	since, err := support.TTLStartTime(e.Session.Config(),
		string(oam.Organization), string(oam.TLSCertificate), c.name)
	if err != nil {
		return err
	}
	if support.AssetMonitoredWithinTTL(e.Session, e.Entity, c.source, since) {
		return nil
	}

	body := c.query(e, o.Name)
	support.MarkAssetMonitored(e.Session, e.Entity, c.source)
	if body == "" {
		return nil
	}

	if certs := crtshOrgCerts(body, o.Name); len(certs) > 0 {
		c.store(e, e.Entity, certs)
	}
	return nil
}

func (c *crtshOrg) query(e *et.Event, orgName string) string {
	_ = support.WaitLimit(e.Session.Ctx(), c.rlimit)
	e.Session.NetSem().Acquire()
	defer e.Session.NetSem().Release()

	// crt.sh O= queries are slow (a full-text search over all certificates).
	ctx, cancel := context.WithTimeout(e.Session.Ctx(), 4*time.Minute)
	defer cancel()

	resp, err := amasshttp.RequestWebPage(ctx, e.Session.Clients().General, &amasshttp.Request{
		URL: "https://crt.sh/?O=" + url.QueryEscape(orgName) + "&output=json&exclude=expired&deduplicate=Y",
	})
	if err != nil || resp == nil {
		return ""
	}
	return resp.Body
}

// crtOrgEntry is one crt.sh result from an O= query: the domain is in
// common_name, and name_value echoes the matched subject organization.
type crtOrgEntry struct {
	CommonName   string `json:"common_name"`
	NameValue    string `json:"name_value"`
	SerialNumber string `json:"serial_number"`
}

// crtshOrgCerts parses a crt.sh O= JSON response and returns the certificates
// whose matched identity (name_value) confirms the queried organization,
// deduplicated by serial number, each with its common-name domain. It is a pure
// function so the parse is tested against a real saved response.
func crtshOrgCerts(body, org string) []crtOrgEntry {
	var entries []crtOrgEntry
	if err := json.Unmarshal([]byte(strings.TrimSpace(body)), &entries); err != nil {
		return nil
	}

	orgNorm := strings.ToLower(strings.TrimSpace(org))
	seen := make(map[string]bool)
	var out []crtOrgEntry
	for _, e := range entries {
		cn := strings.ToLower(strings.TrimSpace(amassdns.RemoveAsteriskLabel(e.CommonName)))
		if cn == "" || e.SerialNumber == "" {
			continue
		}
		// crt.sh echoes the matched subject organization in name_value; require
		// it to confirm the org (the O= filter is server-side, this guards it).
		if orgNorm != "" && !strings.Contains(strings.ToLower(e.NameValue), orgNorm) {
			continue
		}
		if seen[e.SerialNumber] {
			continue
		}
		seen[e.SerialNumber] = true
		out = append(out, crtOrgEntry{CommonName: cn, NameValue: e.NameValue, SerialNumber: e.SerialNumber})
	}
	return out
}

// store records each certificate as a TLSCertificate tied to the organization
// by a subject contact, plus the certificate's common-name FQDN. The
// organization is the triggering entity, so the contact links to it directly.
func (c *crtshOrg) store(e *et.Event, orgent *dbt.Entity, certs []crtOrgEntry) {
	ctx, cancel := context.WithTimeout(e.Session.Ctx(), 2*time.Minute)
	defer cancel()

	for i, ce := range certs {
		if i >= crtshOrgMaxCerts {
			break
		}

		certent, err := e.Session.DB().CreateAsset(ctx,
			&oamcert.TLSCertificate{SerialNumber: ce.SerialNumber, SubjectCommonName: ce.CommonName})
		if err != nil || certent == nil {
			continue
		}
		c.tag(ctx, e, certent)

		crent, err := e.Session.DB().CreateAsset(ctx,
			&oamcontact.ContactRecord{DiscoveredAt: "crt.sh O= " + ce.SerialNumber})
		if err == nil && crent != nil {
			c.tag(ctx, e, crent)
			c.link(ctx, e, certent, crent, "subject_contact")
			c.link(ctx, e, crent, orgent, "organization")
		}

		if fqdn, err := e.Session.DB().CreateAsset(ctx, &oamdns.FQDN{Name: ce.CommonName}); err == nil && fqdn != nil {
			c.tag(ctx, e, fqdn)
			c.link(ctx, e, certent, fqdn, "common_name")
		}
	}
}

func (c *crtshOrg) tag(ctx context.Context, e *et.Event, ent *dbt.Entity) {
	_, _ = e.Session.DB().CreateEntityProperty(ctx, ent,
		&oamgen.SourceProperty{Source: c.source.Name, Confidence: c.source.Confidence})
}

func (c *crtshOrg) link(ctx context.Context, e *et.Event, from, to *dbt.Entity, label string) {
	edge, err := e.Session.DB().CreateEdge(ctx, &dbt.Edge{
		Relation:   &oamgen.SimpleRelation{Name: label},
		FromEntity: from,
		ToEntity:   to,
	})
	if err == nil && edge != nil {
		_, _ = e.Session.DB().CreateEdgeProperty(ctx, edge,
			&oamgen.SourceProperty{Source: c.source.Name, Confidence: c.source.Confidence})
	}
}
