// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package rdap

import (
	"context"
	"crypto/tls"
	"errors"
	"log/slog"
	"net/http"
	"path/filepath"
	"strings"
	"time"

	"github.com/caffix/stringset"
	"github.com/openrdap/rdap"
	"github.com/openrdap/rdap/bootstrap"
	"github.com/openrdap/rdap/bootstrap/cache"
	"github.com/owasp-amass/amass/v5/config"
	"github.com/owasp-amass/amass/v5/engine/plugins/support"
	"github.com/owasp-amass/amass/v5/engine/plugins/support/org"
	et "github.com/owasp-amass/amass/v5/engine/types"
	"github.com/owasp-amass/amass/v5/internal/net/pacer"
	"github.com/owasp-amass/amass/v5/internal/semantics"
	dbt "github.com/owasp-amass/asset-db/types"
	oam "github.com/owasp-amass/open-asset-model"
	"github.com/owasp-amass/open-asset-model/contact"
	"github.com/owasp-amass/open-asset-model/general"
	oamreg "github.com/owasp-amass/open-asset-model/registration"
	"github.com/owasp-amass/open-asset-model/url"
	"golang.org/x/time/rate"
)

type rdapPlugin struct {
	name     string
	log      *slog.Logger
	client   *rdap.Client
	rlimit   *rate.Limiter
	autsys   *autsys
	autnum   *recordDetail
	netblock *netblock
	ipnet    *recordDetail
	domain   *domain
	domrec   *recordDetail
	source   *et.Source
}

func NewRDAP() et.Plugin {
	limit := rate.Every(2 * time.Second)

	return &rdapPlugin{
		name:   "RDAP",
		rlimit: rate.NewLimiter(limit, 1),
		source: &et.Source{
			Name:       "RDAP",
			Confidence: 100,
		},
	}
}

func (rd *rdapPlugin) Name() string {
	return rd.name
}

func (rd *rdapPlugin) Start(r et.Registry) error {
	rd.log = r.Log().WithGroup("plugin").With("name", rd.name)

	outdir := config.OutputDirectory()
	if outdir == "" {
		return errors.New("failed to obtain the Amass output directory")
	}

	c := cache.NewDiskCache()
	if c == nil {
		return errors.New("failed to create the RDAP disk cache")
	}
	c.Dir = filepath.Join(outdir, ".openrdap")

	bs := &bootstrap.Client{Cache: c}
	tlsConfig := &tls.Config{InsecureSkipVerify: true}
	transport := &http.Transport{
		Proxy:           http.ProxyFromEnvironment,
		TLSClientConfig: tlsConfig,
	}
	// registries refuse a burst (ARIN answers 429); pace each one adaptively
	paced := pacer.Default.Transport(transport)
	bs.HTTP = &http.Client{
		Transport: paced,
	}
	httpClient := &http.Client{
		Transport: paced,
	}
	rd.client = &rdap.Client{
		HTTP:      httpClient,
		Bootstrap: bs,
	}

	rd.autsys = &autsys{
		name:   rd.name + "-Autsys-Handler",
		plugin: rd,
	}
	if err := r.RegisterHandler(&et.Handler{
		Plugin:       rd,
		Name:         rd.autsys.name,
		Position:     40,
		Exclusive:    true,
		MaxInstances: support.MinHandlerInstances,
		Transforms:   []string{string(oam.AutnumRecord)},
		EventType:    oam.AutonomousSystem,
		Callback:     rd.autsys.check,
	}); err != nil {
		return err
	}

	rd.autnum = newRecordDetail(rd, oam.AutnumRecord)
	if err := r.RegisterHandler(&et.Handler{
		Plugin:       rd,
		Name:         rd.autnum.name,
		Position:     2,
		Exclusive:    true,
		MaxInstances: support.MidHandlerInstances,
		Transforms:   rd.autnum.transforms,
		EventType:    oam.AutnumRecord,
		Callback:     rd.autnum.check,
	}); err != nil {
		return err
	}

	rd.netblock = &netblock{
		name:   rd.name + "-Netblock-Handler",
		plugin: rd,
	}
	if err := r.RegisterHandler(&et.Handler{
		Plugin:       rd,
		Name:         rd.netblock.name,
		Position:     40,
		Exclusive:    true,
		MaxInstances: support.MinHandlerInstances,
		Transforms:   []string{string(oam.IPNetRecord)},
		EventType:    oam.Netblock,
		Callback:     rd.netblock.check,
	}); err != nil {
		return err
	}

	rd.ipnet = newRecordDetail(rd, oam.IPNetRecord)
	if err := r.RegisterHandler(&et.Handler{
		Plugin:       rd,
		Name:         rd.ipnet.name,
		Position:     2,
		Exclusive:    true,
		MaxInstances: support.MidHandlerInstances,
		Transforms:   rd.ipnet.transforms,
		EventType:    oam.IPNetRecord,
		Callback:     rd.ipnet.check,
	}); err != nil {
		return err
	}

	rd.domain = &domain{
		name:   rd.name + "-Domain-Handler",
		plugin: rd,
	}
	if err := r.RegisterHandler(&et.Handler{
		Plugin:   rd,
		Name:     rd.domain.name,
		Position: 14,
		// Shares the stage with the WHOIS FQDN handler: RDAP and WHOIS are
		// peer registration sources that both enrich the apex DomainRecord,
		// so neither is exclusive at this position.
		Exclusive:    false,
		MaxInstances: support.MidHandlerInstances,
		Transforms:   []string{string(oam.DomainRecord)},
		EventType:    oam.FQDN,
		Callback:     rd.domain.check,
	}); err != nil {
		return err
	}

	rd.domrec = newRecordDetail(rd, oam.DomainRecord)
	if err := r.RegisterHandler(&et.Handler{
		Plugin:   rd,
		Name:     rd.domrec.name,
		Position: 2,
		// Peer of the WHOIS DomainRecord handler at this stage; both enrich
		// the record from their own source, so neither is exclusive.
		Exclusive:    false,
		MaxInstances: support.MidHandlerInstances,
		Transforms:   rd.domrec.transforms,
		EventType:    oam.DomainRecord,
		Callback:     rd.domrec.check,
	}); err != nil {
		return err
	}

	rd.log.Info("Plugin started")
	return nil
}

func (rd *rdapPlugin) Stop() {
	rd.log.Info("Plugin stopped")
}

func (rd *rdapPlugin) storeEntity(e *et.Event, level int, entity *rdap.Entity, asset *dbt.Entity, src *et.Source, m *config.Matches) {
	roles := stringset.New(entity.Roles...)
	defer roles.Close()

	_, isDomain := asset.Asset.(*oamreg.DomainRecord)

	// A domain record's contacts use the DomainRecord relation labels the
	// semantics catalog knows (registrant_contact, …); an IP record keeps the
	// labels the IP handlers already use.
	var rel string
	switch {
	case roles.Has("registrant") && level == 1:
		if isDomain {
			rel = "registrant_contact"
		} else {
			rel = "registrant"
		}
	case roles.Has("administrative"):
		rel = "admin_contact"
	case roles.Has("technical"):
		rel = "technical_contact"
	case isDomain && roles.Has("billing"):
		rel = "billing_contact"
	case isDomain && roles.Has("registrar"):
		rel = "registrar_contact"
	case !isDomain && roles.Has("abuse"):
		rel = "abuse_contact"
	default:
		return
	}

	u := rd.getJSONLink(entity.Links)
	// IP registration contacts are keyed by their RDAP self link; a domain
	// contact is often redacted with no link, so it is keyed by the record
	// and its role instead.
	discoveredAt := ""
	if u != nil {
		discoveredAt = u.Raw
	} else if isDomain {
		discoveredAt = recordContactKey(asset, rel)
	} else {
		return
	}

	ctx, cancel := context.WithTimeout(e.Session.Ctx(), 10*time.Minute)
	defer cancel()

	cr, err := e.Session.DB().CreateAsset(ctx, &contact.ContactRecord{DiscoveredAt: discoveredAt})
	if err != nil || cr == nil {
		return
	}

	v := entity.VCard
	var info support.Contact
	if u != nil {
		info.URL = u.Raw
	}
	prop := v.GetFirst("kind")
	if prop == nil {
		// Without a kind the contact is only its RDAP link.
		support.StoreContact(ctx, e.Session, cr, info, src, m)
		return
	}

	if adr := v.GetFirst("adr"); adr != nil {
		if label, ok := adr.Parameters["label"]; ok {
			info.Address = strings.Join(strings.Split(strings.Join(label, " "), "\n"), " ")
		}
	}
	info.Email = v.Email()
	info.Phone = v.Tel()
	info.Fax = v.Fax()
	info.Country = v.Country()
	support.StoreContact(ctx, e.Session, cr, info, src, m)

	// process the relation immediately
	support.ProcessAssetsWithSource(e, []*support.Finding{{
		From:     asset,
		FromName: recordName(asset),
		To:       cr,
		ToName:   "ContactRecord: " + discoveredAt,
		Rel:      &general.SimpleRelation{Name: rel},
	}}, rd.source, rd.name, rd.name+"-storeEntity")

	// the organization must come last due to a potential chicken-and-egg problem
	name := v.Name()
	kind := strings.Join(prop.Values(), " ")
	if kind == "individual" && name != "" {
		// registries mark organizations as individuals too: the name decides
		switch nk, why, p := support.NameKind(e.Session, name, nil, []string{info.Email}); nk {
		case semantics.NameKindPerson:
			if m.IsMatch(string(oam.Person)) {
				support.LinkContactPerson(e, cr, p, src)
			}
		case semantics.NameKindOrganization:
			kind = "org"
		case semantics.NameKindUncertain:
			support.KeepUncertainName(ctx, e.Session, cr, "person", name, why, src)
		}
	}
	if m.IsMatch(string(oam.Organization)) && kind == "org" {
		if orgent, err := org.FindOrgByRDAPHandle(e.Session, entity.Handle, src); err == nil && orgent != nil {
			org.DispatchOrg(e, orgent)
		} else if orgent := org.LinkContactOrg(e, cr, name, src); orgent != nil {
			_, _ = org.CreateOrgRDAPHandle(e.Session, orgent, entity.Handle, src)
		}
	}

	level++
	for _, ent := range entity.Entities {
		rd.storeEntity(e, level, &ent, asset, rd.source, m)
	}
}

// recordContactKey identifies a registration contact that has no RDAP self
// link by the record it belongs to and its role, so the same redacted contact
// is one asset across reruns.
func recordContactKey(asset *dbt.Entity, rel string) string {
	switch v := asset.Asset.(type) {
	case *oamreg.DomainRecord:
		return v.Domain + " " + rel
	case *oamreg.IPNetRecord:
		return v.Handle + " " + rel
	case *oamreg.AutnumRecord:
		return v.Handle + " " + rel
	}
	return rel
}

func (rd *rdapPlugin) getJSONLink(links []rdap.Link) *url.URL {
	var url *url.URL
	for _, link := range links {
		if link.Type == "application/rdap+json" {
			url = support.RawURLToOAM(link.Href)
			break
		}
	}
	return url
}
