// Copyright © by Jeff Foley 2017-2025. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package rdap

import (
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"path/filepath"
	"strings"
	"time"

	"github.com/caffix/stringset"
	"github.com/openrdap/rdap"
	"github.com/openrdap/rdap/bootstrap"
	"github.com/openrdap/rdap/bootstrap/cache"
	"github.com/owasp-amass/amass/v4/config"
	"github.com/owasp-amass/amass/v4/engine/plugins/support"
	et "github.com/owasp-amass/amass/v4/engine/types"
	dbt "github.com/owasp-amass/asset-db/types"
	oam "github.com/owasp-amass/open-asset-model"
	"github.com/owasp-amass/open-asset-model/contact"
	"github.com/owasp-amass/open-asset-model/general"
	"github.com/owasp-amass/open-asset-model/org"
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
	autnum   *autnum
	netblock *netblock
	ipnet    *ipnet
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
	bs.HTTP = &http.Client{
		Transport: transport,
	}
	httpClient := &http.Client{
		Transport: transport,
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
		Plugin:     rd,
		Name:       rd.autsys.name,
		Priority:   9,
		Transforms: []string{string(oam.AutnumRecord)},
		EventType:  oam.AutonomousSystem,
		Callback:   rd.autsys.check,
	}); err != nil {
		return err
	}

	rd.autnum = &autnum{
		name:   rd.name + "-Autnum-Handler",
		plugin: rd,
		transforms: []string{
			string(oam.FQDN),
			string(oam.URL),
			string(oam.ContactRecord),
			string(oam.Person),
			string(oam.Organization),
			string(oam.Location),
			string(oam.Identifier),
			string(oam.Phone),
		},
	}
	if err := r.RegisterHandler(&et.Handler{
		Plugin:     rd,
		Name:       rd.autnum.name,
		Priority:   1,
		Transforms: rd.autnum.transforms,
		EventType:  oam.AutnumRecord,
		Callback:   rd.autnum.check,
	}); err != nil {
		return err
	}

	rd.netblock = &netblock{
		name:   rd.name + "-Netblock-Handler",
		plugin: rd,
	}
	if err := r.RegisterHandler(&et.Handler{
		Plugin:     rd,
		Name:       rd.netblock.name,
		Priority:   9,
		Transforms: []string{string(oam.IPNetRecord)},
		EventType:  oam.Netblock,
		Callback:   rd.netblock.check,
	}); err != nil {
		return err
	}

	rd.ipnet = &ipnet{
		name:   rd.name + "-IPNetwork-Handler",
		plugin: rd,
		transforms: []string{
			string(oam.FQDN),
			string(oam.URL),
			string(oam.ContactRecord),
			string(oam.Person),
			string(oam.Organization),
			string(oam.Location),
			string(oam.Identifier),
			string(oam.Phone),
		},
	}
	if err := r.RegisterHandler(&et.Handler{
		Plugin:     rd,
		Name:       rd.ipnet.name,
		Priority:   1,
		Transforms: rd.ipnet.transforms,
		EventType:  oam.IPNetRecord,
		Callback:   rd.ipnet.check,
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

	u := rd.getJSONLink(entity.Links)
	if u == nil {
		return
	}

	var rel string
	if roles.Has("registrant") && level == 1 {
		rel = "registrant"
	} else if roles.Has("administrative") {
		rel = "admin_contact"
	} else if roles.Has("abuse") {
		rel = "abuse_contact"
	} else if roles.Has("technical") {
		rel = "technical_contact"
	} else {
		return
	}

	cr, err := e.Session.Cache().CreateAsset(&contact.ContactRecord{DiscoveredAt: u.Raw})
	if err != nil || cr == nil {
		return
	}

	var name string
	switch v := asset.Asset.(type) {
	case *oamreg.AutnumRecord:
		name = "AutnumRecord: " + v.Handle
	case *oamreg.IPNetRecord:
		name = "IPNetRecord: " + v.Handle
	}

	if m.IsMatch(string(oam.URL)) {
		a, err := e.Session.Cache().CreateAsset(u)
		if err != nil {
			return
		}
		_ = rd.createContactEdge(e.Session, cr, a, &general.SimpleRelation{Name: "url"}, src)
	}

	v := entity.VCard
	prop := v.GetFirst("kind")
	if prop == nil {
		return
	}

	if adr := v.GetFirst("adr"); adr != nil && m.IsMatch(string(oam.Location)) {
		if label, ok := adr.Parameters["label"]; ok {
			s := strings.Join(label, " ")

			addr := strings.Join(strings.Split(s, "\n"), " ")
			if loc := support.StreetAddressToLocation(addr); loc != nil {
				if a, err := e.Session.Cache().CreateAsset(loc); err == nil && a != nil {
					_ = rd.createContactEdge(e.Session, cr, a, &general.SimpleRelation{Name: "location"}, src)
				}
			}
		}
	}
	if email := strings.ToLower(v.Email()); m.IsMatch(string(oam.Identifier)) && email != "" {
		if a, err := e.Session.Cache().CreateAsset(&general.Identifier{
			UniqueID: fmt.Sprintf("%s:%s", general.EmailAddress, email),
			ID:       email,
			Type:     general.EmailAddress,
		}); err == nil && a != nil {
			_ = rd.createContactEdge(e.Session, cr, a, &general.SimpleRelation{Name: "id"}, src)
		}
	}
	if m.IsMatch(string(oam.Phone)) {
		if phone := support.PhoneToOAMPhone(v.Tel(), "", v.Country()); phone != nil {
			phone.Type = contact.PhoneTypeRegular
			if a, err := e.Session.Cache().CreateAsset(phone); err == nil && a != nil {
				_ = rd.createContactEdge(e.Session, cr, a, &general.SimpleRelation{Name: "phone"}, src)
			}
		}
		if fax := support.PhoneToOAMPhone(v.Fax(), "", v.Country()); fax != nil {
			fax.Type = contact.PhoneTypeFax
			if a, err := e.Session.Cache().CreateAsset(fax); err == nil && a != nil {
				_ = rd.createContactEdge(e.Session, cr, a, &general.SimpleRelation{Name: "phone"}, src)
			}
		}
	}

	var findings []*support.Finding
	findings = append(findings, &support.Finding{
		From:     asset,
		FromName: name,
		To:       cr,
		ToName:   "ContactRecord: " + u.Raw,
		Rel:      &general.SimpleRelation{Name: rel},
	})
	// process the relation immediately
	support.ProcessAssetsWithSource(e, findings, rd.source, rd.name, rd.name+"-storeEntity")

	name = v.Name()
	// the organization must come last due to a potential chicken-and-egg problem
	if kind := strings.Join(prop.Values(), " "); m.IsMatch(string(oam.Person)) && name != "" && kind == "individual" {
		if p := support.FullNameToPerson(name); p != nil {
			if a, err := e.Session.Cache().CreateAsset(p); err == nil && a != nil {
				_ = rd.createContactEdge(e.Session, cr, a, &general.SimpleRelation{Name: "person"}, src)
				_ = e.Dispatcher.DispatchEvent(&et.Event{
					Name:    fmt.Sprintf("%s:%s", p.FullName, p.ID),
					Entity:  a,
					Session: e.Session,
				})
			}
		}
	} else if m.IsMatch(string(oam.Organization)) && kind == "org" {
		orgent, err := support.CreateOrgAsset(e.Session, cr,
			&general.SimpleRelation{Name: "organization"}, &org.Organization{Name: name}, src)

		if err == nil && orgent != nil {
			o := orgent.Asset.(*org.Organization)

			_ = e.Dispatcher.DispatchEvent(&et.Event{
				Name:    fmt.Sprintf("%s:%s", o.Name, o.ID),
				Entity:  orgent,
				Session: e.Session,
			})
		}
	}

	level++
	for _, ent := range entity.Entities {
		rd.storeEntity(e, level, &ent, asset, rd.source, m)
	}
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

func (rd *rdapPlugin) createContactEdge(sess et.Session, cr, a *dbt.Entity, rel oam.Relation, src *et.Source) error {
	edge, err := sess.Cache().CreateEdge(&dbt.Edge{
		Relation:   rel,
		FromEntity: cr,
		ToEntity:   a,
	})
	if err != nil {
		return err
	} else if edge == nil {
		return errors.New("failed to create the edge")
	}

	_, err = sess.Cache().CreateEdgeProperty(edge, &general.SourceProperty{
		Source:     src.Name,
		Confidence: src.Confidence,
	})
	return err
}
