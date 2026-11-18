// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package osm

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"strings"
	"time"

	"github.com/owasp-amass/amass/v5/engine/plugins/support"
	orgsupport "github.com/owasp-amass/amass/v5/engine/plugins/support/org"
	et "github.com/owasp-amass/amass/v5/engine/types"
	amasshttp "github.com/owasp-amass/amass/v5/internal/net/http"
	dbt "github.com/owasp-amass/asset-db/types"
	oam "github.com/owasp-amass/open-asset-model"
	"github.com/owasp-amass/open-asset-model/contact"
	"github.com/owasp-amass/open-asset-model/general"
	oamorg "github.com/owasp-amass/open-asset-model/org"
)

// reverse looks organizations up from a phone number or a street address: the
// opposite direction of the phones handler, which starts from an organization.
// It is what lets an enumeration pivot from a Phone or Location to the
// organizations tied to it. A feature that carries the number or sits at the
// address names a candidate organization; the name is not proof the
// organization belongs there, so matching is conservative and the stored
// confidence is modest. The organization is created through the shared,
// idempotent CreateOrgAsset, so a name already in the graph is reused rather
// than duplicated.
type reverse struct {
	name   string
	plugin *openstreetmap
}

// checkPhone resolves the organizations whose OpenStreetMap feature carries the
// event's phone number, linking each to the phone through a ContactRecord.
func (h *reverse) checkPhone(e *et.Event) error {
	ph, ok := e.Entity.Asset.(*contact.Phone)
	if !ok {
		return errors.New("failed to extract the Phone asset")
	}
	if digitsOnly(ph.E164) == "" {
		return nil
	}

	since, err := support.TTLStartTime(e.Session.Config(),
		string(oam.Phone), string(oam.Organization), h.plugin.name)
	if err != nil {
		return err
	}

	src := &et.Source{Name: h.name, Confidence: h.plugin.source.Confidence}
	if support.AssetMonitoredWithinTTL(e.Session, e.Entity, src, since) {
		return nil
	}
	h.queryPhone(e, e.Entity, ph)
	support.MarkAssetMonitored(e.Session, e.Entity, src)
	return nil
}

// checkAddress resolves the organizations whose OpenStreetMap feature sits at
// the event's street address, linking each to the location through a
// ContactRecord. It needs a structured address (a street name at least); a
// bare, unparsed address string cannot be matched reliably and is skipped.
func (h *reverse) checkAddress(e *et.Event) error {
	loc, ok := e.Entity.Asset.(*contact.Location)
	if !ok {
		return errors.New("failed to extract the Location asset")
	}
	// A seeded freeform address (e.g. from a phone/address pivot) may carry only
	// the Address string with no parsed components. Parse it so the reverse
	// query can key on the street and house number.
	if strings.TrimSpace(loc.StreetName) == "" && strings.TrimSpace(loc.Address) != "" {
		if parsed := support.StreetAddressToLocation(loc.Address); parsed != nil && parsed.StreetName != "" {
			loc = parsed
		}
	}
	if strings.TrimSpace(loc.StreetName) == "" {
		return nil
	}

	since, err := support.TTLStartTime(e.Session.Config(),
		string(oam.Location), string(oam.Organization), h.plugin.name)
	if err != nil {
		return err
	}

	src := &et.Source{Name: h.name, Confidence: h.plugin.source.Confidence}
	if support.AssetMonitoredWithinTTL(e.Session, e.Entity, src, since) {
		return nil
	}
	h.queryAddress(e, e.Entity, loc)
	support.MarkAssetMonitored(e.Session, e.Entity, src)
	return nil
}

func (h *reverse) queryPhone(e *et.Event, phoneent *dbt.Entity, ph *contact.Phone) {
	body, err := h.request(e, phoneQuery(ph.E164))
	if err != nil {
		h.logError(e, fmt.Sprintf("failed to query Overpass for %s: %s", ph.E164, err))
		return
	}

	elements, err := parseOverpass([]byte(body))
	if err != nil {
		h.logError(e, fmt.Sprintf("failed to parse the Overpass result for %s: %s", ph.E164, err))
		return
	}

	want := digitsOnly(ph.E164)
	for i := range elements {
		el := &elements[i]
		if el.Tags["name"] == "" {
			continue
		}
		// A broad regex bounds the Overpass result; confirm the match on the
		// number's digits so a near-miss is not attached.
		if !featureHasPhone(el, want) {
			continue
		}
		h.link(e, el, "phone", phoneent)
	}
}

func (h *reverse) queryAddress(e *et.Event, locent *dbt.Entity, loc *contact.Location) {
	body, err := h.request(e, addressQuery(loc))
	if err != nil {
		h.logError(e, fmt.Sprintf("failed to query Overpass for %s: %s", loc.Address, err))
		return
	}

	elements, err := parseOverpass([]byte(body))
	if err != nil {
		h.logError(e, fmt.Sprintf("failed to parse the Overpass result for %s: %s", loc.Address, err))
		return
	}

	for i := range elements {
		el := &elements[i]
		if el.Tags["name"] == "" {
			continue
		}
		if !featureAtAddress(el, loc) {
			continue
		}
		h.link(e, el, "location", locent)
	}
}

// link creates (or reuses) the organization named by the feature and ties it to
// the seed entity through a ContactRecord: ContactRecord --organization-->
// Organization and ContactRecord --<label>--> seed. The organization goes
// through CreateOrgAsset so a name already in the graph is reused.
func (h *reverse) link(e *et.Event, el *element, label string, seedent *dbt.Entity) {
	src := &et.Source{Name: h.plugin.source.Name, Confidence: h.plugin.source.Confidence}
	orgent, err := orgsupport.CreateOrgAsset(e.Session, nil, nil,
		&oamorg.Organization{Name: el.Tags["name"]}, src)
	if err != nil || orgent == nil {
		h.logError(e, fmt.Sprintf("failed to create the organization %q: %s", el.Tags["name"], err))
		return
	}

	ctx, cancel := context.WithTimeout(e.Session.Ctx(), 30*time.Second)
	defer cancel()

	cr, err := e.Session.DB().CreateAsset(ctx, &contact.ContactRecord{DiscoveredAt: el.url()})
	if err != nil || cr == nil {
		h.logError(e, fmt.Sprintf("failed to create the ContactRecord for %s: %s", el.url(), err))
		return
	}
	if _, err := e.Session.DB().CreateEntityProperty(ctx, cr, &general.SourceProperty{
		Source: h.plugin.source.Name, Confidence: h.plugin.source.Confidence}); err != nil {
		h.logError(e, fmt.Sprintf("failed to create the ContactRecord source property: %s", err))
	}

	if err := h.plugin.createRelation(ctx, e.Session, cr, &general.SimpleRelation{Name: "organization"},
		orgent, h.plugin.source.Confidence); err != nil {
		h.logError(e, fmt.Sprintf("failed to link the ContactRecord to the organization: %s", err))
		return
	}
	if err := h.plugin.createRelation(ctx, e.Session, cr, &general.SimpleRelation{Name: label},
		seedent, h.plugin.source.Confidence); err != nil {
		h.logError(e, fmt.Sprintf("failed to link the ContactRecord to the %s: %s", label, err))
		return
	}

	o := orgent.Asset.(*oamorg.Organization)
	_ = e.Dispatcher.DispatchEvent(&et.Event{Name: o.Name, Entity: orgent, Session: e.Session})
	e.Session.Log().Info("relationship discovered", "from", o.Name, "relation", label,
		"to", el.url(), slog.Group("plugin", "name", h.plugin.name, "handler", h.name))
}

func (h *reverse) request(e *et.Event, query string) (string, error) {
	_ = support.WaitLimit(e.Session.Ctx(), h.plugin.rlimit)
	e.Session.NetSem().Acquire()
	ctx, cancel := context.WithTimeout(e.Session.Ctx(), 60*time.Second)
	defer cancel()

	resp, err := amasshttp.RequestWebPage(ctx, e.Session.Clients().General, &amasshttp.Request{
		URL:    h.plugin.api,
		Method: "POST",
		Header: amasshttp.Header{"Content-Type": []string{"application/x-www-form-urlencoded"}},
		Body:   "data=" + url.QueryEscape(query),
	})
	e.Session.NetSem().Release()
	if err != nil {
		return "", err
	}
	if resp.StatusCode != 200 {
		return "", fmt.Errorf("status %s", resp.Status)
	}
	if resp.Body == "" {
		return "", errors.New("empty body")
	}
	return resp.Body, nil
}

func (h *reverse) logError(e *et.Event, msg string) {
	e.Session.Log().Error(msg, slog.Group("plugin", "name", h.plugin.name, "handler", h.name))
}

// phoneQuery returns an Overpass query for features whose phone tag carries the
// number's digits in order, allowing any separators between them. The regex
// only bounds the result; featureHasPhone confirms the match.
func phoneQuery(e164 string) string {
	re := phoneRegex(e164)
	return "[out:json][timeout:25];(" +
		`nwr["phone"~"` + re + `"];` +
		`nwr["contact:phone"~"` + re + `"];` +
		");out tags center 50;"
}

// phoneRegex joins the number's digits with a separator class, so "+13152281000"
// matches "+1-315-228-1000", "+1 315 228 1000" and "(1) 315 228 1000" alike.
func phoneRegex(e164 string) string {
	digits := digitsOnly(e164)
	if digits == "" {
		return ""
	}

	parts := make([]string, 0, len(digits))
	for _, d := range digits {
		parts = append(parts, string(d))
	}
	return strings.Join(parts, "[^0-9]*")
}

// addressQuery returns an Overpass query for features at the location's street
// address, keyed on the house number and street the OAM Location carries.
func addressQuery(loc *contact.Location) string {
	var b strings.Builder
	b.WriteString(`nwr["addr:street"~"^` + overpassString(loc.StreetName) + `$",i]`)
	if n := strings.TrimSpace(loc.BuildingNumber); n != "" {
		b.WriteString(`["addr:housenumber"="` + overpassString(n) + `"]`)
	}
	if c := strings.TrimSpace(loc.City); c != "" {
		b.WriteString(`["addr:city"~"^` + overpassString(c) + `$",i]`)
	}
	return "[out:json][timeout:25];(" + b.String() + ";);out tags center 50;"
}

// featureHasPhone reports whether any of the feature's phone tags carries the
// wanted digits exactly, ignoring separators.
func featureHasPhone(el *element, wantDigits string) bool {
	for _, key := range []string{"phone", "contact:phone"} {
		for _, v := range strings.Split(el.Tags[key], ";") {
			if digitsOnly(v) == wantDigits {
				return true
			}
		}
	}
	return false
}

// featureAtAddress reports whether the feature's address tags match the
// location's street and, when known, house number: a conservative check so a
// feature merely on the same street is not taken for the same address.
func featureAtAddress(el *element, loc *contact.Location) bool {
	if !normEq(el.Tags["addr:street"], loc.StreetName) {
		return false
	}
	if n := strings.TrimSpace(loc.BuildingNumber); n != "" {
		return normEq(el.Tags["addr:housenumber"], n)
	}
	return true
}

// normEq compares two strings with the same normalization the forward handler
// uses, so casing and punctuation do not matter.
func normEq(a, b string) bool {
	na, nb := normalize(a), normalize(b)
	return na != "" && na == nb
}

// digitsOnly returns the digits of s, dropping every other character.
func digitsOnly(s string) string {
	var b strings.Builder
	for _, r := range s {
		if r >= '0' && r <= '9' {
			b.WriteRune(r)
		}
	}
	return b.String()
}
