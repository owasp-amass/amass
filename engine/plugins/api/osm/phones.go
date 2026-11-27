// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package osm

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/owasp-amass/amass/v5/engine/plugins/support"
	et "github.com/owasp-amass/amass/v5/engine/types"
	"github.com/owasp-amass/amass/v5/internal/semantics"
	dbt "github.com/owasp-amass/asset-db/types"
	oam "github.com/owasp-amass/open-asset-model"
	"github.com/owasp-amass/open-asset-model/contact"
	"github.com/owasp-amass/open-asset-model/general"
	oamorg "github.com/owasp-amass/open-asset-model/org"
)

// element is one OpenStreetMap feature from an Overpass result.
type element struct {
	Type string            `json:"type"`
	ID   int64             `json:"id"`
	Tags map[string]string `json:"tags"`
}

type overpassResult struct {
	Elements []element `json:"elements"`
}

// parseOverpass reads an Overpass JSON response into its features.
func parseOverpass(body []byte) ([]element, error) {
	var r overpassResult
	if err := json.Unmarshal(body, &r); err != nil {
		return nil, err
	}
	return r.Elements, nil
}

// url is the OpenStreetMap page for a feature, used as the Phone evidence.
func (el *element) url() string {
	return fmt.Sprintf("https://www.openstreetmap.org/%s/%d", el.Type, el.ID)
}

// phoneNumbers returns the feature's phone tags, split on the ';' OSM uses to
// list several values in one tag.
func (el *element) phoneNumbers() []string {
	var out []string
	for _, key := range []string{"phone", "contact:phone"} {
		for _, v := range strings.Split(el.Tags[key], ";") {
			if v = strings.TrimSpace(v); v != "" {
				out = append(out, v)
			}
		}
	}
	return out
}

func (h *phones) check(e *et.Event) error {
	o, ok := e.Entity.Asset.(*oamorg.Organization)
	if !ok {
		return errors.New("failed to extract the Organization asset")
	}

	since, err := support.TTLStartTime(e.Session.Config(),
		string(oam.Organization), string(oam.Phone), h.plugin.name)
	if err != nil {
		return err
	}

	src := &et.Source{Name: h.name, Confidence: h.plugin.source.Confidence}
	if support.AssetMonitoredWithinTTL(e.Session, e.Entity, src, since) {
		return nil
	}
	h.query(e, e.Entity, o.Name)
	support.MarkAssetMonitored(e.Session, e.Entity, src)
	return nil
}

func (h *phones) query(e *et.Event, orgent *dbt.Entity, name string) {
	body, err := h.plugin.overpass(e, buildQuery(name))
	if err != nil {
		msg := fmt.Sprintf("failed to query Overpass for %s: %s", name, err)
		e.Session.Log().Error(msg, slog.Group("plugin", "name", h.plugin.name, "handler", h.name))
		return
	}

	elements, err := parseOverpass([]byte(body))
	if err != nil {
		msg := fmt.Sprintf("failed to parse the Overpass result for %s: %s", name, err)
		e.Session.Log().Error(msg, slog.Group("plugin", "name", h.plugin.name, "handler", h.name))
		return
	}

	seen := map[string]bool{}
	for i := range elements {
		el := &elements[i]
		// Only features whose name is the organization's, to avoid attaching a
		// same-named place's phone.
		if !semantics.SameOrgName(name, el.Tags["name"]) {
			continue
		}
		h.store(e, orgent, el, seen)
	}
}

func (h *phones) store(e *et.Event, orgent *dbt.Entity, el *element, seen map[string]bool) {
	numbers := el.phoneNumbers()
	if len(numbers) == 0 {
		return
	}

	ctx, cancel := context.WithTimeout(e.Session.Ctx(), 30*time.Second)
	defer cancel()

	var cr *dbt.Entity
	for _, raw := range numbers {
		// Only numbers that parse on their own (E.164, the OSM convention);
		// a bare local number without a country cannot be placed reliably.
		phone := support.PhoneToOAMPhone(raw, "", "")
		if phone == nil || seen[phone.E164] {
			continue
		}
		seen[phone.E164] = true
		phone.Type = contact.PhoneTypeRegular

		// Create the shared ContactRecord lazily, once a usable number exists.
		if cr == nil {
			ent, err := e.Session.DB().CreateAsset(ctx, &contact.ContactRecord{DiscoveredAt: el.url()})
			if err != nil || ent == nil {
				msg := fmt.Sprintf("failed to create the ContactRecord for %s: %s", el.url(), err)
				e.Session.Log().Error(msg, slog.Group("plugin", "name", h.plugin.name, "handler", h.name))
				return
			}
			cr = ent

			support.AddSource(ctx, e.Session, cr, h.plugin.source)

			if _, err := support.Relate(ctx, e.Session, cr,
				&general.SimpleRelation{Name: "organization"}, orgent, h.plugin.source); err != nil {
				msg := fmt.Sprintf("failed to link the ContactRecord to the organization: %s", err)
				e.Session.Log().Error(msg, slog.Group("plugin", "name", h.plugin.name, "handler", h.name))
				return
			}
		}

		phoneent, err := e.Session.DB().CreateAsset(ctx, phone)
		if err != nil || phoneent == nil {
			msg := fmt.Sprintf("failed to create the Phone asset %s: %s", phone.E164, err)
			e.Session.Log().Error(msg, slog.Group("plugin", "name", h.plugin.name, "handler", h.name))
			continue
		}

		support.AddSource(ctx, e.Session, phoneent, h.plugin.source)

		if _, err := support.Relate(ctx, e.Session, cr,
			&general.SimpleRelation{Name: "phone"}, phoneent, h.plugin.source); err != nil {
			msg := fmt.Sprintf("failed to link the Phone %s: %s", phone.E164, err)
			e.Session.Log().Error(msg, slog.Group("plugin", "name", h.plugin.name, "handler", h.name))
			continue
		}

		_ = e.Dispatcher.DispatchEvent(&et.Event{Name: phone.E164, Entity: phoneent, Session: e.Session})
	}
}

// buildQuery returns an Overpass QL query for features named like the
// organization that carry a phone tag.
func buildQuery(name string) string {
	esc := overpassString(name)
	return "[out:json][timeout:25];(" +
		`nwr["name"~"^` + esc + `$",i]["phone"];` +
		`nwr["name"~"^` + esc + `$",i]["contact:phone"];` +
		");out tags center 50;"
}

// overpassString escapes a name for use inside an Overpass regex string
// literal: backslashes and quotes for the string, and regex metacharacters so
// the name is matched literally.
func overpassString(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch r {
		case '\\', '"':
			b.WriteByte('\\')
			b.WriteRune(r)
		case '.', '+', '*', '?', '(', ')', '[', ']', '{', '}', '^', '$', '|':
			b.WriteByte('\\')
			b.WriteRune(r)
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}
