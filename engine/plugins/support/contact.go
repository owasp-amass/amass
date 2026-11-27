// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package support

import (
	"context"
	"fmt"
	"strings"

	"github.com/owasp-amass/amass/v5/config"
	et "github.com/owasp-amass/amass/v5/engine/types"
	dbt "github.com/owasp-amass/asset-db/types"
	oam "github.com/owasp-amass/open-asset-model"
	"github.com/owasp-amass/open-asset-model/contact"
	"github.com/owasp-amass/open-asset-model/general"
	oampeop "github.com/owasp-amass/open-asset-model/people"
)

// LinkAsset creates asset with src as its source and links it from from with
// a simple relation labeled label. It returns the asset's entity, or nil when
// it was not created.
func LinkAsset(ctx context.Context, sess et.Session, from *dbt.Entity, label string, asset oam.Asset,
	src *et.Source) *dbt.Entity {
	if from == nil || asset == nil {
		return nil
	}
	ent, err := sess.DB().CreateAsset(ctx, asset)
	if err != nil || ent == nil {
		return nil
	}
	AddSource(ctx, sess, ent, src)
	Link(ctx, sess, from, label, ent, src)
	return ent
}

// LinkContactRecord creates the ContactRecord discovered at key (the URL or
// other locator of the published contact information) and links it from
// owner with a simple relation labeled label, such as contact.
func LinkContactRecord(ctx context.Context, sess et.Session, owner *dbt.Entity, label, key string,
	src *et.Source) *dbt.Entity {
	if key == "" {
		return nil
	}
	return LinkAsset(ctx, sess, owner, label, &contact.ContactRecord{DiscoveredAt: key}, src)
}

// EmailIdentifier returns the email Identifier for an address.
func EmailIdentifier(email string) *general.Identifier {
	email = strings.ToLower(strings.TrimSpace(email))
	if email == "" {
		return nil
	}
	return &general.Identifier{UniqueID: general.EmailAddress + ":" + email, ID: email,
		Type: general.EmailAddress}
}

// LinkContactValue links one published contact value to a ContactRecord: an
// email address (mailto: or bare) as an email Identifier (id), an http(s)
// URL (url), or a phone number (tel: or bare) as a Phone (phone). It
// returns the value's entity, or nil when the value is none of these.
func LinkContactValue(ctx context.Context, sess et.Session, cr *dbt.Entity, value string,
	src *et.Source) *dbt.Entity {
	value = strings.TrimSpace(value)
	lower := strings.ToLower(value)
	switch {
	case strings.HasPrefix(lower, "mailto:"):
		return LinkEmail(ctx, sess, cr, "id", value[len("mailto:"):], src)
	case strings.HasPrefix(lower, "tel:"):
		return linkPhone(ctx, sess, cr, value[len("tel:"):], src)
	case strings.HasPrefix(lower, "http://") || strings.HasPrefix(lower, "https://"):
		if u := RawURLToOAM(value); u != nil {
			return LinkAsset(ctx, sess, cr, "url", u, src)
		}
		return nil
	case strings.Contains(value, "@") && !strings.Contains(value, "://"):
		return LinkEmail(ctx, sess, cr, "id", value, src)
	}
	return linkPhone(ctx, sess, cr, value, src)
}

// LinkEmail creates the email Identifier for an address and links it from
// from with a simple relation labeled label.
func LinkEmail(ctx context.Context, sess et.Session, from *dbt.Entity, label, email string,
	src *et.Source) *dbt.Entity {
	id := EmailIdentifier(email)
	if id == nil {
		return nil
	}
	return LinkAsset(ctx, sess, from, label, id, src)
}

func linkPhone(ctx context.Context, sess et.Session, cr *dbt.Entity, value string, src *et.Source) *dbt.Entity {
	phone := PhoneToOAMPhone(strings.TrimSpace(value), "", "")
	if phone == nil {
		return nil
	}
	if phone.Type == "" {
		phone.Type = contact.PhoneTypeRegular
	}
	return LinkAsset(ctx, sess, cr, "phone", phone, src)
}

// Contact is the contact information a registration or a certificate
// publishes for one party.
type Contact struct {
	Address  string // a freeform street address, parsed when stored
	Email    string
	Phone    string
	PhoneExt string
	Fax      string
	FaxExt   string
	Country  string // the region phone numbers are read in
	URL      string
}

// StoreContact links what a contact carries to its ContactRecord, each kind
// of asset only when the configuration matches it: the street address
// (street_address), the email Identifier (id), the phone and fax numbers
// (phone) and the URL (url), each with src as its source. It returns the
// street address entity, or nil.
func StoreContact(ctx context.Context, sess et.Session, cr *dbt.Entity, c Contact, src *et.Source,
	m *config.Matches) *dbt.Entity {
	if cr == nil {
		return nil
	}

	var addr *dbt.Entity
	if m.IsMatch(string(oam.StreetAddress)) {
		if loc := ParseStreetAddressIn(c.Address, c.Country); loc != nil {
			addr = LinkAsset(ctx, sess, cr, "street_address", loc, src)
		}
	}
	if m.IsMatch(string(oam.Identifier)) {
		LinkEmail(ctx, sess, cr, "id", c.Email, src)
	}
	if m.IsMatch(string(oam.Phone)) {
		if phone := PhoneToOAMPhone(c.Phone, c.PhoneExt, c.Country); phone != nil {
			phone.Type = contact.PhoneTypeRegular
			LinkAsset(ctx, sess, cr, "phone", phone, src)
		}
		if fax := PhoneToOAMPhone(c.Fax, c.FaxExt, c.Country); fax != nil {
			fax.Type = contact.PhoneTypeFax
			LinkAsset(ctx, sess, cr, "phone", fax, src)
		}
	}
	if m.IsMatch(string(oam.URL)) {
		if u := RawURLToOAM(strings.TrimSpace(c.URL)); u != nil {
			LinkAsset(ctx, sess, cr, "url", u, src)
		}
	}
	return addr
}

// LinkContactPerson creates the Person a contact names, linked from its
// ContactRecord (person), and dispatches it. It returns the person, or nil.
// Decide first with NameKind that the contact's name names a person.
func LinkContactPerson(e *et.Event, cr *dbt.Entity, p *oampeop.Person, src *et.Source) *dbt.Entity {
	if p == nil {
		return nil
	}

	ent, err := CreatePersonAsset(e.Session, cr, &general.SimpleRelation{Name: "person"}, p, src)
	if err != nil || ent == nil {
		return nil
	}
	_ = e.Dispatcher.DispatchEvent(&et.Event{
		Name:    fmt.Sprintf("%s:%s", p.FullName, p.ID),
		Entity:  ent,
		Session: e.Session,
	})
	return ent
}
