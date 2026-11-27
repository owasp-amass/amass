// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package oamrepo

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/owasp-amass/amass/v5/internal/review"
	dbt "github.com/owasp-amass/asset-db/types"
	oam "github.com/owasp-amass/open-asset-model"
	oamdns "github.com/owasp-amass/open-asset-model/dns"
	"github.com/owasp-amass/open-asset-model/general"
	oamorg "github.com/owasp-amass/open-asset-model/org"
	oampeople "github.com/owasp-amass/open-asset-model/people"
	"github.com/owasp-amass/open-asset-model/platform"
)

// UnmergeOrganizations undoes a merge of organizations or of people: it
// removes what the merge added to the survivor, gives it back its name and
// clears the fields it filled when they are unchanged, and recreates the
// duplicate with its properties and the relationships whose other end still
// exists. The restored record has a new ID.
func (a Adapter) UnmergeOrganizations(ctx context.Context, rec review.MergeRecord) (review.UnmergeResult, error) {
	var res review.UnmergeResult
	if a.Repo == nil {
		return res, errors.New("missing OAM repository")
	}

	wctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), mergeTimeout)
	defer cancel()

	surv, err := a.Repo.FindEntityById(wctx, rec.SurvivorID)
	if err != nil {
		return res, fmt.Errorf("entity %s: %w", rec.SurvivorID, err)
	}
	var restored oam.Asset
	switch surv.Asset.(type) {
	case *oamorg.Organization:
		restored = &oamorg.Organization{}
	case *oampeople.Person:
		restored = &oampeople.Person{}
	default:
		return res, fmt.Errorf("entity %s is neither an organization nor a person", rec.SurvivorID)
	}
	if err := json.Unmarshal(rec.DuplicateAsset, restored); err != nil {
		return res, fmt.Errorf("merge record %s: %w", restored.AssetType(), err)
	}
	if err := a.removeAdditions(wctx, rec); err != nil {
		return res, err
	}
	if next, kept := restoreName(surv.Asset, rec); kept {
		res.KeptFields = append(res.KeptFields, "name")
	} else if next != nil && a.storeContent(wctx, next) != nil {
		res.KeptFields = append(res.KeptFields, "name")
	}
	res.KeptFields = append(res.KeptFields, a.clearFilledFields(wctx, surv, restored, rec.FilledFields)...)

	dup, err := a.Repo.CreateAsset(wctx, restored)
	if err != nil {
		return res, err
	} else if dup == nil {
		return res, errors.New("failed to restore the merged record")
	}

	for _, t := range rec.DuplicateTags {
		p, err := propertyFromTag(t)
		if err != nil {
			res.RestoredID = dup.ID
			return res, err
		}
		if _, err := a.Repo.CreateEntityProperty(wctx, dup, p); err != nil {
			res.RestoredID = dup.ID
			return res, err
		}
	}

	for _, m := range rec.Edges {
		other := surv
		if m.OtherID != rec.SurvivorID {
			if other, err = a.Repo.FindEntityById(wctx, m.OtherID); err != nil || other == nil {
				// The other end was deleted since the merge.
				continue
			}
		}

		rel, err := relationFromJSON(m.RelationType, m.Relation)
		if err != nil {
			res.RestoredID = dup.ID
			return res, err
		}

		from, to := dup, other
		if !m.Outgoing {
			from, to = other, dup
		}

		edge, err := a.createEdge(wctx, &dbt.Edge{Relation: rel, FromEntity: from, ToEntity: to})
		if err != nil {
			res.RestoredID = dup.ID
			return res, err
		}
		for _, t := range m.Tags {
			p, err := propertyFromTag(t)
			if err != nil {
				res.RestoredID = dup.ID
				return res, err
			}
			if _, err := a.Repo.CreateEdgeProperty(wctx, edge, p); err != nil {
				res.RestoredID = dup.ID
				return res, err
			}
		}
	}

	res.RestoredID = dup.ID
	return res, nil
}

// assetReplacer is the asset-db capability that stores an asset's content
// exactly, clearing the fields it leaves empty.
type assetReplacer interface {
	ReplaceAsset(ctx context.Context, asset oam.Asset) (*dbt.Entity, error)
}

// clearFilledFields empties the survivor's fields a merge filled, when each
// still holds the duplicate's value, and returns the fields it left.
func (a Adapter) clearFilledFields(ctx context.Context, surv *dbt.Entity, restored oam.Asset,
	filled []string) []string {
	if len(filled) == 0 {
		return nil
	}

	r, ok := a.Repo.(assetReplacer)
	if !ok {
		return filled
	}

	ent, err := a.Repo.FindEntityById(ctx, surv.ID)
	if err != nil || ent == nil {
		return filled
	}

	var kept, cleared []string
	done := func(field string, ok bool) {
		if ok {
			cleared = append(cleared, field)
		} else {
			kept = append(kept, field)
		}
	}
	clear := func(field string, have *string, was string) {
		ok := *have == was
		if ok {
			*have = ""
		}
		done(field, ok)
	}
	var next oam.Asset
	switch cur := ent.Asset.(type) {
	case *oamorg.Organization:
		dup, ok := restored.(*oamorg.Organization)
		if !ok {
			return filled
		}
		o := *cur
		next = &o
		clearOrgFields(&o, dup, filled, clear, done)
	case *oampeople.Person:
		dup, ok := restored.(*oampeople.Person)
		if !ok {
			return filled
		}
		p := *cur
		next = &p
		for _, f := range filled {
			switch f {
			case "middle_name":
				clear(f, &p.MiddleName, dup.MiddleName)
			case "birth_date":
				clear(f, &p.BirthDate, dup.BirthDate)
			case "gender":
				clear(f, &p.Gender, dup.Gender)
			default:
				done(f, false)
			}
		}
	default:
		return filled
	}
	if len(cleared) == 0 {
		return kept
	}
	if _, err := r.ReplaceAsset(ctx, next); err != nil {
		return filled
	}

	return kept
}

// clearOrgFields clears the organization fields a merge filled, through
// clear, and reports each field to done.
func clearOrgFields(next, dup *oamorg.Organization, filled []string,
	clear func(field string, have *string, was string), done func(field string, ok bool)) {
	for _, f := range filled {
		switch f {
		case "legal_name":
			// The merge fills legal_name from the duplicate's legal name, or,
			// when it had none, from its distinct name; clear it back only when
			// it still holds whichever value the merge put there.
			was := dup.LegalName
			if was == "" {
				was = dup.Name
			}
			clear(f, &next.LegalName, was)
		case "founding_date":
			clear(f, &next.FoundingDate, dup.FoundingDate)
		case "jurisdiction":
			clear(f, &next.Jurisdiction, dup.Jurisdiction)
		case "registration_id":
			clear(f, &next.RegistrationID, dup.RegistrationID)
		case "industry":
			clear(f, &next.Industry, dup.Industry)
		case "target_markets":
			ok := slices.Equal(next.TargetMarkets, dup.TargetMarkets)
			if ok {
				next.TargetMarkets = nil
			}
			done(f, ok)
		case "headcount":
			ok := next.Headcount == dup.Headcount
			if ok {
				next.Headcount = 0
			}
			done(f, ok)
		default:
			done(f, false)
		}
	}
}

// missing reports whether err means the tag is already gone.
func missing(err error) bool {
	return err != nil && (emptyTagLookup(err) || strings.Contains(strings.ToLower(err.Error()), "not found"))
}

func hasProperty(have []oam.Property, p oam.Property) bool {
	for _, h := range have {
		if h.PropertyType() == p.PropertyType() && h.Name() == p.Name() && h.Value() == p.Value() {
			return true
		}
	}

	return false
}

func mergedTag(p oam.Property) (review.MergedTag, error) {
	raw, err := p.JSON()
	if err != nil {
		return review.MergedTag{}, err
	}

	return review.MergedTag{Type: string(p.PropertyType()), Property: raw}, nil
}

func propertyFromTag(t review.MergedTag) (oam.Property, error) {
	var p oam.Property
	switch oam.PropertyType(t.Type) {
	case oam.SimpleProperty:
		p = &general.SimpleProperty{}
	case oam.SourceProperty:
		p = &general.SourceProperty{}
	case oam.DNSRecordProperty:
		p = &oamdns.DNSRecordProperty{}
	case oam.VulnProperty:
		p = &platform.VulnProperty{}
	default:
		return nil, fmt.Errorf("unknown property type %q", t.Type)
	}

	if err := json.Unmarshal(t.Property, p); err != nil {
		return nil, fmt.Errorf("%s: %w", t.Type, err)
	}

	return p, nil
}

func relationFromJSON(t string, raw json.RawMessage) (oam.Relation, error) {
	var r oam.Relation
	switch oam.RelationType(t) {
	case oam.SimpleRelation:
		r = &general.SimpleRelation{}
	case oam.PortRelation:
		r = &general.PortRelation{}
	case oam.BasicDNSRelation:
		r = &oamdns.BasicDNSRelation{}
	case oam.PrefDNSRelation:
		r = &oamdns.PrefDNSRelation{}
	case oam.SRVDNSRelation:
		r = &oamdns.SRVDNSRelation{}
	default:
		return nil, fmt.Errorf("unknown relation type %q", t)
	}

	if err := json.Unmarshal(raw, r); err != nil {
		return nil, fmt.Errorf("%s: %w", t, err)
	}

	return r, nil
}
