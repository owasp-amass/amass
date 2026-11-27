// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package support

import (
	"context"
	"os"
	"strings"
	"time"

	et "github.com/owasp-amass/amass/v5/engine/types"
	"github.com/owasp-amass/amass/v5/internal/graph"
	"github.com/owasp-amass/amass/v5/internal/review"
	"github.com/owasp-amass/amass/v5/internal/semantics"
	dbt "github.com/owasp-amass/asset-db/types"
	oam "github.com/owasp-amass/open-asset-model"
	oamgen "github.com/owasp-amass/open-asset-model/general"
	oampeop "github.com/owasp-amass/open-asset-model/people"
)

// NameKind decides what a raw name found in a person's field names
// (semantics.NameKindOf), adding what the graph knows: an organization
// already stored under the name, or claiming it. orgNames are the
// organization names the same record gives, and emails its email addresses.
// For a person it returns the Person to store.
func NameKind(sess et.Session, raw string, orgNames, emails []string) (semantics.NameKind, []string,
	*oampeop.Person) {
	raw = strings.TrimSpace(raw)
	clues := semantics.NameClues{OrgNames: orgNames, Emails: emails, StoredOrg: storedOrgNamed(sess, raw)}
	p := FullNameToPerson(raw)
	if p != nil {
		clues.First, clues.Middle, clues.Last = p.FirstName, p.MiddleName, p.FamilyName
	}

	kind, why := semantics.NameKindOf(raw, clues)
	if kind != semantics.NameKindPerson {
		p = nil
	}
	return kind, why, p
}

// storedOrgNamed reports whether an organization is stored under the name
// (its normalized name) or claims it.
func storedOrgNamed(sess et.Session, raw string) bool {
	key := semantics.OrgNameKey(raw)
	if key == "" || sess == nil || sess.DB() == nil {
		return false
	}

	ctx, cancel := context.WithTimeout(sess.Ctx(), 10*time.Second)
	defer cancel()
	if ents, err := sess.DB().FindEntitiesByContent(ctx, oam.Organization, time.Time{}, 1,
		dbt.ContentFilters{"name": key}); err == nil && len(ents) > 0 {
		return true
	}
	for _, idType := range []string{oamgen.OrganizationName, oamgen.LegalName} {
		for _, form := range []string{raw, strings.ToLower(raw)} {
			if ents, err := sess.DB().FindEntitiesByContent(ctx, oam.Identifier, time.Time{}, 1,
				dbt.ContentFilters{"unique_id": idType + ":" + form}); err == nil && len(ents) > 0 {
				return true
			}
		}
	}
	return false
}

// KeepUncertainName stores the raw name on the record that gave it
// (graph.UncertainNameProp), and asks what it names with a name proposal in
// the review journal, when the configuration keeps one: the session's name
// decider (askNameKind) or a person decides. label is the relation from the record to the person the
// field names, and reasons the evidence NameKind weighed.
func KeepUncertainName(ctx context.Context, sess et.Session, rec *dbt.Entity, label, raw string, reasons []string,
	src *et.Source) {
	raw = strings.TrimSpace(raw)
	if rec == nil || rec.Asset == nil || raw == "" {
		return
	}
	_, _ = sess.DB().CreateEntityProperty(ctx, rec,
		&oamgen.SimpleProperty{PropertyName: graph.UncertainNameProp, PropertyValue: raw})

	j := ReviewJournal(sess, os.LookupEnv)
	if j == nil {
		return
	}
	p := review.NameKindProposal{ID: review.NameKindProposalID(rec.ID, label, raw), RecordID: rec.ID,
		RecordType: string(rec.Asset.AssetType()), Label: label, Name: raw, Reasons: reasons}
	if src != nil {
		p.Source = src.Name
	}
	// a name an earlier run kept with no answer is asked again
	ask, err := j.NameKindsToAsk([]review.NameKindProposal{p})
	if err != nil {
		sess.Log().Warn("the uncertain name was not recorded for review", "name", raw, "error", err.Error())
		return
	}
	for _, a := range ask {
		askNameKind(sess, j, a, p.Source)
	}
}

// ListedPerson returns the Person a source that lists people (employees,
// investors) names, unless the name's words name an organization or a role
// (semantics.NameKindOf). The source's saying it lists a person settles what
// the words leave uncertain, and outweighs an organization stored under the
// same name.
func ListedPerson(raw string) *oampeop.Person {
	p := FullNameToPerson(raw)
	if p == nil {
		return nil
	}
	switch kind, _ := semantics.NameKindOf(raw, semantics.NameClues{First: p.FirstName, Middle: p.MiddleName,
		Last: p.FamilyName}); kind {
	case semantics.NameKindOrganization, semantics.NameKindRole:
		return nil
	}
	return p
}
