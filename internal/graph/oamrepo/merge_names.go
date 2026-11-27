// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package oamrepo

import (
	"context"
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"unicode"

	"github.com/owasp-amass/amass/v5/internal/graph"
	"github.com/owasp-amass/amass/v5/internal/lens"
	"github.com/owasp-amass/amass/v5/internal/review"
	"github.com/owasp-amass/amass/v5/internal/semantics"
	dbt "github.com/owasp-amass/asset-db/types"
	oam "github.com/owasp-amass/open-asset-model"
	"github.com/owasp-amass/open-asset-model/general"
	oamorg "github.com/owasp-amass/open-asset-model/org"
	oampeople "github.com/owasp-amass/open-asset-model/people"
)

// nameClaim is a name a merged organization keeps as a claim.
type nameClaim struct {
	idType, value string
}

// keepOrgNames shows the more complete of the two organizations' names and
// keeps every other name either had as a name claim (Organization --id-->
// Identifier), so a merge loses none: the full name is not dropped in favor
// of an acronym. merged is the survivor's content, updated in place; it
// reports whether the name changed.
func (a Adapter) keepOrgNames(ctx context.Context, surv *dbt.Entity, merged *oamorg.Organization,
	dup *oamorg.Organization, src oam.Property, rec *review.MergeRecord) (bool, error) {
	renamed := false
	if betterOrgName(merged.Name, dup.Name) {
		before, err := merged.JSON()
		if err != nil {
			return false, err
		}
		rec.SurvivorBefore = before
		merged.Name, renamed = dup.Name, true
	}

	var claims []nameClaim
	for _, n := range []string{surv.Asset.(*oamorg.Organization).Name, dup.Name} {
		if n != "" && !strings.EqualFold(n, merged.Name) {
			claims = append(claims, nameClaim{general.OrganizationName, n})
		}
	}
	if dup.LegalName != "" && !strings.EqualFold(dup.LegalName, merged.LegalName) {
		claims = append(claims, nameClaim{general.LegalName, dup.LegalName})
	}
	for _, c := range claims {
		if err := a.claimName(ctx, surv, c, src, rec); err != nil {
			return renamed, err
		}
	}
	return renamed, nil
}

// claimName relates the organization to the name Identifier, with the
// amass-ai source, unless it already claims it.
func (a Adapter) claimName(ctx context.Context, org *dbt.Entity, c nameClaim, src oam.Property,
	rec *review.MergeRecord) error {
	ident, err := a.Repo.CreateAsset(ctx, &general.Identifier{UniqueID: c.idType + ":" + c.value, ID: c.value,
		Type: c.idType})
	if err != nil {
		return err
	}

	edge, existed, err := a.survivorEdge(ctx, org, ident, &general.SimpleRelation{Name: "id"}, true)
	if err != nil || existed {
		return err
	}
	m := review.MergedEdge{Outgoing: true, OtherID: ident.ID, Label: "id", SurvivorEdgeID: edge.ID, Created: true}
	tag, err := a.Repo.CreateEdgeProperty(ctx, edge, src)
	if err != nil {
		return err
	}
	m.AddedTagIDs = []string{tag.ID}
	rec.NameEdges = append(rec.NameEdges, m)
	return nil
}

// keepPersonNames shows the more complete of the two people's names and
// keeps the other as an also_known_as property on the survivor. merged is
// the survivor's content, updated in place; it reports whether the name
// changed.
func (a Adapter) keepPersonNames(ctx context.Context, surv *dbt.Entity, merged *oampeople.Person,
	dup *oampeople.Person, rec *review.MergeRecord) (bool, error) {
	old := merged.FullName
	renamed := false
	if betterPersonName(merged.FullName, dup.FullName) {
		before, err := merged.JSON()
		if err != nil {
			return false, err
		}
		rec.SurvivorBefore = before
		merged.FullName, merged.FirstName, merged.MiddleName, merged.FamilyName =
			dup.FullName, dup.FirstName, dup.MiddleName, dup.FamilyName
		renamed = true
	}

	tags, err := a.tagsOf(ctx, surv)
	if err != nil {
		return renamed, err
	}
	var have []oam.Property
	for _, t := range tags {
		if t != nil && t.Property != nil {
			have = append(have, t.Property)
		}
	}
	add := func(p oam.Property) error {
		if hasProperty(have, p) {
			return nil
		}
		tag, err := a.Repo.CreateEntityProperty(ctx, surv, p)
		if err != nil {
			return err
		}
		rec.SurvivorTagIDs = append(rec.SurvivorTagIDs, tag.ID)
		have = append(have, p)
		return nil
	}
	for _, n := range []string{old, dup.FullName} {
		if n == "" || strings.EqualFold(n, merged.FullName) {
			continue
		}
		if err := add(&general.SimpleProperty{PropertyName: graph.PersonAlias, PropertyValue: n}); err != nil {
			return renamed, err
		}
		// the other name's family name groups the person with others of
		// that name in the duplicate sweep (a maiden name)
		if key := lens.PersonNameKey(lens.PersonAliasFamily(n)); key != "" {
			if err := add(&general.SimpleProperty{PropertyName: lens.PersonNameKeyProperty,
				PropertyValue: key}); err != nil {
				return renamed, err
			}
		}
	}
	return renamed, nil
}

// restoreName gives the survivor back the name a merge replaced, when it
// still shows the name the merge gave it. It reports whether the name was
// left, changed since.
func restoreName(cur oam.Asset, rec review.MergeRecord) (oam.Asset, bool) {
	if len(rec.SurvivorBefore) == 0 {
		return nil, false
	}
	switch c := cur.(type) {
	case *oamorg.Organization:
		var before, dup oamorg.Organization
		if json.Unmarshal(rec.SurvivorBefore, &before) != nil || json.Unmarshal(rec.DuplicateAsset, &dup) != nil {
			return nil, true
		}
		if c.Name != dup.Name {
			return nil, true
		}
		next := *c
		next.Name = before.Name
		return &next, false
	case *oampeople.Person:
		var before, dup oampeople.Person
		if json.Unmarshal(rec.SurvivorBefore, &before) != nil || json.Unmarshal(rec.DuplicateAsset, &dup) != nil {
			return nil, true
		}
		if c.FullName != dup.FullName {
			return nil, true
		}
		next := *c
		next.FullName, next.FirstName, next.MiddleName, next.FamilyName =
			before.FullName, before.FirstName, before.MiddleName, before.FamilyName
		return &next, false
	}
	return nil, false
}

// betterOrgName reports whether other is a more complete name for the
// organization than have: have is empty, an acronym or initials of other,
// or other holds every word of have and more ("OWASP" and "OWASP
// University").
func betterOrgName(have, other string) bool {
	kh, ko := semantics.OrgNameKey(have), semantics.OrgNameKey(other)
	switch {
	case ko == "" || kh == ko:
		return false
	case kh == "":
		return true
	}

	wh, wo := strings.Fields(kh), strings.Fields(ko)
	if len(wh) == 1 && len(wo) > 1 && initials(wo) == lettersOf(wh[0]) {
		return true
	}
	return len(wo) > len(wh) && containsAll(wo, wh)
}

// initials returns the first letters of words, leaving out the words
// skipped in initials ("of", "the").
func initials(words []string) string {
	stop := semantics.OrgInitialsStopWords()
	var b strings.Builder
	for _, w := range words {
		if !slices.Contains(stop, w) {
			for _, r := range w {
				b.WriteRune(r)
				break
			}
		}
	}
	return b.String()
}

func lettersOf(s string) string {
	return strings.Map(func(r rune) rune {
		if unicode.IsLetter(r) || unicode.IsNumber(r) {
			return unicode.ToLower(r)
		}
		return -1
	}, s)
}

// containsAll reports whether words holds each of want, as many times.
func containsAll(words, want []string) bool {
	rest := slices.Clone(words)
	for _, w := range want {
		i := slices.Index(rest, w)
		if i < 0 {
			return false
		}
		rest = slices.Delete(rest, i, i+1)
	}
	return true
}

// betterPersonName reports whether other is a more complete rendering of
// the person's name than have: every word of have is in other, written out
// or as its initial ("J. Smith" and "James Smith", "Robert Smith" and
// "Robert J. Smith"), and other says more.
func betterPersonName(have, other string) bool {
	wh, wo := nameWords(have), nameWords(other)
	switch {
	case len(wo) == 0:
		return false
	case len(wh) == 0:
		return true
	}

	rest := slices.Clone(wo)
	for _, w := range wh {
		i := slices.IndexFunc(rest, func(o string) bool {
			return o == w || (len(w) == 1 && strings.HasPrefix(o, w))
		})
		if i < 0 {
			return false
		}
		rest = slices.Delete(rest, i, i+1)
	}
	return len(lettersOf(other)) > len(lettersOf(have))
}

func nameWords(name string) []string {
	var out []string
	for _, w := range strings.Fields(name) {
		if w = lettersOf(w); w != "" {
			out = append(out, w)
		}
	}
	return out
}

// KeepMergedNames gives the record now holding a merge's survivor the
// duplicate's names (keepOrgNames, keepPersonNames), for a merge made before
// merges kept every name, and returns what it added.
func (a Adapter) KeepMergedNames(ctx context.Context, survivorID string, duplicate json.RawMessage,
	confidence int) (review.MergeRecord, error) {
	rec := review.MergeRecord{SurvivorID: survivorID, DuplicateAsset: duplicate}
	surv, err := a.Repo.FindEntityById(ctx, survivorID)
	if missing(err) || (err == nil && (surv == nil || surv.Asset == nil)) {
		return rec, fmt.Errorf("entity %s: %w", survivorID, review.ErrRecordGone)
	} else if err != nil {
		return rec, fmt.Errorf("entity %s: %w", survivorID, err)
	}

	src := &general.SourceProperty{Source: review.InferenceSource, Confidence: confidence}
	var renamed bool
	var merged oam.Asset
	switch s := surv.Asset.(type) {
	case *oamorg.Organization:
		var dup oamorg.Organization
		if err := json.Unmarshal(duplicate, &dup); err != nil {
			return rec, err
		}
		next := *s
		merged = &next
		renamed, err = a.keepOrgNames(ctx, surv, &next, &dup, src, &rec)
	case *oampeople.Person:
		var dup oampeople.Person
		if err := json.Unmarshal(duplicate, &dup); err != nil {
			return rec, err
		}
		next := *s
		merged = &next
		renamed, err = a.keepPersonNames(ctx, surv, &next, &dup, &rec)
	default:
		return rec, fmt.Errorf("entity %s is neither an organization nor a person", survivorID)
	}
	if err == nil && renamed {
		err = a.storeContent(ctx, merged)
	}
	return rec, err
}
