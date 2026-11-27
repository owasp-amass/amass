// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package org

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/caffix/stringset"
	et "github.com/owasp-amass/amass/v5/engine/types"
	"github.com/owasp-amass/amass/v5/internal/graph"
	"github.com/owasp-amass/amass/v5/internal/semantics"
	dbt "github.com/owasp-amass/asset-db/types"
	oam "github.com/owasp-amass/open-asset-model"
	"github.com/owasp-amass/open-asset-model/general"
	"github.com/owasp-amass/open-asset-model/org"
)

// NameMatch checks if the provided organization entity matches any of the given names.
func NameMatch(sess et.Session, orgent *dbt.Entity, names []string) ([]string, []string, bool) {
	var found bool
	var exact, partial []string

	if orgent == nil || len(names) == 0 {
		return exact, partial, found
	}

	o, ok := orgent.Asset.(*org.Organization)
	if !ok {
		return exact, partial, found
	}

	set := stringset.New()
	defer set.Close()

	if o.Name != "" {
		set.Insert(o.Name)
	}
	if o.LegalName != "" {
		set.Insert(o.LegalName)
	}

	ctx, cancel := context.WithTimeout(sess.Ctx(), 10*time.Second)
	defer cancel()

	if edges, err := sess.DB().OutgoingEdges(ctx, orgent, time.Time{}, "id"); err == nil && len(edges) > 0 {
		seconds := 10 * len(edges)
		ctx, cancel := context.WithTimeout(sess.Ctx(), time.Duration(seconds)*time.Second)
		defer cancel()

		for _, edge := range edges {
			if a, err := sess.DB().FindEntityById(ctx, edge.ToEntity.ID); err == nil && a != nil {
				if id, ok := a.Asset.(*general.Identifier); ok &&
					(id.Type == general.OrganizationName || id.Type == general.LegalName) {
					set.Insert(id.ID)
				}
			}
		}
	}

	orgnames := set.Slice()
	for _, name := range names {
		var isExact, isNear bool
		for _, orgname := range orgnames {
			e, n := semantics.OrgNameMatch(orgname, name)
			isExact, isNear = isExact || e, isNear || n
		}
		switch {
		case isExact:
			exact = append(exact, name)
		case isNear:
			partial = append(partial, name)
		}
	}
	found = len(exact) > 0 || len(partial) > 0

	return exact, partial, found
}

func orgsWithSameNames(sess et.Session, names []string) ([]*dbt.Entity, error) {
	var idents []*dbt.Entity
	ctx, cancel := context.WithTimeout(sess.Ctx(), 2*time.Minute)
	defer cancel()

	// Name claims keep the name as each source wrote it, and callers pass
	// either that or the normalized lower-case name, so both forms are
	// looked up.
	var forms []string
	for _, n := range names {
		if n == "" {
			continue
		}
		graph.AddUnique(&forms, n)
		graph.AddUnique(&forms, strings.ToLower(n))
	}
	for _, name := range forms {
		for _, idType := range []string{general.OrganizationName, general.LegalName} {
			if assets, err := sess.DB().FindEntitiesByContent(ctx, oam.Identifier, time.Time{}, 0, dbt.ContentFilters{
				"unique_id": idType + ":" + name,
			}); err == nil {
				for _, a := range assets {
					if _, ok := a.Asset.(*general.Identifier); ok {
						idents = append(idents, a)
					}
				}
			}
		}
	}

	var orgents []*dbt.Entity
	for _, ident := range idents {
		if edges, err := sess.DB().IncomingEdges(ctx, ident, time.Time{}, "id"); err == nil {
			for _, edge := range edges {
				if a, err := sess.DB().FindEntityById(ctx, edge.FromEntity.ID); err == nil && a != nil {
					if _, ok := a.Asset.(*org.Organization); ok {
						orgents = append(orgents, a)
					}
				}
			}
		}
	}

	if len(orgents) == 0 {
		return nil, errors.New("no matching organizations were found")
	}
	return orgents, nil
}
