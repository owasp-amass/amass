// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package documents

import (
	"context"
	"strings"
	"time"
	"unicode"

	et "github.com/owasp-amass/amass/v5/engine/types"
	dbt "github.com/owasp-amass/asset-db/types"
	oam "github.com/owasp-amass/open-asset-model"
	oamacct "github.com/owasp-amass/open-asset-model/account"
	oamgen "github.com/owasp-amass/open-asset-model/general"
	oamurl "github.com/owasp-amass/open-asset-model/url"
	"golang.org/x/net/publicsuffix"
)

// DirectoryAccount is the account_type of a user account in an
// organization's directory, as a document's metadata shows it (the user
// folder in a file path written by the author's computer).
const DirectoryAccount = "directory"

// directoryAccountID is the Account's unique_id: the username within the
// directory of the registered domain the document was published on, so the
// same username at two organizations is two accounts.
func directoryAccountID(realm, username string) string {
	return DirectoryAccount + ":" + realm + ":" + strings.ToLower(username)
}

// accountLeads stores each username the document's metadata shows as a
// directory Account of the publishing domain, linked from the File by
// contains and dispatched as a lead. An account is tied to what was observed
// about it, and nothing is guessed:
//   - Account --user--> Person when the document names an author whose name
//     the username spells under a common convention (jsmith, john.smith,
//     smithj for John Smith);
//   - Account --id--> Identifier when the email address username@realm has
//     been observed.
func (d *documents) accountLeads(e *et.Event, fent *dbt.Entity, u *oamurl.URL, usernames []string,
	authors []author, n *leads) {
	realm, err := publicsuffix.EffectiveTLDPlusOne(strings.ToLower(u.Host))
	if err != nil || len(usernames) == 0 {
		return
	}

	seen := map[string]bool{}
	for _, name := range usernames {
		name = strings.TrimSpace(name)
		if name == "" || seen[strings.ToLower(name)] || n.accounts >= maxLeads {
			continue
		}
		seen[strings.ToLower(name)] = true

		acct := &oamacct.Account{ID: directoryAccountID(realm, name), Type: DirectoryAccount, Username: name}
		aent := d.linkAsset(e, fent, acct)
		if aent == nil {
			continue
		}
		n.accounts++

		for _, a := range authors {
			if usernameSpells(name, a.first, a.last) {
				d.edge(e, aent, "user", a.ent)
			}
		}
		if email := d.observedEmail(e, strings.ToLower(name)+"@"+realm); email != nil {
			d.edge(e, aent, "id", email)
		}

		d.dispatch(e, aent, acct.ID)
	}
}

// usernameSpells reports whether username is how a directory commonly writes
// the person first last: the full first name or its initial joined with the
// family name in either order, plainly or with a dot, underscore or hyphen.
// A bare first or family name is not taken; too many people share one.
func usernameSpells(username, first, last string) bool {
	f, l := letters(first), letters(last)
	if f == "" || l == "" {
		return false
	}
	user := strings.ToLower(username)
	fi := f[:1]

	for _, sep := range []string{"", ".", "_", "-"} {
		for _, form := range []string{f + sep + l, fi + sep + l, l + sep + f, l + sep + fi} {
			if user == form {
				return true
			}
		}
	}
	return false
}

// letters lowercases s and keeps only its letters.
func letters(s string) string {
	return strings.Map(func(r rune) rune {
		if unicode.IsLetter(r) {
			return unicode.ToLower(r)
		}
		return -1
	}, s)
}

// observedEmail returns the stored email Identifier for addr, if one was
// observed.
func (d *documents) observedEmail(e *et.Event, addr string) *dbt.Entity {
	ctx, cancel := context.WithTimeout(e.Session.Ctx(), 10*time.Second)
	defer cancel()

	ents, err := e.Session.DB().FindEntitiesByContent(ctx, oam.Identifier, time.Time{}, 1,
		dbt.ContentFilters{"unique_id": oamgen.EmailAddress + ":" + addr})
	if err != nil || len(ents) == 0 {
		return nil
	}
	return ents[0]
}

// edge records from --label--> to with the document as its source.
func (d *documents) edge(e *et.Event, from *dbt.Entity, label string, to *dbt.Entity) {
	ctx, cancel := context.WithTimeout(e.Session.Ctx(), 10*time.Second)
	defer cancel()

	edge, err := e.Session.DB().CreateEdge(ctx, &dbt.Edge{Relation: rel(label), FromEntity: from, ToEntity: to})
	if err != nil || edge == nil {
		return
	}
	_, _ = e.Session.DB().CreateEdgeProperty(ctx, edge, &oamgen.SourceProperty{
		Source:     d.source.Name,
		Confidence: d.source.Confidence,
	})
}
