// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package lens

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/owasp-amass/amass/v5/internal/graph"
)

// Document evidence in lens answers: what a subject's own documents state
// about its suppliers, the products it uses and the organizations it is a
// member or partner of. It is shown, cited, beside the stored evidence; it is
// never written (the lenses read only).

// KindDocument is the vendors-lens kind of a supplier or product a subject's
// own documents name.
const KindDocument = "Stated in its own documents (cited, not verified)"

// docAffiliationKey is the affiliation signal of a membership or partnership
// a subject's own documents state.
const docAffiliationKey = "document_affiliation"

// docLensMaxCited bounds the documents cited for one vendor or affiliate.
const docLensMaxCited = 3

// rootDocumentFindings reads the relation findings with the given predicates
// from the documents the root publishes (DocumentSources): its own documents.
func rootDocumentFindings(ctx context.Context, g graph.Graph, schema graph.SchemaCatalog, root graph.Asset,
	limits LensLimits, predicates ...string) ([]docFinding, error) {
	sources, err := DocumentSources(ctx, g, schema, root, limits)
	if err != nil {
		return nil, err
	}

	want := map[string]bool{}
	for _, p := range predicates {
		want[p] = true
	}
	var out []docFinding
	for _, src := range sources {
		if src.Statements == 0 {
			continue
		}
		ev, err := g.Evidence(ctx, src.FileID, allEvidence)
		if err != nil {
			return out, err
		}
		for _, v := range propertyValues(ev, propDocStatement) {
			var st docStatement
			if json.Unmarshal([]byte(v), &st) != nil || st.Kind != "relation" || !want[st.Predicate] ||
				staleFinding(src.Stale, st.Predicate) {
				continue
			}
			out = append(out, docFinding{st: st, fileID: src.FileID, url: src.URL})
		}
	}
	return out, nil
}

// exactOrganization resolves a name to the one stored organization it names,
// by name or legal name; an ambiguous or unknown name resolves to nothing.
func exactOrganization(ctx context.Context, g graph.Graph, name string) (graph.Asset, bool) {
	r, ok := g.(graph.OrganizationResolver)
	if !ok || strings.TrimSpace(name) == "" {
		return graph.Asset{}, false
	}
	for _, q := range []graph.OrganizationQuery{{Name: name}, {LegalName: name}} {
		res, err := r.ResolveOrganizations(ctx, q, 2)
		if err != nil || res.Status == "ambiguous" || res.Status == "truncated" {
			return graph.Asset{}, false
		}
		if res.Status == "matched" && len(res.Candidates) == 1 {
			return res.Candidates[0].Asset, true
		}
	}
	return graph.Asset{}, false
}

// documentVendors returns the suppliers and products the root's own
// documents name: an organization a service, product or the subject itself
// is supplied by, and a product the subject uses. own holds the folded names
// of the subject's own organizations, which are never its vendors. Each use
// counts the documents stating it and cites the first few.
func documentVendors(ctx context.Context, g graph.Graph, schema graph.SchemaCatalog, root graph.Asset,
	limits LensLimits, own map[string]bool) ([]VendorUse, error) {
	findings, err := rootDocumentFindings(ctx, g, schema, root, limits, "supplied_by", "uses_product")
	if err != nil || len(findings) == 0 {
		return nil, err
	}

	type use struct {
		v     VendorUse
		files map[string]bool
	}
	found := map[string]*use{}
	var order []string
	for _, f := range findings {
		switch f.st.SubjectType {
		case "Organization":
			if !own[docFold(f.st.Subject)] {
				// a third party's supplier is not the subject's
				continue
			}
		case "Service", "Product":
			if f.st.Predicate != "supplied_by" {
				continue
			}
		default:
			continue
		}
		vendor := strings.Join(strings.Fields(f.st.Object), " ")
		key := docFold(vendor)
		if key == "" || own[key] {
			continue
		}

		u, ok := found[key]
		if !ok {
			u = &use{v: VendorUse{Vendor: vendor, Kind: KindDocument, Via: "document " + f.st.Predicate},
				files: map[string]bool{}}
			if f.st.ObjectType == "Organization" {
				if org, ok := exactOrganization(ctx, g, vendor); ok {
					u.v.VendorID = org.ID
				}
			}
			found[key] = u
			order = append(order, key)
		}
		if !u.files[f.fileID] {
			u.files[f.fileID] = true
			if len(u.v.Examples) < docLensMaxCited {
				what := fmt.Sprintf("%s %s %s (%s)", f.st.Subject, f.st.Predicate, f.st.Object, f.url)
				u.v.Examples = append(u.v.Examples, what)
			}
		}
	}

	out := make([]VendorUse, 0, len(order))
	for _, key := range order {
		u := found[key]
		u.v.Assets = len(u.files)
		out = append(out, u.v)
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Vendor < out[j].Vendor })
	return out, nil
}

// ownNames folds the names of a report's own organizations: its registrant
// owners and the institution the family lens found.
func ownNames(r ThirdPartyReport) map[string]bool {
	own := map[string]bool{}
	for _, n := range append(append([]string{}, r.Owners...), r.Institution) {
		if k := docFold(n); k != "" {
			own[k] = true
		}
	}
	return own
}

// docAffiliation is a membership or partnership the subject's own documents
// state with another stored organization.
type docAffiliation struct {
	org      graph.Asset
	evidence string
	weight   float64
}

// documentAffiliations returns the organizations the root's own documents
// state the subject is a member or partner of (or that are members or
// partners of it), each resolved exactly to one stored organization. The
// weight is a first-party document's, with the corroboration bonus when two
// or more distinct document versions state it.
func documentAffiliations(ctx context.Context, g graph.Graph, schema graph.SchemaCatalog, root graph.Asset,
	limits LensLimits, subjects []graph.Asset) ([]docAffiliation, error) {
	findings, err := rootDocumentFindings(ctx, g, schema, root, limits, "member_of", "partner_of")
	if err != nil || len(findings) == 0 {
		return nil, err
	}

	subject := map[string]bool{}
	subjectID := map[string]bool{}
	for _, o := range subjects {
		subjectID[o.ID] = true
		for _, field := range []string{"name", "legal_name"} {
			if k := docFold(graph.ContentString(o, field)); k != "" {
				subject[k] = true
			}
		}
	}

	type agg struct {
		a        docAffiliation
		versions map[string]bool
		dated    time.Time
	}
	found := map[string]*agg{}
	var order []string
	for _, f := range findings {
		if f.st.SubjectType != "Organization" || f.st.ObjectType != "Organization" {
			continue
		}
		var other string
		switch {
		case subject[docFold(f.st.Subject)]:
			other = f.st.Object
		case subject[docFold(f.st.Object)]:
			other = f.st.Subject
		default:
			continue
		}
		org, ok := exactOrganization(ctx, g, other)
		if !ok || subjectID[org.ID] {
			continue
		}

		x, ok := found[org.ID]
		if !ok {
			x = &agg{a: docAffiliation{org: org,
				evidence: fmt.Sprintf("%s %s %s (%s)", f.st.Subject, f.st.Predicate, f.st.Object, f.url)},
				versions: map[string]bool{}}
			found[org.ID] = x
			order = append(order, org.ID)
		}
		x.versions[f.version()] = true
		x.dated = newer(x.dated, f.dated)
	}

	out := make([]docAffiliation, 0, len(order))
	for _, id := range order {
		x := found[id]
		x.a.weight = DocumentWeight(true, len(x.versions), x.dated)
		out = append(out, x.a)
	}
	return out, nil
}
