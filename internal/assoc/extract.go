// Copyright © by Jeff Foley 2017-2025. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package assoc

import (
	"errors"
	"fmt"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/caffix/stringset"
	"github.com/owasp-amass/asset-db/repository"
	dbt "github.com/owasp-amass/asset-db/types"
	oam "github.com/owasp-amass/open-asset-model"
	oamacct "github.com/owasp-amass/open-asset-model/account"
	oamcert "github.com/owasp-amass/open-asset-model/certificate"
	oamcontact "github.com/owasp-amass/open-asset-model/contact"
	oamdns "github.com/owasp-amass/open-asset-model/dns"
	oamfile "github.com/owasp-amass/open-asset-model/file"
	oamfin "github.com/owasp-amass/open-asset-model/financial"
	oamgen "github.com/owasp-amass/open-asset-model/general"
	oamnet "github.com/owasp-amass/open-asset-model/network"
	oamorg "github.com/owasp-amass/open-asset-model/org"
	oampeople "github.com/owasp-amass/open-asset-model/people"
	oamplat "github.com/owasp-amass/open-asset-model/platform"
	oamreg "github.com/owasp-amass/open-asset-model/registration"
	oamurl "github.com/owasp-amass/open-asset-model/url"
)

type Results struct {
	Node *node `json:"entity"`
}

type node struct {
	Ent        *dbt.Entity   `json:"-"`
	ID         string        `json:"id"`
	Type       oam.AssetType `json:"type"`
	CreatedAt  string        `json:"created_at"`
	LastSeen   string        `json:"last_seen"`
	Asset      oam.Asset     `json:"asset"`
	Relations  []*link       `json:"edges"`
	Properties []*prop       `json:"properties"`
}

type link struct {
	ID         string           `json:"id"`
	Type       oam.RelationType `json:"type"`
	CreatedAt  string           `json:"created_at"`
	LastSeen   string           `json:"last_seen"`
	Relation   oam.Relation     `json:"relation"`
	Node       *node            `json:"entity"`
	Properties []*prop          `json:"properties"`
}

type prop struct {
	ID        string           `json:"id"`
	Type      oam.PropertyType `json:"type"`
	CreatedAt string           `json:"created_at"`
	LastSeen  string           `json:"last_seen"`
	Property  oam.Property     `json:"property"`
}

func Extract(db repository.Repository, triples []*Triple) (*Results, error) {
	if len(triples) == 0 {
		return nil, errors.New("no triples provided for extraction")
	}

	ent, err := findFirstSubject(db, triples[0].Subject)
	if err != nil {
		return nil, fmt.Errorf("failed to find first subject: %w", err)
	}

	n := &node{
		Ent:       ent,
		ID:        ent.ID,
		Type:      ent.Asset.AssetType(),
		CreatedAt: ent.CreatedAt.Format(time.DateOnly),
		LastSeen:  ent.LastSeen.Format(time.DateOnly),
		Asset:     ent.Asset,
		Relations: []*link{},
	}

	rels, err := performWalk(db, triples, 0, []*link{{Node: n}})
	if err != nil {
		return nil, err
	}
	if len(rels) != 1 {
		return nil, errors.New("failed to extract the walk from the first subject")
	}

	return &Results{Node: n}, nil
}

func performWalk(db repository.Repository, triples []*Triple, idx int, links []*link) ([]*link, error) {
	var rels []*link
	triple := triples[idx]

	for _, n := range links {
		ent := n.Node.Ent

		// filter based on the entity asset and the triple subject
		if (!triple.Subject.Since.IsZero() && ent.LastSeen.Before(triple.Subject.Since)) ||
			(triple.Subject.Type != "*" && triple.Subject.Type != ent.Asset.AssetType()) ||
			(triple.Subject.Key != "*" && !valueMatch(ent.Asset.Key(), triple.Subject.Key,
				triple.Subject.Regexp)) || !allAttrsMatch(ent.Asset, triple.Subject.Attributes) {
			continue
		}

		subjectProps, ok := entityPropsMatch(db, ent, triple.Subject.Properties)
		if !ok {
			continue // skip this entity if properties do not match
		}
		n.Node.Properties = subjectProps

		entRels, err := predAndObject(db, ent, triple)
		if err != nil || len(entRels) == 0 {
			continue // skip this entity if no objects are found
		}

		if idx+1 < len(triples) {
			entRels, err = performWalk(db, triples, idx+1, entRels)
			if err != nil || len(entRels) == 0 {
				continue // skip if the walk could not be completed
			}
		}

		rels = append(rels, n)
		n.Node.Relations = append(n.Node.Relations, entRels...)
	}

	var err error
	if len(rels) == 0 {
		err = errors.New("no walks were successful")
	}
	return rels, err
}

func predAndObject(db repository.Repository, ent *dbt.Entity, triple *Triple) ([]*link, error) {
	if ent == nil || triple == nil {
		return nil, errors.New("entity or triple cannot be nil")
	}

	var labels []string
	if triple.Predicate.Label != "*" && triple.Predicate.Regexp == nil {
		labels = []string{triple.Predicate.Label}
	}

	var err error
	var edges []*dbt.Edge
	if triple.Direction == DirectionIncoming {
		edges, err = db.IncomingEdges(ent, triple.Predicate.Since, labels...)
	} else {
		edges, err = db.OutgoingEdges(ent, triple.Predicate.Since, labels...)
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get edges for entity %s: %v", ent.ID, err)
	}

	var results []*link
	for _, edge := range edges {
		// perform filtering based on the predicate in the triple and the edge relation
		if edge == nil || (triple.Predicate.Type != oam.RelationType("*") &&
			triple.Predicate.Type != edge.Relation.RelationType()) || (triple.Predicate.Label != "*" &&
			!valueMatch(edge.Relation.Label(), triple.Predicate.Label, triple.Predicate.Regexp)) ||
			!allAttrsMatch(edge.Relation, triple.Predicate.Attributes) {
			continue // skip edges that do not match the predicate
		}

		linkProps, ok := edgePropsMatch(db, edge, triple.Predicate.Properties)
		if !ok {
			continue // skip edges that do not match the properties
		}

		var objent *dbt.Entity
		if triple.Direction == DirectionIncoming {
			objent = edge.FromEntity
		} else {
			objent = edge.ToEntity
		}

		obj, err := db.FindEntityById(objent.ID)
		if err != nil {
			return nil, fmt.Errorf("failed to find the object entity %s: %v", objent.ID, err)
		}
		if obj == nil {
			return nil, errors.New("failed to return the object entity")
		}

		// perform filtering based on the object in the triple and the entity asset
		if (triple.Object.Since.IsZero() || !obj.LastSeen.Before(triple.Object.Since)) &&
			(triple.Object.Type == "*" || triple.Object.Type == obj.Asset.AssetType()) &&
			(triple.Object.Key == "*" || valueMatch(obj.Asset.Key(), triple.Object.Key,
				triple.Object.Regexp)) && allAttrsMatch(obj.Asset, triple.Object.Attributes) {

			if objectProps, ok := entityPropsMatch(db, obj, triple.Object.Properties); ok {
				results = append(results, &link{
					ID:        edge.ID,
					Type:      edge.Relation.RelationType(),
					CreatedAt: edge.CreatedAt.Format(time.DateOnly),
					LastSeen:  edge.LastSeen.Format(time.DateOnly),
					Relation:  edge.Relation,
					Node: &node{
						ID:         obj.ID,
						Ent:        obj,
						Type:       obj.Asset.AssetType(),
						CreatedAt:  obj.CreatedAt.Format(time.DateOnly),
						LastSeen:   obj.LastSeen.Format(time.DateOnly),
						Asset:      obj.Asset,
						Relations:  []*link{},
						Properties: objectProps,
					},
					Properties: linkProps,
				})
			}
		}
	}

	if len(results) == 0 {
		return nil, fmt.Errorf("no objects found for entity %s with predicate %s", ent.ID, triple.Predicate.Label)
	}
	return results, nil
}

func findFirstSubject(db repository.Repository, subject *Node) (*dbt.Entity, error) {
	if subject == nil {
		return nil, errors.New("subject cannot be nil")
	}

	asset, err := subjectToAsset(subject)
	if err != nil {
		return nil, fmt.Errorf("failed to convert subject to asset: %v", err)
	}

	ents, err := db.FindEntitiesByContent(asset, subject.Since)
	if err != nil {
		return nil, fmt.Errorf("failed to find the subject in the database: %v", err)
	}
	if len(ents) != 1 {
		return nil, fmt.Errorf("expected one entity for subject %s:%s, found %d", string(subject.Type), subject.Key, len(ents))
	}
	return ents[0], nil
}

func subjectToAsset(subject *Node) (oam.Asset, error) {
	subtype := string(subject.Type)

	switch {
	case strings.EqualFold(subtype, string(oam.Account)):
		return &oamacct.Account{ID: subject.Key}, nil
	case strings.EqualFold(subtype, string(oam.AutnumRecord)):
		return &oamreg.AutnumRecord{Handle: subject.Key}, nil
	case strings.EqualFold(subtype, string(oam.AutonomousSystem)):
		asn, err := strconv.Atoi(subject.Key)
		if err != nil {
			return nil, fmt.Errorf("invalid autonomous system number: %s", subject.Key)
		}
		return &oamnet.AutonomousSystem{Number: asn}, nil
	case strings.EqualFold(subtype, string(oam.ContactRecord)):
		return &oamcontact.ContactRecord{DiscoveredAt: subject.Key}, nil
	case strings.EqualFold(subtype, string(oam.DomainRecord)):
		return &oamreg.DomainRecord{Domain: subject.Key}, nil
	case strings.EqualFold(subtype, string(oam.File)):
		return &oamfile.File{URL: subject.Key}, nil
	case strings.EqualFold(subtype, string(oam.FQDN)):
		return &oamdns.FQDN{Name: subject.Key}, nil
	case strings.EqualFold(subtype, string(oam.FundsTransfer)):
		return &oamfin.FundsTransfer{ID: subject.Key}, nil
	case strings.EqualFold(subtype, string(oam.Identifier)):
		return &oamgen.Identifier{UniqueID: subject.Key}, nil
	case strings.EqualFold(subtype, string(oam.IPAddress)):
		addr, err := netip.ParseAddr(subject.Key)
		if err != nil {
			return nil, fmt.Errorf("invalid IP address: %s", subject.Key)
		}
		return &oamnet.IPAddress{Address: addr}, nil
	case strings.EqualFold(subtype, string(oam.IPNetRecord)):
		return &oamreg.IPNetRecord{Handle: subject.Key}, nil
	case strings.EqualFold(subtype, string(oam.Location)):
		return &oamcontact.Location{Address: subject.Key}, nil
	case strings.EqualFold(subtype, string(oam.Netblock)):
		prefix, err := netip.ParsePrefix(subject.Key)
		if err != nil {
			return nil, fmt.Errorf("invalid netblock prefix: %s", subject.Key)
		}
		return &oamnet.Netblock{CIDR: prefix}, nil
	case strings.EqualFold(subtype, string(oam.Organization)):
		return &oamorg.Organization{ID: subject.Key}, nil
	case strings.EqualFold(subtype, string(oam.Person)):
		return &oampeople.Person{ID: subject.Key}, nil
	case strings.EqualFold(subtype, string(oam.Phone)):
		return &oamcontact.Phone{Raw: subject.Key}, nil
	case strings.EqualFold(subtype, string(oam.Product)):
		return &oamplat.Product{ID: subject.Key}, nil
	case strings.EqualFold(subtype, string(oam.ProductRelease)):
		return &oamplat.ProductRelease{Name: subject.Key}, nil
	case strings.EqualFold(subtype, string(oam.Service)):
		return &oamplat.Service{ID: subject.Key}, nil
	case strings.EqualFold(subtype, string(oam.TLSCertificate)):
		return &oamcert.TLSCertificate{SerialNumber: subject.Key}, nil
	case strings.EqualFold(subtype, string(oam.URL)):
		return &oamurl.URL{Raw: subject.Key}, nil
	}

	return nil, fmt.Errorf("unknown asset type: %s", subtype)
}

func entityPropsMatch(db repository.Repository, ent *dbt.Entity, propstrs []*Property) ([]*prop, bool) {
	var names []string
	for _, p := range propstrs {
		if p.Name != "*" && p.Regexp == nil {
			names = append(names, p.Name)
		}
	}

	var since time.Time
	for _, p := range propstrs {
		if p.Since.IsZero() {
			continue // skip properties without a since value
		}
		if since.IsZero() || p.Since.Before(since) {
			since = p.Since // find the earliest since value
		}
	}

	tags, err := db.GetEntityTags(ent, since, names...)
	if err != nil || len(tags) == 0 {
		// return an empty slice if no tags are found or an error occurs
		return []*prop{}, len(propstrs) == 0
	}

	set := stringset.New()
	defer set.Close()

	for _, p := range propstrs {
		pkey := fmt.Sprintf("%s:%s", string(p.Type), p.Name)
		set.Insert(pkey)
	}

	matchedProps := []*prop{}
	for _, t := range tags {
		if t == nil || t.Property.Name() == "" || t.Property.Value() == "" {
			continue // skip invalid properties
		}

		passed := true
		for _, s := range propstrs {
			if s.Type == t.Property.PropertyType() &&
				(s.Name == "*" || valueMatch(t.Property.Name(), s.Name, s.Regexp)) {
				if !s.Since.IsZero() && t.LastSeen.Before(s.Since) {
					passed = false // property does not match the since value
					break
				}
				if !allAttrsMatch(t.Property, s.Attributes) {
					passed = false // property does not match the attributes
					break
				}
			}
		}

		if passed {
			matchedProps = append(matchedProps, &prop{
				ID:        t.ID,
				Type:      t.Property.PropertyType(),
				CreatedAt: t.CreatedAt.Format(time.DateOnly),
				LastSeen:  t.LastSeen.Format(time.DateOnly),
				Property:  t.Property,
			})
		}
	}

	return matchedProps, len(matchedProps) >= set.Len()
}

func edgePropsMatch(db repository.Repository, edge *dbt.Edge, propstrs []*Property) ([]*prop, bool) {
	var names []string
	for _, p := range propstrs {
		if p.Name != "*" && p.Regexp == nil {
			names = append(names, p.Name)
		}
	}

	var since time.Time
	for _, p := range propstrs {
		if p.Since.IsZero() {
			continue // skip properties without a since value
		}
		if since.IsZero() || p.Since.Before(since) {
			since = p.Since // find the earliest since value
		}
	}

	tags, err := db.GetEdgeTags(edge, since, names...)
	if err != nil || len(tags) == 0 {
		// indicate failure if no tags are found or an error occurs
		return []*prop{}, len(propstrs) == 0
	}

	set := stringset.New()
	defer set.Close()

	for _, p := range propstrs {
		pkey := fmt.Sprintf("%s:%s", string(p.Type), p.Name)
		set.Insert(pkey)
	}

	matchedProps := []*prop{}
	for _, t := range tags {
		if t == nil || t.Property.Name() == "" || t.Property.Value() == "" {
			continue // skip invalid properties
		}

		passed := true
		for _, s := range propstrs {
			if s.Type == t.Property.PropertyType() &&
				(s.Name == "*" || valueMatch(t.Property.Name(), s.Name, s.Regexp)) {
				if !s.Since.IsZero() && t.LastSeen.Before(s.Since) {
					passed = false // property does not match the since value
					break
				}
				if !allAttrsMatch(t.Property, s.Attributes) {
					passed = false // property does not match the attributes
					break
				}
			}
		}

		if passed {
			matchedProps = append(matchedProps, &prop{
				ID:        t.ID,
				Type:      t.Property.PropertyType(),
				CreatedAt: t.CreatedAt.Format(time.DateOnly),
				LastSeen:  t.LastSeen.Format(time.DateOnly),
				Property:  t.Property,
			})
		}
	}

	return matchedProps, len(matchedProps) >= set.Len()
}
