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
	Data []oam.Asset `json:"data"`
}

func Extract(db repository.Repository, triples []*Triple) (*Results, error) {
	if len(triples) == 0 {
		return nil, errors.New("no triples provided for extraction")
	}

	ent, err := findFirstSubject(db, triples[0].Subject)
	if err != nil {
		return nil, fmt.Errorf("failed to find first subject: %w", err)
	}

	subents := []*dbt.Entity{ent}
	for i, triple := range triples {
		ents := subents
		objids := stringset.New()
		subents = []*dbt.Entity{}

		for _, ent := range ents {
			objects, err := getObjects(db, ent, triple)
			if err != nil || len(objects) == 0 {
				continue // skip this entity if no objects are found
			}

			for _, obj := range objects {
				if !objids.Has(obj.ID) {
					objids.Insert(obj.ID)
					subents = append(subents, obj)
				}
			}
		}
		objids.Close()

		if len(subents) == 0 {
			return nil, fmt.Errorf("no objects found for triple %d", i+1)
		}
	}

	var results Results
	for _, ent := range subents {
		results.Data = append(results.Data, ent.Asset)
	}

	return &results, nil
}

func getObjects(db repository.Repository, ent *dbt.Entity, triple *Triple) ([]*dbt.Entity, error) {
	if ent == nil || triple == nil {
		return nil, errors.New("entity or triple cannot be nil")
	}

	var labels []string
	if triple.Predicate.Label != "*" {
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

	var objects []*dbt.Entity
	for _, edge := range edges {
		// perform filtering based on the predicate in the triple and the edge relation
		if edge == nil || (triple.Predicate.Type != oam.RelationType("*") && triple.Predicate.Type != edge.Relation.RelationType()) {
			continue // skip edges that do not match the predicate type
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
		if (triple.Object.Since.IsZero() || !obj.LastSeen.Before(triple.Object.Since)) && (triple.Object.Type == "*" ||
			triple.Object.Type == obj.Asset.AssetType()) && (triple.Object.Key == "*" || triple.Object.Key == obj.Asset.Key()) {
			objects = append(objects, obj)
		}
	}

	if len(objects) == 0 {
		return nil, fmt.Errorf("no objects found for entity %s with predicate %s", ent.ID, triple.Predicate.Label)
	}
	return objects, nil
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
