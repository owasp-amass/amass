// Copyright © by Jeff Foley 2017-2024. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package viz

import (
	"strings"
	"time"

	"github.com/owasp-amass/amass/v4/utils"
	assetdb "github.com/owasp-amass/asset-db"
	"github.com/owasp-amass/asset-db/types"
	oam "github.com/owasp-amass/open-asset-model"
	oamcert "github.com/owasp-amass/open-asset-model/certificate"
	"github.com/owasp-amass/open-asset-model/contact"
	"github.com/owasp-amass/open-asset-model/domain"
	oamreg "github.com/owasp-amass/open-asset-model/registration"
	"github.com/owasp-amass/open-asset-model/relation"
)

// Edge represents an Amass graph edge in the viz package.
type Edge struct {
	From, To int
	Label    string
	Title    string
}

// Node represents an Amass graph node in the viz package.
type Node struct {
	ID    int
	Type  string
	Label string
	Title string
}

// VizData returns the current state of the Graph as viz package Nodes and Edges.
func VizData(domains []string, since time.Time, db *assetdb.AssetDB) ([]Node, []Edge) {
	if len(domains) == 0 {
		return []Node{}, []Edge{}
	}

	var next []*types.Entity
	for _, d := range domains {
		if ents, err := db.Repo.FindEntityByContent(&domain.FQDN{Name: d}, since); err == nil && len(ents) == 1 {
			if n, err := utils.FindByFQDNScope(db.Repo, ents[0], since); err == nil && len(n) > 0 {
				next = append(next, n...)
			}
		}
	}

	var idx int
	var viznodes []Node
	var vizedges []Edge
	nodeToIdx := make(map[string]int)
	for {
		if len(next) == 0 {
			break
		}

		var assets []*types.Entity
		assets = append(assets, next...)
		next = []*types.Entity{}

		for _, a := range assets {
			n := newNode(db, idx, a, since)
			if n == nil {
				continue
			}
			// Keep track of which indices nodes were assigned to
			id := idx
			if nid, found := nodeToIdx[n.Label]; !found {
				idx++
				nodeToIdx[n.Label] = id
				viznodes = append(viznodes, *n)
			} else {
				id = nid
			}
			// Determine relationship directions to follow on the graph
			var in, out bool
			var inRels, outRels []string
			switch a.Asset.AssetType() {
			case oam.FQDN:
				if domainNameInScope(n.Label, domains) {
					in = true
					out = true
				} else if associatedWithScope(db, a, domains, since) {
					out = true
				}
			case oam.IPAddress:
				in = true
				inRels = append(inRels, "contains")
				out = true
			case oam.Netblock:
				in = true
				inRels = append(inRels, "announces")
				out = true
				outRels = append(outRels, "registration")
			case oam.AutonomousSystem:
				out = true
				outRels = append(outRels, "registration")
			case oam.AutnumRecord:
				out = true
			case oam.IPNetRecord:
				out = true
			case oam.ContactRecord:
				out = true
			case oam.EmailAddress:
				out = true
			case oam.Location:
				out = true
			case oam.Phone:
				out = true
			case oam.Organization:
				out = true
			case oam.Person:
				out = true
			case oam.TLSCertificate:
				out = true
			case oam.URL:
				out = true
			case oam.DomainRecord:
				out = true
			case oam.Service:
				out = true
			default:
			}
			// Obtain relations to additional assets in the graph
			if out {
				if edges, err := db.Repo.OutgoingEdges(a, since, outRels...); err == nil && len(edges) > 0 {
					fromID := id
					for _, edge := range edges {
						if to, err := db.Repo.FindEntityById(edge.ToEntity.ID); err == nil {
							toID := idx
							n2 := newNode(db, toID, to, since)
							if n2 == nil {
								continue
							}

							if id, found := nodeToIdx[n2.Label]; !found {
								idx++
								nodeToIdx[n2.Label] = toID
								viznodes = append(viznodes, *n2)
								next = append(next, to)
							} else {
								toID = id
							}

							vizedges = append(vizedges, Edge{
								From:  fromID,
								To:    toID,
								Label: edge.Relation.Label(),
								Title: edge.Relation.Label(),
							})
						}
					}
				}
			}
			if in {
				if edges, err := db.Repo.IncomingEdges(a, since, inRels...); err == nil && len(edges) > 0 {
					toID := id
					for _, edge := range edges {
						if from, err := db.Repo.FindEntityById(edge.FromEntity.ID); err == nil {
							fromID := idx
							n2 := newNode(db, fromID, from, since)
							if n2 == nil {
								continue
							}

							if id, found := nodeToIdx[n2.Label]; !found {
								idx++
								nodeToIdx[n2.Label] = fromID
								viznodes = append(viznodes, *n2)
								if edge.Relation.Label() != "ptr_record" {
									next = append(next, from)
								}
							} else {
								fromID = id
							}

							vizedges = append(vizedges, Edge{
								From:  fromID,
								To:    toID,
								Label: edge.Relation.Label(),
								Title: edge.Relation.Label(),
							})
						}
					}
				}
			}
		}
	}
	return viznodes, vizedges
}

func newNode(db *assetdb.AssetDB, idx int, a *types.Entity, since time.Time) *Node {
	if a == nil || a.Asset == nil {
		return nil
	}
	asset := a.Asset

	key := asset.Key()
	if key == "" {
		return nil
	}

	atype := string(asset.AssetType())
	switch v := asset.(type) {
	case *contact.ContactRecord:
		key = "Found->" + key
	case *contact.Location:
		parts := []string{v.BuildingNumber, v.StreetName, v.City, v.Province, v.PostalCode}
		key = strings.Join(parts, " ")
	case *oamreg.DomainRecord:
		key = "WHOIS: " + key
	case *oamcert.TLSCertificate:
		key = "x509 Serial Number: " + v.SerialNumber
	}
	title := atype + ": " + key

	return &Node{
		ID:    idx,
		Type:  atype,
		Label: key,
		Title: title,
	}
}

func domainNameInScope(name string, scope []string) bool {
	var discovered bool

	n := strings.ToLower(strings.TrimSpace(name))
	for _, d := range scope {
		d = strings.ToLower(d)

		if n == d || strings.HasSuffix(n, "."+d) {
			discovered = true
			break
		}
	}

	return discovered
}

func associatedWithScope(db *assetdb.AssetDB, asset *types.Entity, scope []string, since time.Time) bool {
	if edges, err := db.Repo.OutgoingEdges(asset, since, "dns_record"); err == nil && len(edges) > 0 {
		for _, edge := range edges {
			if to, err := db.Repo.FindEntityById(edge.ToEntity.ID); err == nil {
				if n, ok := to.Asset.(*domain.FQDN); ok && n != nil && domainNameInScope(n.Name, scope) {
					return true
				}
			}
		}
		return false
	}
	return followBackForScope(db, asset, scope, since)
}

func followBackForScope(db *assetdb.AssetDB, asset *types.Entity, scope []string, since time.Time) bool {
	if edges, err := db.Repo.IncomingEdges(asset, since, "dns_record"); err == nil && len(edges) > 0 {
		for _, edge := range edges {
			if rel, ok := edge.Relation.(*relation.BasicDNSRelation); ok && rel.Header.RRType != 5 {
				continue
			} else if rel, ok := edge.Relation.(*relation.PrefDNSRelation); ok && rel.Header.RRType != 2 && rel.Header.RRType != 15 {
				continue
			} else if rel, ok := edge.Relation.(*relation.SRVDNSRelation); ok && rel.Header.RRType != 33 {
				continue
			}
			if from, err := db.Repo.FindEntityById(edge.FromEntity.ID); err == nil {
				if n, ok := from.Asset.(*domain.FQDN); ok && n != nil && domainNameInScope(n.Name, scope) {
					return true
				} else if followBackForScope(db, from, scope, since) {
					return true
				}
			}
		}
	}
	return false
}
