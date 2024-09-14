// Copyright © by Jeff Foley 2017-2024. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package viz

import (
	"strings"
	"time"

	assetdb "github.com/owasp-amass/asset-db"
	"github.com/owasp-amass/asset-db/types"
	oam "github.com/owasp-amass/open-asset-model"
	"github.com/owasp-amass/open-asset-model/contact"
	"github.com/owasp-amass/open-asset-model/domain"
	oamreg "github.com/owasp-amass/open-asset-model/registration"
	"github.com/owasp-amass/open-asset-model/source"
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

	var fqdns []oam.Asset
	for _, d := range domains {
		fqdns = append(fqdns, &domain.FQDN{Name: d})
	}

	if !since.IsZero() {
		since = since.UTC()
	}

	next, err := db.FindByScope(fqdns, since)
	if err != nil {
		return []Node{}, []Edge{}
	}

	var idx int
	var nodes []Node
	var edges []Edge
	nodeToIdx := make(map[string]int)
	for {
		if len(next) == 0 {
			break
		}

		var assets []*types.Asset
		assets = append(assets, next...)
		next = []*types.Asset{}

		for _, a := range assets {
			n := newNode(idx, a)
			if n == nil {
				continue
			}
			// Keep track of which indices nodes were assigned to
			id := idx
			if nid, found := nodeToIdx[n.Label]; !found {
				idx++
				nodeToIdx[n.Label] = id
				nodes = append(nodes, *n)
			} else {
				id = nid
			}
			// Determine relationship directions to follow on the graph
			var in, out bool
			var inRels, outRels []string
			switch a.Asset.AssetType() {
			case oam.FQDN:
				out = true
				if domainNameInScope(n.Label, domains) {
					in = true
				}
			case oam.IPAddress:
				in = true
				inRels = append(inRels, "contains")
				out = true
			case oam.Netblock:
				in = true
				inRels = append(inRels, "announces")
			case oam.AutonomousSystem:
				out = true
				outRels = append(outRels, "registration")
			case oam.AutnumRecord:
				out = true
			case oam.SocketAddress:
			case oam.ContactRecord:
				out = true
			case oam.EmailAddress:
				out = true
			case oam.Location:
				out = true
			case oam.Phone:
				out = true
			case oam.Fingerprint:
			case oam.Organization:
				out = true
			case oam.Person:
				out = true
			case oam.TLSCertificate:
			case oam.URL:
				out = true
			case oam.DomainRecord:
				out = true
			case oam.Source:
			default:
			}
			// Obtain relations to additional assets in the graph
			if out {
				if rels, err := db.OutgoingRelations(a, since, outRels...); err == nil && len(rels) > 0 {
					fromID := id
					for _, rel := range rels {
						if to, err := db.FindById(rel.ToAsset.ID, since); err == nil {
							toID := idx
							n2 := newNode(toID, to)
							if n2 == nil {
								continue
							}

							if id, found := nodeToIdx[n2.Label]; !found {
								idx++
								nodeToIdx[n2.Label] = toID
								nodes = append(nodes, *n2)
								next = append(next, to)
							} else {
								toID = id
							}

							edges = append(edges, Edge{
								From:  fromID,
								To:    toID,
								Label: rel.Type,
								Title: rel.Type,
							})
						}
					}
				}
			}
			if in {
				if rels, err := db.IncomingRelations(a, since, inRels...); err == nil && len(rels) > 0 {
					toID := id
					for _, rel := range rels {
						if from, err := db.FindById(rel.FromAsset.ID, since); err == nil {
							fromID := idx
							n2 := newNode(fromID, from)
							if n2 == nil {
								continue
							}

							if id, found := nodeToIdx[n2.Label]; !found {
								idx++
								nodeToIdx[n2.Label] = fromID
								nodes = append(nodes, *n2)
								if rel.Type != "ptr_record" {
									next = append(next, from)
								}
							} else {
								fromID = id
							}

							edges = append(edges, Edge{
								From:  fromID,
								To:    toID,
								Label: rel.Type,
								Title: rel.Type,
							})
						}
					}
				}
			}
		}
	}
	return nodes, edges
}

func newNode(idx int, a *types.Asset) *Node {
	if a == nil || a.Asset == nil {
		return nil
	}
	asset := a.Asset

	key := asset.Key()
	if key == "" {
		return nil
	}

	atype := string(asset.AssetType())
	if atype == string(oam.Source) {
		return nil
	}

	switch v := asset.(type) {
	case *oamreg.AutnumRecord:
		key = v.Handle + " - " + key
	case *contact.ContactRecord:
		key = "Found->" + key
	case *contact.Location:
		parts := []string{v.BuildingNumber, v.StreetName, v.City, v.Province, v.PostalCode}
		key = strings.Join(parts, " ")
	case *oamreg.DomainRecord:
		key = "WHOIS: " + key
	case *source.Source:
		return nil
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
