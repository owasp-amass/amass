// Copyright © by Jeff Foley 2017-2024. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package viz

import (
	"strconv"
	"strings"
	"time"

	"github.com/owasp-amass/asset-db/types"
	"github.com/owasp-amass/engine/graph"
	oam "github.com/owasp-amass/open-asset-model"
	"github.com/owasp-amass/open-asset-model/domain"
	"github.com/owasp-amass/open-asset-model/network"
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
func VizData(domains []string, since time.Time, g *graph.Graph) ([]Node, []Edge) {
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

	next, err := g.DB.FindByScope(fqdns, since)
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
			switch a.Asset.AssetType() {
			case oam.FQDN:
				out = true
				if domainNameInScope(n.Label, domains) {
					in = true
				}
			case oam.IPAddress:
				in = true
			case oam.Netblock:
				in = true
			case oam.ASN:
				out = true
			case oam.RIROrg:
				in = true
			}
			// Obtain relations to additional assets in the graph
			if rels, err := g.DB.OutgoingRelations(a, since); err == nil && out {
				fromID := id
				for _, rel := range rels {
					if to, err := g.DB.FindById(rel.ToAsset.ID, since); err == nil {
						toID := idx
						n2 := newNode(toID, to)

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
			if rels, err := g.DB.IncomingRelations(a, since); err == nil && in {
				toID := id
				for _, rel := range rels {
					if from, err := g.DB.FindById(rel.FromAsset.ID, since); err == nil {
						fromID := idx
						n2 := newNode(fromID, from)

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

	return nodes, edges
}

func newNode(idx int, a *types.Asset) *Node {
	var name, atype, title string

	switch v := a.Asset.(type) {
	case *domain.FQDN:
		name = v.Name
		atype = string(oam.FQDN)
		title = atype + ": " + name
	case *network.IPAddress:
		name = v.Address.String()
		atype = string(oam.IPAddress)
		title = atype + ": " + name
	case *network.AutonomousSystem:
		name = strconv.Itoa(v.Number)
		atype = string(oam.ASN)
		title = atype + ": AS" + name
	case *network.RIROrganization:
		name = v.RIRId + v.Name
		atype = string(oam.RIROrg)
		title = atype + ": " + name
	case *network.Netblock:
		name = v.Cidr.String()
		atype = string(oam.Netblock)
		title = atype + ": " + name
	default:
		return nil
	}

	return &Node{
		ID:    idx,
		Type:  atype,
		Label: name,
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
