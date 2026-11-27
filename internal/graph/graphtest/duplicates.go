// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package graphtest

import (
	"fmt"

	"github.com/owasp-amass/amass/v5/internal/graph"
)

// orgGraph builds organizations in the shapes the OWASP data showed.
type orgGraph struct {
	Graph FakeGraph
	next  int
}

func NewOrgGraph() *orgGraph {
	return &orgGraph{Graph: FakeGraph{Assets: map[string]graph.Asset{}}}
}

func (o *orgGraph) id() string {
	o.next++
	return fmt.Sprintf("%d", o.next)
}

func (o *orgGraph) Org(id, name, legal, jurisdiction, reg string) string {
	o.Graph.Assets[id] = graph.Asset{ID: id, Type: "Organization", Key: name + ":" + id, Content: map[string]any{
		"name": name, "legal_name": legal, "jurisdiction": jurisdiction, "registration_id": reg}}
	return id
}

func (o *orgGraph) Link(from, to, label string) {
	o.Graph.Links = append(o.Graph.Links, graph.Relation{ID: "e" + o.id(), FromID: from, ToID: to, Label: label,
		Type: "SimpleRelation"})
}

func (o *orgGraph) Ident(org, idtype, value string) {
	key := idtype + ":" + value
	if _, ok := o.Graph.Assets[key]; !ok {
		o.Graph.Assets[key] = graph.Asset{ID: key, Type: "Identifier", Key: key,
			Content: map[string]any{"id": value, "id_type": idtype}}
	}
	o.Link(org, key, "id")
}

// Contact adds a contact record naming org, at location loc when given.
func (o *orgGraph) Contact(org, cr, loc string) {
	if _, ok := o.Graph.Assets[cr]; !ok {
		o.Graph.Assets[cr] = graph.Asset{ID: cr, Type: "ContactRecord", Key: cr}
	}
	o.Link(cr, org, "organization")
	if loc != "" {
		if _, ok := o.Graph.Assets[loc]; !ok {
			o.Graph.Assets[loc] = graph.Asset{ID: loc, Type: "StreetAddress", Key: loc}
		}
		o.Link(cr, loc, "street_address")
	}
}
