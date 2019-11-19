// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package graph

import (
	"errors"

	"github.com/OWASP/Amass/v3/graph/db"
	"golang.org/x/net/publicsuffix"
)

// InsertFQDN adds a fully qualified domain name to the graph.
func (g *Graph) InsertFQDN(name, source, tag, eventID string) (db.Node, error) {
	tld, _ := publicsuffix.PublicSuffix(name)

	domain, err := publicsuffix.EffectiveTLDPlusOne(name)
	if err != nil {
		return nil, errors.New("InsertFQDN: Failed to obtain valid domain name(s)")
	}

	if name == "" || tld == "" || domain == "" {
		return nil, errors.New("InsertFQDN: Failed to obtain valid domain name(s)")
	}

	// Create the graph nodes that represent the three portions of the DNS name
	fqdnNode, err := g.InsertNodeIfNotExist(name, "fqdn")
	if err != nil {
		return fqdnNode, err
	}

	domainNode, err := g.InsertNodeIfNotExist(domain, "fqdn")
	if err != nil {
		return fqdnNode, err
	}

	tldNode, err := g.InsertNodeIfNotExist(tld, "fqdn")
	if err != nil {
		return fqdnNode, err
	}

	// Link the three nodes together
	domainEdge := &db.Edge{
		Predicate: "root",
		From:      fqdnNode,
		To:        domainNode,
	}
	if err := g.InsertEdge(domainEdge); err != nil {
		return fqdnNode, err
	}

	tldEdge := &db.Edge{
		Predicate: "tld",
		From:      domainNode,
		To:        tldNode,
	}
	if err := g.InsertEdge(tldEdge); err != nil {
		return fqdnNode, err
	}

	// Source and event edges for the FQDN
	if err := g.AddNodeToEvent(fqdnNode, source, tag, eventID); err != nil {
		return fqdnNode, err
	}

	// Source and event edges for the root domain name
	if err := g.AddNodeToEvent(domainNode, source, tag, eventID); err != nil {
		return fqdnNode, err
	}

	// Source and event edges for the top-level domain name
	if err := g.AddNodeToEvent(tldNode, source, tag, eventID); err != nil {
		return fqdnNode, err
	}

	return fqdnNode, nil
}

// InsertCNAME adds the FQDNs and CNAME record between them to the graph.
func (g *Graph) InsertCNAME(fqdn, target, source, tag, eventID string) error {
	return g.insertAlias(fqdn, target, "cname_record", source, tag, eventID)
}

// IsCNAMENode returns true if the FQDN has a CNAME edge to another FQDN in the graph.
func (g *Graph) IsCNAMENode(fqdn string) bool {
	return g.checkForOutEdge(fqdn, "cname_record")
}

func (g *Graph) insertAlias(fqdn, target, pred, source, tag, eventID string) error {
	fqdnNode, err := g.InsertFQDN(fqdn, source, tag, eventID)
	if err != nil {
		return err
	}

	targetNode, err := g.InsertFQDN(target, source, tag, eventID)
	if err != nil {
		return err
	}

	// Create the edge between the alias and the target subdomain name
	aliasEdge := &db.Edge{
		Predicate: pred,
		From:      fqdnNode,
		To:        targetNode,
	}

	return g.InsertEdge(aliasEdge)
}

// InsertPTR adds the FQDNs and PTR record between them to the graph.
func (g *Graph) InsertPTR(fqdn, target, source, tag, eventID string) error {
	return g.insertAlias(fqdn, target, "ptr_record", source, tag, eventID)
}

// IsPTRNode returns true if the FQDN has a PTR edge to another FQDN in the graph.
func (g *Graph) IsPTRNode(fqdn string) bool {
	return g.checkForOutEdge(fqdn, "ptr_record")
}

// InsertSRV adds the FQDNs and SRV record between them to the graph.
func (g *Graph) InsertSRV(fqdn, service, target, source, tag, eventID string) error {
	// Create the edge between the service and the subdomain
	if err := g.insertAlias(service, fqdn, "service", source, tag, eventID); err != nil {
		return err
	}

	// Create the edge between the service and the target
	return g.insertAlias(service, target, "srv_record", source, tag, eventID)
}

// InsertNS adds the FQDNs and NS record between them to the graph.
func (g *Graph) InsertNS(fqdn, target, source, tag, eventID string) error {
	return g.insertAlias(fqdn, target, "ns_record", source, tag, eventID)
}

// IsNSNode returns true if the FQDN has a NS edge pointing to it in the graph.
func (g *Graph) IsNSNode(fqdn string) bool {
	return g.checkForInEdge(fqdn, "ns_record")
}

// InsertMX adds the FQDNs and MX record between them to the graph.
func (g *Graph) InsertMX(fqdn, target, source, tag, eventID string) error {
	return g.insertAlias(fqdn, target, "mx_record", source, tag, eventID)
}

// IsMXNode returns true if the FQDN has a MX edge pointing to it in the graph.
func (g *Graph) IsMXNode(fqdn string) bool {
	return g.checkForInEdge(fqdn, "mx_record")
}

// IsRootDomainNode returns true if the FQDN has a 'root' edge pointing to it in the graph.
func (g *Graph) IsRootDomainNode(fqdn string) bool {
	return g.checkForInEdge(fqdn, "root")
}

// IsTLDNode returns true if the FQDN has a 'tld' edge pointing to it in the graph.
func (g *Graph) IsTLDNode(fqdn string) bool {
	return g.checkForInEdge(fqdn, "tld")
}

func (g *Graph) checkForInEdge(id, predicate string) bool {
	if node, err := g.db.ReadNode(id); err == nil {
		count, err := g.db.CountInEdges(node, predicate)

		if err == nil && count > 0 {
			return true
		}
	}

	return false
}

func (g *Graph) checkForOutEdge(id, predicate string) bool {
	if node, err := g.db.ReadNode(id); err == nil {
		count, err := g.db.CountOutEdges(node, predicate)

		if err == nil && count > 0 {
			return true
		}
	}

	return false
}
