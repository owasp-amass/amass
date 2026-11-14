// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package aitest

import (
	"fmt"
	"strings"

	"github.com/owasp-amass/amass/v5/internal/ai/graph"
)

// FamilyGraph builds the shape the 11 Nov Johns Hopkins data had: the
// university on certificates and holding 128.220.0.0/16, its domain
// registered by the same institution under another name, JHMI holding a
// network that mostly serves jhu.edu, an IT department as a registration
// contact, a cloud provider hosting a few jhu.edu names among many others,
// and an unrelated organization with a similar name.
func FamilyGraph() FakeGraph {
	g := NewOrgGraph()
	a := func(id, typ string, content map[string]any) {
		g.Graph.Assets[id] = graph.Asset{ID: id, Type: typ, Key: id, Content: content}
	}
	fqdn := func(name string) { a(name, "FQDN", map[string]any{"name": name}) }
	resolve := func(name, ip, block string) {
		fqdn(name)
		if _, ok := g.Graph.Assets[ip]; !ok {
			a(ip, "IPAddress", map[string]any{"address": ip})
		}
		g.Graph.Links = append(g.Graph.Links,
			graph.Relation{ID: "e" + g.id(), FromID: name, ToID: ip, Label: "dns_record",
				Content: map[string]any{"header": map[string]any{"rr_type": 1}}},
			graph.Relation{ID: "e" + g.id(), FromID: block, ToID: ip, Label: "contains"})
	}
	// network creates a netblock held through an ARIN record by org.
	network := func(block, cidr, org string) {
		a(block, "Netblock", map[string]any{"cidr": cidr})
		rec := "rec-" + block
		a(rec, "IPNetRecord", map[string]any{"cidr": cidr})
		g.Link(block, rec, "registration")
		cr := "cr-" + block
		a(cr, "ContactRecord", nil)
		g.Link(rec, cr, "registrant")
		g.Link(cr, org, "organization")
	}

	g.Org("jhu", "the johns hopkins university", "the johns hopkins university", "US-MD", "D00089169")
	g.Org("jhu-arin", "johns hopkins university", "", "", "")
	g.Org("jhmi", "the johns hopkins medical institutions", "", "", "")
	g.Org("its", "hopkins information technology services", "", "", "")
	g.Org("cloud", "cloudhost", "cloudhost, inc.", "US-WA", "1")
	g.Org("other", "hopkins & sons plumbing", "", "", "")

	// Certificates name the university for jhu.edu names.
	for i := 0; i < 3; i++ {
		cert := fmt.Sprintf("cert%d", i)
		a(cert, "TLSCertificate", map[string]any{"subject_common_name": fmt.Sprintf("www%d.jhu.edu", i)})
		a("cr-"+cert, "ContactRecord", nil)
		g.Link(cert, "cr-"+cert, "subject_contact")
		g.Link("cr-"+cert, "jhu", "organization")
		name := fmt.Sprintf("www%d.jhu.edu", i)
		fqdn(name)
		g.Link("jhu.edu", name, "node")
		g.Link(cert, name, "common_name")
	}

	// The IT department is the domain's technical contact, with a jhu.edu
	// address.
	a("dr-jhu", "DomainRecord", map[string]any{"domain": "jhu.edu"})
	g.Link("jhu.edu", "dr-jhu", "registration")
	a("cr-its", "ContactRecord", nil)
	g.Link("dr-jhu", "cr-its", "technical_contact")
	g.Link("cr-its", "its", "organization")
	g.Graph.Assets["email:hostmaster@jhu.edu"] = graph.Asset{ID: "email:hostmaster@jhu.edu", Type: "Identifier",
		Key: "email:hostmaster@jhu.edu", Content: map[string]any{"id": "hostmaster@jhu.edu", "id_type": "email"}}
	g.Link("cr-its", "email:hostmaster@jhu.edu", "id")

	// An ISP whose only stored addresses are the few jhu.edu names using it,
	// so its stored names look dedicated to jhu.edu.
	g.Org("isp", "comcast cable communications", "", "", "")
	network("nb-isp", "50.128.0.0/9", "isp")
	for i := 0; i < 6; i++ {
		name := fmt.Sprintf("home%d.jhu.edu", i)
		resolve(name, fmt.Sprintf("50.128.0.%d", i), "nb-isp")
		g.Link("jhu.edu", name, "node")
	}

	// A person named as the domain's registrant, sharing only the street
	// address; and a placeholder certificate subject.
	g.Org("person", "eric torgersen", "", "", "")
	a("dr-reg", "DomainRecord", map[string]any{"domain": "jhu.edu"})
	g.Link("jhu.edu", "dr-reg", "registration")
	a("cr-person", "ContactRecord", nil)
	g.Link("dr-reg", "cr-person", "registrant_contact")
	g.Link("cr-person", "person", "organization")
	a("loc-1", "Location", map[string]any{"address": "3400 north charles street baltimore md 21218"})
	a("loc-2", "Location", map[string]any{"address": "3400 n. charles st., garland hall, baltimore, md 21218-2683"})
	g.Link("cr-person", "loc-1", "location")
	g.Org("unspecified", "unspecified", "", "", "")
	a("cert-u", "TLSCertificate", map[string]any{"subject_common_name": "x.jhu.edu"})
	fqdn("x.jhu.edu")
	g.Link("jhu.edu", "x.jhu.edu", "node")
	g.Link("cert-u", "x.jhu.edu", "common_name")
	a("cr-cert-u", "ContactRecord", nil)
	g.Link("cert-u", "cr-cert-u", "subject_contact")
	g.Link("cr-cert-u", "unspecified", "organization")

	// A network the university holds, whose stored names are mostly other
	// domains' (as when an active probe stores addresses without names):
	// held by a directly tied organization, it is dedicated anyway.
	network("nb-campus", "10.20.0.0/16", "jhu")
	for i := 0; i < 5; i++ {
		name := fmt.Sprintf("lab%d.jhu.edu", i)
		resolve(name, fmt.Sprintf("10.20.0.%d", i), "nb-campus")
		g.Link("jhu.edu", name, "node")
	}
	for i := 0; i < 30; i++ {
		resolve(fmt.Sprintf("guest%d.example%d.org", i, i), fmt.Sprintf("10.20.1.%d", i), "nb-campus")
	}

	network("nb-jhu", "128.220.0.0/16", "jhu-arin")
	g.Link("cr-nb-jhu", "loc-2", "location")
	network("nb-jhmi", "162.129.0.0/16", "jhmi")
	network("nb-cloud", "52.0.0.0/8", "cloud")

	fqdn("jhu.edu")
	for i := 0; i < 22; i++ {
		name := fmt.Sprintf("h%d.jhu.edu", i)
		switch {
		case i < 10:
			resolve(name, fmt.Sprintf("128.220.0.%d", i), "nb-jhu")
		case i < 16:
			resolve(name, fmt.Sprintf("162.129.0.%d", i), "nb-jhmi")
		default:
			resolve(name, fmt.Sprintf("52.0.0.%d", i), "nb-cloud")
		}
		g.Link("jhu.edu", name, "node")
	}
	// JHMI's network also serves jhmi.edu and jhsph.edu names; the cloud
	// network serves many unrelated customers.
	for i := 0; i < 4; i++ {
		resolve(fmt.Sprintf("m%d.jhmi.edu", i), fmt.Sprintf("162.129.1.%d", i), "nb-jhmi")
		resolve(fmt.Sprintf("p%d.jhsph.edu", i), fmt.Sprintf("162.129.2.%d", i), "nb-jhmi")
	}
	for i := 0; i < 40; i++ {
		resolve(fmt.Sprintf("site%d.customer%d.com", i, i), fmt.Sprintf("52.1.0.%d", i), "nb-cloud")
	}

	return g.Graph
}

// brandGraph is a company with several brand domains whose networks serve
// all of them, as Northrop Grumman's and Automattic's do: no network has
// most of its names from any one domain.
type brandGraph struct {
	*orgGraph
}

func NewBrandGraph() brandGraph {
	return brandGraph{orgGraph: NewOrgGraph()}
}

func (g brandGraph) asset(id, typ string, content map[string]any) {
	g.Graph.Assets[id] = graph.Asset{ID: id, Type: typ, Key: id, Content: content}
}

func (g brandGraph) FQDN(name string) {
	if _, ok := g.Graph.Assets[name]; !ok {
		g.asset(name, "FQDN", map[string]any{"name": name})
	}
}

// Network creates a netblock held through an ARIN record by org.
func (g brandGraph) Network(block, cidr, org string) {
	g.asset(block, "Netblock", map[string]any{"cidr": cidr})
	rec := "rec-" + block
	g.asset(rec, "IPNetRecord", map[string]any{"cidr": cidr})
	g.Link(block, rec, "registration")
	cr := "cr-" + block
	g.asset(cr, "ContactRecord", nil)
	g.Link(rec, cr, "registrant")
	g.Link(cr, org, "organization")
}

// Serve stores n names of domain resolving into block, under the domain.
func (g brandGraph) Serve(domain, block, prefix string, n int, octet int) {
	g.FQDN(domain)
	for i := 0; i < n; i++ {
		name := fmt.Sprintf("%s%d.%s", prefix, i, domain)
		ip := fmt.Sprintf("10.%d.%d.%d", octet, i/250, i%250)
		g.FQDN(name)
		g.asset(ip, "IPAddress", map[string]any{"address": ip})
		g.Graph.Links = append(g.Graph.Links,
			graph.Relation{ID: "e" + g.id(), FromID: name, ToID: ip, Label: "dns_record",
				Content: map[string]any{"header": map[string]any{"rr_type": 1}}},
			graph.Relation{ID: "e" + g.id(), FromID: block, ToID: ip, Label: "contains"})
		g.Link(domain, name, "node")
	}
}

// Cert stores a certificate naming org for cn, linked to cn as the engine
// links it, with cn stored under its registered domain when that is stored.
func (g brandGraph) Cert(id, cn, org string) {
	g.asset(id, "TLSCertificate", map[string]any{"subject_common_name": cn})
	g.asset("cr-"+id, "ContactRecord", nil)
	g.Link(id, "cr-"+id, "subject_contact")
	g.Link("cr-"+id, org, "organization")

	name := strings.TrimPrefix(cn, "*.")
	if _, ok := g.Graph.Assets[name]; !ok {
		g.FQDN(name)
		if root := graph.RegisteredDomain(name); root != name {
			if _, ok := g.Graph.Assets[root]; ok {
				g.Link(root, name, "node")
			}
		}
	}
	g.Link(id, name, "common_name")
}

// Registers stores a registration record of each domain naming org as its
// registrant, linked from the domain.
func (g brandGraph) Registers(org string, domains ...string) {
	for _, d := range domains {
		g.FQDN(d)
		g.asset("dr-"+d, "DomainRecord", map[string]any{"domain": d})
		g.Link(d, "dr-"+d, "registration")
		g.asset("cr-dr-"+d, "ContactRecord", nil)
		g.Link("dr-"+d, "cr-dr-"+d, "registrant_contact")
		g.Link("cr-dr-"+d, org, "organization")
	}
}
