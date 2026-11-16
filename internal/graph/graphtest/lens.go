// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package graphtest

import (
	"context"
	"strings"

	"github.com/owasp-amass/amass/v5/internal/graph"
)

// oamSemantics is every entry of semantics/oam_relations.yaml, so the
// lenses are tested against the reviewed table rather than a hand-picked
// subset. Regenerate it when the table changes.
var oamSemantics = map[string]graph.RelationMeaning{
	"Account|id|SimpleRelation|Identifier":                             {Attribution: "attribute", Purpose: "identity", Vendor: true},
	"Account|user|SimpleRelation|Organization":                         {Attribution: "controller", Purpose: "identity", Vendor: true},
	"Account|user|SimpleRelation|Person":                               {Attribution: "controller", Purpose: "identity", Vendor: true},
	"AutnumRecord|abuse_contact|SimpleRelation|ContactRecord":          {Attribution: "third_party", Purpose: "registration", Vendor: false},
	"AutnumRecord|admin_contact|SimpleRelation|ContactRecord":          {Attribution: "controller", Purpose: "registration", Vendor: true},
	"AutnumRecord|rdap_url|SimpleRelation|URL":                         {Attribution: "third_party", Purpose: "registration", Vendor: false},
	"AutnumRecord|registrant|SimpleRelation|ContactRecord":             {Attribution: "controller", Purpose: "registration", Vendor: true},
	"AutnumRecord|technical_contact|SimpleRelation|ContactRecord":      {Attribution: "third_party", Purpose: "registration", Vendor: true},
	"AutnumRecord|whois_server|SimpleRelation|FQDN":                    {Attribution: "third_party", Purpose: "registration", Vendor: false},
	"AutonomousSystem|announces|SimpleRelation|Netblock":               {Attribution: "infrastructure", Purpose: "network", Vendor: true},
	"AutonomousSystem|registration|SimpleRelation|AutnumRecord":        {Attribution: "same_subject", Purpose: "registration", Vendor: true},
	"ContactRecord|fqdn|SimpleRelation|FQDN":                           {Attribution: "attribute", Purpose: "contact", Vendor: true},
	"ContactRecord|id|SimpleRelation|Identifier":                       {Attribution: "attribute", Purpose: "contact", Vendor: true},
	"ContactRecord|location|SimpleRelation|Location":                   {Attribution: "attribute", Purpose: "contact", Vendor: true},
	"ContactRecord|organization|SimpleRelation|Organization":           {Attribution: "same_subject", Purpose: "contact", Vendor: true},
	"ContactRecord|person|SimpleRelation|Person":                       {Attribution: "same_subject", Purpose: "contact", Vendor: true},
	"ContactRecord|phone|SimpleRelation|Phone":                         {Attribution: "attribute", Purpose: "contact", Vendor: true},
	"ContactRecord|url|SimpleRelation|URL":                             {Attribution: "attribute", Purpose: "contact", Vendor: true},
	"DomainRecord|admin_contact|SimpleRelation|ContactRecord":          {Attribution: "controller", Purpose: "registration", Vendor: true},
	"DomainRecord|billing_contact|SimpleRelation|ContactRecord":        {Attribution: "controller", Purpose: "registration", Vendor: true},
	"DomainRecord|name_server|SimpleRelation|FQDN":                     {Attribution: "third_party", Purpose: "dns", Vendor: true},
	"DomainRecord|registrant_contact|SimpleRelation|ContactRecord":     {Attribution: "controller", Purpose: "registration", Vendor: true},
	"DomainRecord|registrar_contact|SimpleRelation|ContactRecord":      {Attribution: "third_party", Purpose: "registration", Vendor: true},
	"DomainRecord|technical_contact|SimpleRelation|ContactRecord":      {Attribution: "third_party", Purpose: "registration", Vendor: true},
	"DomainRecord|whois_server|SimpleRelation|FQDN":                    {Attribution: "third_party", Purpose: "registration", Vendor: false},
	"FQDN|dns_record|BasicDNSRelation|FQDN":                            {Attribution: "infrastructure", Purpose: "dns", Vendor: true},
	"FQDN|dns_record|BasicDNSRelation|IPAddress":                       {Attribution: "infrastructure", Purpose: "dns", Vendor: true},
	"FQDN|dns_record|PrefDNSRelation|FQDN":                             {Attribution: "infrastructure", Purpose: "dns", Vendor: true},
	"FQDN|dns_record|SRVDNSRelation|FQDN":                              {Attribution: "infrastructure", Purpose: "dns", Vendor: true},
	"FQDN|node|SimpleRelation|FQDN":                                    {Attribution: "same_subject", Purpose: "hierarchy", Vendor: true},
	"FQDN|port|PortRelation|Service":                                   {Attribution: "infrastructure", Purpose: "network", Vendor: true},
	"FQDN|registration|SimpleRelation|DomainRecord":                    {Attribution: "same_subject", Purpose: "registration", Vendor: true},
	"FQDN|verified_for|SimpleRelation|Organization":                    {Attribution: "third_party", Purpose: "dns", Vendor: true},
	"FQDN|verified_for|SimpleRelation|Service":                         {Attribution: "third_party", Purpose: "dns", Vendor: true},
	"File|contains|SimpleRelation|ContactRecord":                       {Attribution: "attribute", Purpose: "web", Vendor: true},
	"File|contains|SimpleRelation|URL":                                 {Attribution: "attribute", Purpose: "web", Vendor: true},
	"File|url|SimpleRelation|URL":                                      {Attribution: "attribute", Purpose: "web", Vendor: true},
	"FundsTransfer|id|SimpleRelation|Identifier":                       {Attribution: "attribute", Purpose: "financial", Vendor: true},
	"FundsTransfer|recipient|SimpleRelation|Account":                   {Attribution: "attribute", Purpose: "financial", Vendor: true},
	"FundsTransfer|sender|SimpleRelation|Account":                      {Attribution: "attribute", Purpose: "financial", Vendor: true},
	"FundsTransfer|third_party|SimpleRelation|Organization":            {Attribution: "third_party", Purpose: "financial", Vendor: true},
	"IPAddress|port|PortRelation|Service":                              {Attribution: "infrastructure", Purpose: "network", Vendor: true},
	"IPAddress|ptr_record|SimpleRelation|FQDN":                         {Attribution: "infrastructure", Purpose: "dns", Vendor: true},
	"IPNetRecord|abuse_contact|SimpleRelation|ContactRecord":           {Attribution: "third_party", Purpose: "registration", Vendor: false},
	"IPNetRecord|admin_contact|SimpleRelation|ContactRecord":           {Attribution: "controller", Purpose: "registration", Vendor: true},
	"IPNetRecord|rdap_url|SimpleRelation|URL":                          {Attribution: "third_party", Purpose: "registration", Vendor: false},
	"IPNetRecord|registrant|SimpleRelation|ContactRecord":              {Attribution: "controller", Purpose: "registration", Vendor: true},
	"IPNetRecord|technical_contact|SimpleRelation|ContactRecord":       {Attribution: "third_party", Purpose: "registration", Vendor: true},
	"IPNetRecord|whois_server|SimpleRelation|FQDN":                     {Attribution: "third_party", Purpose: "registration", Vendor: false},
	"Identifier|issuing_agent|SimpleRelation|ContactRecord":            {Attribution: "third_party", Purpose: "identity", Vendor: true},
	"Identifier|issuing_authority|SimpleRelation|ContactRecord":        {Attribution: "third_party", Purpose: "identity", Vendor: true},
	"Identifier|registration_agency|SimpleRelation|ContactRecord":      {Attribution: "third_party", Purpose: "identity", Vendor: true},
	"Location|id|SimpleRelation|Identifier":                            {Attribution: "attribute", Purpose: "identity", Vendor: true},
	"Netblock|contains|SimpleRelation|IPAddress":                       {Attribution: "same_subject", Purpose: "network", Vendor: true},
	"Netblock|registration|SimpleRelation|IPNetRecord":                 {Attribution: "same_subject", Purpose: "registration", Vendor: true},
	"Organization|account|SimpleRelation|Account":                      {Attribution: "controls", Purpose: "identity", Vendor: true},
	"Organization|funding_source|SimpleRelation|Organization":          {Attribution: "attribute", Purpose: "financial", Vendor: true},
	"Organization|funding_source|SimpleRelation|Person":                {Attribution: "attribute", Purpose: "financial", Vendor: true},
	"Organization|hq_address|SimpleRelation|Location":                  {Attribution: "attribute", Purpose: "corporate", Vendor: true},
	"Organization|id|SimpleRelation|Identifier":                        {Attribution: "attribute", Purpose: "identity", Vendor: true},
	"Organization|legal_address|SimpleRelation|Location":               {Attribution: "attribute", Purpose: "corporate", Vendor: true},
	"Organization|location|SimpleRelation|Location":                    {Attribution: "attribute", Purpose: "corporate", Vendor: true},
	"Organization|member|SimpleRelation|Person":                        {Attribution: "attribute", Purpose: "corporate", Vendor: true},
	"Organization|org_unit|SimpleRelation|Organization":                {Attribution: "controls", Purpose: "corporate", Vendor: true},
	"Organization|social_media_profile|SimpleRelation|URL":             {Attribution: "controls", Purpose: "web", Vendor: true},
	"Organization|subsidiary|SimpleRelation|Organization":              {Attribution: "controls", Purpose: "corporate", Vendor: true},
	"Organization|website|SimpleRelation|URL":                          {Attribution: "controls", Purpose: "web", Vendor: true},
	"Person|account|SimpleRelation|Account":                            {Attribution: "controls", Purpose: "identity", Vendor: true},
	"Person|address|SimpleRelation|Location":                           {Attribution: "attribute", Purpose: "identity", Vendor: true},
	"Person|id|SimpleRelation|Identifier":                              {Attribution: "attribute", Purpose: "identity", Vendor: true},
	"Person|phone|SimpleRelation|Phone":                                {Attribution: "attribute", Purpose: "identity", Vendor: true},
	"Phone|account|SimpleRelation|Account":                             {Attribution: "attribute", Purpose: "identity", Vendor: true},
	"Phone|contact|SimpleRelation|ContactRecord":                       {Attribution: "attribute", Purpose: "contact", Vendor: true},
	"ProductRelease|id|SimpleRelation|Identifier":                      {Attribution: "attribute", Purpose: "product", Vendor: true},
	"ProductRelease|website|SimpleRelation|URL":                        {Attribution: "controls", Purpose: "web", Vendor: true},
	"Product|id|SimpleRelation|Identifier":                             {Attribution: "attribute", Purpose: "product", Vendor: true},
	"Product|manufacturer|SimpleRelation|Organization":                 {Attribution: "controller", Purpose: "product", Vendor: true},
	"Product|release|SimpleRelation|ProductRelease":                    {Attribution: "controls", Purpose: "product", Vendor: true},
	"Product|website|SimpleRelation|URL":                               {Attribution: "controls", Purpose: "web", Vendor: true},
	"Service|certificate|SimpleRelation|TLSCertificate":                {Attribution: "same_subject", Purpose: "certificate", Vendor: true},
	"Service|product_used|SimpleRelation|Product":                      {Attribution: "third_party", Purpose: "product", Vendor: true},
	"Service|product_used|SimpleRelation|ProductRelease":               {Attribution: "third_party", Purpose: "product", Vendor: true},
	"Service|provider|SimpleRelation|Organization":                     {Attribution: "third_party", Purpose: "network", Vendor: true},
	"Service|terms_of_service|SimpleRelation|File":                     {Attribution: "attribute", Purpose: "web", Vendor: true},
	"Service|terms_of_service|SimpleRelation|URL":                      {Attribution: "attribute", Purpose: "web", Vendor: true},
	"Service|security_contact|SimpleRelation|ContactRecord":            {Attribution: "third_party", Purpose: "contact", Vendor: false},
	"Service|security_policy|SimpleRelation|URL":                       {Attribution: "attribute", Purpose: "web", Vendor: true},
	"Service|security_canonical|SimpleRelation|URL":                    {Attribution: "attribute", Purpose: "web", Vendor: true},
	"Service|security_encryption|SimpleRelation|URL":                   {Attribution: "attribute", Purpose: "web", Vendor: true},
	"Service|security_acknowledgments|SimpleRelation|URL":              {Attribution: "attribute", Purpose: "web", Vendor: true},
	"Service|security_hiring|SimpleRelation|URL":                       {Attribution: "attribute", Purpose: "web", Vendor: true},
	"TLSCertificate|common_name|SimpleRelation|FQDN":                   {Attribution: "same_subject", Purpose: "certificate", Vendor: true},
	"TLSCertificate|issuer_contact|SimpleRelation|ContactRecord":       {Attribution: "third_party", Purpose: "certificate", Vendor: true},
	"TLSCertificate|issuing_certificate_url|SimpleRelation|URL":        {Attribution: "third_party", Purpose: "certificate", Vendor: false},
	"TLSCertificate|issuing_certificate|SimpleRelation|TLSCertificate": {Attribution: "third_party", Purpose: "certificate", Vendor: false},
	"TLSCertificate|ocsp_server|SimpleRelation|URL":                    {Attribution: "third_party", Purpose: "certificate", Vendor: false},
	"TLSCertificate|san_dns_name|SimpleRelation|FQDN":                  {Attribution: "shared", Purpose: "certificate", Vendor: true},
	"TLSCertificate|san_email_address|SimpleRelation|Identifier":       {Attribution: "shared", Purpose: "certificate", Vendor: true},
	"TLSCertificate|san_ip_address|SimpleRelation|IPAddress":           {Attribution: "shared", Purpose: "certificate", Vendor: true},
	"TLSCertificate|san_url|SimpleRelation|URL":                        {Attribution: "shared", Purpose: "certificate", Vendor: true},
	"TLSCertificate|subject_contact|SimpleRelation|ContactRecord":      {Attribution: "controller", Purpose: "certificate", Vendor: true},
	"URL|domain|SimpleRelation|FQDN":                                   {Attribution: "same_subject", Purpose: "web", Vendor: true},
	"URL|file|SimpleRelation|File":                                     {Attribution: "attribute", Purpose: "web", Vendor: true},
	"URL|ip_address|SimpleRelation|IPAddress":                          {Attribution: "infrastructure", Purpose: "network", Vendor: true},
	"URL|port|PortRelation|Service":                                    {Attribution: "infrastructure", Purpose: "network", Vendor: true},
}

// VendorCatalog is the full OAM semantics table with selectors.
type VendorCatalog struct{ PlanCatalog }

func (VendorCatalog) Attribution(src, label, rt, dst string) (string, bool) {
	m, ok := oamSemantics[src+"|"+label+"|"+rt+"|"+dst]
	return m.Attribution, ok
}

func (VendorCatalog) Meaning(src, label, rt, dst string) (graph.RelationMeaning, bool) {
	m, ok := oamSemantics[src+"|"+label+"|"+rt+"|"+dst]
	return m, ok
}

// Relations returns every transition in the attribution table.
func (VendorCatalog) Relations() []graph.RelationshipSchema {
	out := make([]graph.RelationshipSchema, 0, len(oamSemantics))
	for k := range oamSemantics {
		p := strings.Split(k, "|")
		out = append(out, graph.RelationshipSchema{SourceType: p[0], Label: p[1], RelationType: p[2], DestinationType: p[3]})
	}

	return out
}

// VendorGraph resolves Colgate University and colgate.edu.
type VendorGraph struct{ PlannedGraph }

func (g VendorGraph) ResolveOrganizations(_ context.Context, q graph.OrganizationQuery, _ int) (graph.OrganizationResolution, error) {
	result := graph.OrganizationResolution{Query: q, Status: "not_found", Candidates: []graph.OrganizationCandidate{}}
	if strings.EqualFold(q.Name, "Colgate University") {
		result.Status = "matched"
		result.Candidates = []graph.OrganizationCandidate{{Asset: g.Assets["colgate"]}}
	}

	return result, nil
}

// VendorFixture models a university: its registrant contact ties the
// organization to colgate.edu and its own netblock. Outside parties are a
// registrar, a DNS host, a mail provider (MX), a CDN network and a
// certificate authority. A person shared with another college's contact
// must not pull that college into the footprint.
func VendorFixture() VendorGraph {
	g := FakeGraph{Assets: map[string]graph.Asset{}}
	add := func(id, typ, key string, content map[string]any) {
		g.Assets[id] = graph.Asset{ID: id, Type: typ, Key: key, Content: content}
	}
	link := func(from, label, to, rt string) {
		g.Links = append(g.Links, graph.Relation{ID: from + "-" + label + "-" + to, FromID: from, ToID: to, Label: label,
			Type: rt})
	}
	named := func(id, typ, name string) { add(id, typ, name, map[string]any{"name": name}) }

	named("colgate", "Organization", "Colgate University")
	named("educause", "Organization", "EDUCAUSE")
	named("digicert", "Organization", "DigiCert Inc")
	named("hamilton", "Organization", "Hamilton College")
	add("cr-colgate", "ContactRecord", "https://rdap.example/colgate", nil)
	add("cr-educause", "ContactRecord", "https://whois.educause.edu/registrar", nil)
	add("cr-digicert", "ContactRecord", "https://crt.example/issuer", nil)
	add("cr-hamilton", "ContactRecord", "https://rdap.example/hamilton", nil)
	add("person", "Person", "Shared Person", map[string]any{"full_name": "Shared Person"})
	add("dr", "DomainRecord", "colgate.edu", map[string]any{"domain": "colgate.edu"})
	add("dr-hamilton", "DomainRecord", "hamilton.edu", map[string]any{"domain": "hamilton.edu"})
	for _, n := range []string{"colgate.edu", "www.colgate.edu", "portal.colgate.edu", "ns1.colgate.edu",
		"pdns1.ultradns.net", "mx1.pphosted.com", "hamilton.edu", "www.hamilton.edu", "x.cloudflare.com"} {
		named(n, "FQDN", n)
	}

	add("nb-own", "Netblock", "149.43.0.0/16", map[string]any{"cidr": "149.43.0.0/16"})
	add("ipnet-own", "IPNetRecord", "149.43.0.0/16", map[string]any{"name": "COLGATE-UNIV"})
	add("ip-own", "IPAddress", "149.43.1.1", map[string]any{"address": "149.43.1.1"})
	add("nb-cdn", "Netblock", "151.101.0.0/16", map[string]any{"cidr": "151.101.0.0/16"})
	add("as-cdn", "AutonomousSystem", "54113", map[string]any{"number": 54113})
	add("autnum-cdn", "AutnumRecord", "AS54113", map[string]any{"handle": "AS54113", "name": "FASTLY"})
	add("ip-cdn", "IPAddress", "151.101.1.1", map[string]any{"address": "151.101.1.1"})
	add("cert", "TLSCertificate", "1234", map[string]any{"serial_number": "1234"})
	add("as-own", "AutonomousSystem", "1289", map[string]any{"number": 1289})
	add("autnum-own", "AutnumRecord", "AS1289", map[string]any{"handle": "AS1289", "name": "COLGATE-UNIVERSITY"})

	link("cr-colgate", "organization", "colgate", "SimpleRelation")
	link("cr-colgate", "person", "person", "SimpleRelation")
	link("dr", "registrant_contact", "cr-colgate", "SimpleRelation")
	link("dr", "registrar_contact", "cr-educause", "SimpleRelation")
	link("cr-educause", "organization", "educause", "SimpleRelation")
	link("dr", "name_server", "ns1.colgate.edu", "SimpleRelation")
	link("dr", "name_server", "pdns1.ultradns.net", "SimpleRelation")
	link("colgate.edu", "registration", "dr", "SimpleRelation")
	link("colgate.edu", "node", "www.colgate.edu", "SimpleRelation")
	link("colgate.edu", "node", "portal.colgate.edu", "SimpleRelation")
	link("colgate.edu", "dns_record", "mx1.pphosted.com", "PrefDNSRelation")
	link("www.colgate.edu", "dns_record", "ip-cdn", "BasicDNSRelation")
	link("portal.colgate.edu", "dns_record", "ip-own", "BasicDNSRelation")
	link("nb-own", "registration", "ipnet-own", "SimpleRelation")
	link("ipnet-own", "registrant", "cr-colgate", "SimpleRelation")
	link("nb-own", "contains", "ip-own", "SimpleRelation")
	link("nb-cdn", "contains", "ip-cdn", "SimpleRelation")
	link("as-own", "announces", "nb-own", "SimpleRelation")
	link("as-own", "registration", "autnum-own", "SimpleRelation")
	link("autnum-own", "registrant", "cr-colgate", "SimpleRelation")
	link("as-cdn", "announces", "nb-cdn", "SimpleRelation")
	link("as-cdn", "registration", "autnum-cdn", "SimpleRelation")
	link("cert", "san_dns_name", "www.colgate.edu", "SimpleRelation")
	link("cert", "issuer_contact", "cr-digicert", "SimpleRelation")
	link("cr-digicert", "organization", "digicert", "SimpleRelation")

	// Hamilton College shares a person with Colgate's contact and uses its
	// own CDN; none of it belongs to Colgate.
	link("cr-hamilton", "organization", "hamilton", "SimpleRelation")
	link("cr-hamilton", "person", "person", "SimpleRelation")
	link("dr-hamilton", "registrant_contact", "cr-hamilton", "SimpleRelation")
	link("hamilton.edu", "registration", "dr-hamilton", "SimpleRelation")
	link("hamilton.edu", "node", "www.hamilton.edu", "SimpleRelation")
	link("www.hamilton.edu", "dns_record", "x.cloudflare.com", "BasicDNSRelation")

	return VendorGraph{PlannedGraph{FakeGraph: g}}
}
