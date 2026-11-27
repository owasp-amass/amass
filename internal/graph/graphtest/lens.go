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
	"Account|contact|SimpleRelation|ContactRecord":                     {Attribution: "attribute", Purpose: "contact", Vendor: true},
	"FQDN|soa_rname|SimpleRelation|Identifier":                         {Attribution: "attribute", Purpose: "dns", Vendor: true},
	"FQDN|spf_authorizes|SimpleRelation|Netblock":                      {Attribution: "shared", Purpose: "dns", Vendor: true},
	"FQDN|spf_authorizes|SimpleRelation|IPAddress":                     {Attribution: "shared", Purpose: "dns", Vendor: true},
	"Netblock|irr_maintainer|SimpleRelation|Identifier":                {Attribution: "attribute", Purpose: "network", Vendor: true},
	"Netblock|irr_origin|SimpleRelation|AutonomousSystem":              {Attribution: "infrastructure", Purpose: "network", Vendor: true},
	"Netblock|rpki_origin|SimpleRelation|AutonomousSystem":             {Attribution: "infrastructure", Purpose: "network", Vendor: true},
	"Account|in_scope|SimpleRelation|FQDN":                             {Attribution: "shared", Purpose: "corporate", Vendor: true},
	"Account|in_scope|SimpleRelation|Netblock":                         {Attribution: "shared", Purpose: "corporate", Vendor: true},
	"Account|in_scope|SimpleRelation|URL":                              {Attribution: "shared", Purpose: "corporate", Vendor: true},
	"Account|program_page|SimpleRelation|URL":                          {Attribution: "attribute", Purpose: "corporate", Vendor: true},
	"Account|package|SimpleRelation|Product":                           {Attribution: "controls", Purpose: "product", Vendor: true},
	"Account|namespace_domain|SimpleRelation|FQDN":                     {Attribution: "attribute", Purpose: "product", Vendor: true},
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
	"ContactRecord|street_address|SimpleRelation|StreetAddress":        {Attribution: "attribute", Purpose: "contact", Vendor: true},
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
	"FQDN|bucket|SimpleRelation|StorageBucket":                         {Attribution: "infrastructure", Purpose: "network", Vendor: true},
	"FQDN|registration|SimpleRelation|DomainRecord":                    {Attribution: "same_subject", Purpose: "registration", Vendor: true},
	"FQDN|verified_for|SimpleRelation|Organization":                    {Attribution: "third_party", Purpose: "dns", Vendor: true},
	"FQDN|verified_for|SimpleRelation|Service":                         {Attribution: "third_party", Purpose: "dns", Vendor: true},
	"File|author|SimpleRelation|Organization":                          {Attribution: "attribute", Purpose: "web", Vendor: true},
	"File|author|SimpleRelation|Person":                                {Attribution: "attribute", Purpose: "web", Vendor: true},
	"File|contains|SimpleRelation|Account":                             {Attribution: "attribute", Purpose: "identity", Vendor: true},
	"File|contains|SimpleRelation|ContactRecord":                       {Attribution: "attribute", Purpose: "web", Vendor: true},
	"File|contains|SimpleRelation|FQDN":                                {Attribution: "attribute", Purpose: "web", Vendor: true},
	"File|contains|SimpleRelation|File":                                {Attribution: "attribute", Purpose: "web", Vendor: true},
	"File|contains|SimpleRelation|GeoLocation":                         {Attribution: "attribute", Purpose: "web", Vendor: true},
	"File|contains|SimpleRelation|Identifier":                          {Attribution: "attribute", Purpose: "web", Vendor: true},
	"File|contains|SimpleRelation|IPAddress":                           {Attribution: "attribute", Purpose: "web", Vendor: true},
	"File|contains|SimpleRelation|StreetAddress":                       {Attribution: "attribute", Purpose: "web", Vendor: true},
	"File|contains|SimpleRelation|Netblock":                            {Attribution: "attribute", Purpose: "web", Vendor: true},
	"File|contains|SimpleRelation|Organization":                        {Attribution: "attribute", Purpose: "web", Vendor: true},
	"File|contains|SimpleRelation|Person":                              {Attribution: "attribute", Purpose: "web", Vendor: true},
	"File|contains|SimpleRelation|Phone":                               {Attribution: "attribute", Purpose: "web", Vendor: true},
	"File|contains|SimpleRelation|URL":                                 {Attribution: "attribute", Purpose: "web", Vendor: true},
	"File|created_with|SimpleRelation|Product":                         {Attribution: "third_party", Purpose: "product", Vendor: true},
	"File|created_with|SimpleRelation|ProductRelease":                  {Attribution: "third_party", Purpose: "product", Vendor: true},
	"File|fingerprint|SimpleRelation|Identifier":                       {Attribution: "attribute", Purpose: "web", Vendor: true},
	"FundsTransfer|id|SimpleRelation|Identifier":                       {Attribution: "attribute", Purpose: "financial", Vendor: true},
	"FundsTransfer|recipient|SimpleRelation|Account":                   {Attribution: "attribute", Purpose: "financial", Vendor: true},
	"FundsTransfer|sender|SimpleRelation|Account":                      {Attribution: "attribute", Purpose: "financial", Vendor: true},
	"FundsTransfer|third_party|SimpleRelation|Organization":            {Attribution: "third_party", Purpose: "financial", Vendor: true},
	"IPAddress|geolocation|SimpleRelation|GeoLocation":                 {Attribution: "attribute", Purpose: "network", Vendor: true},
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
	"StreetAddress|geolocation|SimpleRelation|GeoLocation":             {Attribution: "attribute", Purpose: "contact", Vendor: true},
	"StreetAddress|id|SimpleRelation|Identifier":                       {Attribution: "attribute", Purpose: "identity", Vendor: true},
	"Netblock|contains|SimpleRelation|IPAddress":                       {Attribution: "same_subject", Purpose: "network", Vendor: true},
	"Netblock|provider|SimpleRelation|Organization":                    {Attribution: "infrastructure", Purpose: "network", Vendor: true},
	"Netblock|registration|SimpleRelation|IPNetRecord":                 {Attribution: "same_subject", Purpose: "registration", Vendor: true},
	"Organization|account|SimpleRelation|Account":                      {Attribution: "controls", Purpose: "identity", Vendor: true},
	"Organization|funding_source|SimpleRelation|Organization":          {Attribution: "attribute", Purpose: "financial", Vendor: true},
	"Organization|funding_source|SimpleRelation|Person":                {Attribution: "attribute", Purpose: "financial", Vendor: true},
	"Organization|hq_address|SimpleRelation|StreetAddress":             {Attribution: "attribute", Purpose: "corporate", Vendor: true},
	"Organization|id|SimpleRelation|Identifier":                        {Attribution: "attribute", Purpose: "identity", Vendor: true},
	"Organization|legal_address|SimpleRelation|StreetAddress":          {Attribution: "attribute", Purpose: "corporate", Vendor: true},
	"Organization|street_address|SimpleRelation|StreetAddress":         {Attribution: "attribute", Purpose: "corporate", Vendor: true},
	"Organization|member|SimpleRelation|Person":                        {Attribution: "attribute", Purpose: "corporate", Vendor: true},
	"Organization|org_unit|SimpleRelation|Organization":                {Attribution: "controls", Purpose: "corporate", Vendor: true},
	"Organization|social_media_profile|SimpleRelation|URL":             {Attribution: "controls", Purpose: "web", Vendor: true},
	"Organization|subsidiary|SimpleRelation|Organization":              {Attribution: "controls", Purpose: "corporate", Vendor: true},
	"Organization|website|SimpleRelation|URL":                          {Attribution: "controls", Purpose: "web", Vendor: true},
	"Person|account|SimpleRelation|Account":                            {Attribution: "controls", Purpose: "identity", Vendor: true},
	"Person|street_address|SimpleRelation|StreetAddress":               {Attribution: "attribute", Purpose: "identity", Vendor: true},
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
	"URL|contact|SimpleRelation|ContactRecord":                         {Attribution: "attribute", Purpose: "contact", Vendor: true},
	"URL|domain|SimpleRelation|FQDN":                                   {Attribution: "same_subject", Purpose: "web", Vendor: true},
	"URL|file|SimpleRelation|File":                                     {Attribution: "attribute", Purpose: "web", Vendor: true},
	"URL|ip_address|SimpleRelation|IPAddress":                          {Attribution: "infrastructure", Purpose: "network", Vendor: true},
	"URL|port|PortRelation|Service":                                    {Attribution: "infrastructure", Purpose: "network", Vendor: true},
	"Service|fingerprint|SimpleRelation|Identifier":                    {Attribution: "attribute", Purpose: "web", Vendor: true},
	"StorageBucket|provider|SimpleRelation|Organization":               {Attribution: "third_party", Purpose: "network", Vendor: true},
	"URL|fingerprint|SimpleRelation|Identifier":                        {Attribution: "attribute", Purpose: "web", Vendor: true},
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

// VendorGraph resolves OWASP Foundation and owasp.org.
type VendorGraph struct{ PlannedGraph }

func (g VendorGraph) ResolveOrganizations(_ context.Context, q graph.OrganizationQuery, _ int) (graph.OrganizationResolution, error) {
	result := graph.OrganizationResolution{Query: q, Status: "not_found", Candidates: []graph.OrganizationCandidate{}}
	if strings.EqualFold(q.Name, "OWASP Foundation") {
		result.Status = "matched"
		result.Candidates = []graph.OrganizationCandidate{{Asset: g.Assets["owasp"]}}
	}

	return result, nil
}

// VendorFixture models a university: its registrant contact ties the
// organization to owasp.org and its own netblock. Outside parties are a
// registrar, a DNS host, a mail provider (MX), a CDN network and a
// certificate authority. A person shared with another college's contact
// must not pull that college into the footprint.
func VendorFixture() VendorGraph {
	g := FakeGraph{Assets: map[string]graph.Asset{}}
	add := func(id, typ, key string, content map[string]any) {
		g.Assets[id] = graph.Asset{ID: id, Type: typ, Key: key, Content: content}
	}
	link := func(from, label, to, rt string) {
		rel := graph.Relation{ID: from + "-" + label + "-" + to, FromID: from, ToID: to, Label: label, Type: rt}
		if label == "dns_record" {
			// Stored DNS records carry their RR type, as real records do.
			rr := 1 // A, an address record, by default
			switch {
			case rt == "PrefDNSRelation":
				rr = 15 // MX
			case rt == "SRVDNSRelation":
				rr = 33 // SRV
			case rt == "BasicDNSRelation" && g.Assets[to].Type == "FQDN":
				rr = 5 // CNAME: a record naming another name
			}
			rel.Content = map[string]any{"header": map[string]any{"rr_type": rr}}
		}
		g.Links = append(g.Links, rel)
	}
	named := func(id, typ, name string) { add(id, typ, name, map[string]any{"name": name}) }

	named("owasp", "Organization", "OWASP Foundation")
	named("educause", "Organization", "EDUCAUSE")
	named("digicert", "Organization", "DigiCert Inc")
	named("utica", "Organization", "Utica University")
	add("cr-owasp", "ContactRecord", "https://rdap.example/owasp", nil)
	add("cr-educause", "ContactRecord", "https://whois.educause.edu/registrar", nil)
	add("cr-digicert", "ContactRecord", "https://crt.example/issuer", nil)
	add("cr-utica", "ContactRecord", "https://rdap.example/utica", nil)
	add("person", "Person", "Shared Person", map[string]any{"full_name": "Shared Person"})
	add("dr", "DomainRecord", "owasp.org", map[string]any{"domain": "owasp.org"})
	add("dr-utica", "DomainRecord", "utica.edu", map[string]any{"domain": "utica.edu"})
	for _, n := range []string{"owasp.org", "www.owasp.org", "portal.owasp.org", "ns1.owasp.org",
		"pdns1.ultradns.net", "mx1.pphosted.com", "utica.edu", "www.utica.edu", "x.cloudflare.com"} {
		named(n, "FQDN", n)
	}

	add("nb-own", "Netblock", "203.0.113.0/24", map[string]any{"cidr": "203.0.113.0/24"})
	add("ipnet-own", "IPNetRecord", "203.0.113.0/24", map[string]any{"name": "OWASP-FDN"})
	add("ip-own", "IPAddress", "203.0.113.11", map[string]any{"address": "203.0.113.11"})
	add("nb-cdn", "Netblock", "151.101.0.0/16", map[string]any{"cidr": "151.101.0.0/16"})
	add("as-cdn", "AutonomousSystem", "54113", map[string]any{"number": 54113})
	add("autnum-cdn", "AutnumRecord", "AS54113", map[string]any{"handle": "AS54113", "name": "FASTLY"})
	add("ip-cdn", "IPAddress", "151.101.1.1", map[string]any{"address": "151.101.1.1"})
	add("cert", "TLSCertificate", "1234", map[string]any{"serial_number": "1234"})
	add("as-own", "AutonomousSystem", "64500", map[string]any{"number": 64500})
	add("autnum-own", "AutnumRecord", "AS64500", map[string]any{"handle": "AS64500", "name": "OWASP-FOUNDATION"})

	link("cr-owasp", "organization", "owasp", "SimpleRelation")
	link("cr-owasp", "person", "person", "SimpleRelation")
	link("dr", "registrant_contact", "cr-owasp", "SimpleRelation")
	link("dr", "registrar_contact", "cr-educause", "SimpleRelation")
	link("cr-educause", "organization", "educause", "SimpleRelation")
	link("dr", "name_server", "ns1.owasp.org", "SimpleRelation")
	link("dr", "name_server", "pdns1.ultradns.net", "SimpleRelation")
	link("owasp.org", "registration", "dr", "SimpleRelation")
	link("owasp.org", "node", "www.owasp.org", "SimpleRelation")
	link("owasp.org", "node", "portal.owasp.org", "SimpleRelation")
	link("owasp.org", "dns_record", "mx1.pphosted.com", "PrefDNSRelation")
	link("www.owasp.org", "dns_record", "ip-cdn", "BasicDNSRelation")
	link("portal.owasp.org", "dns_record", "ip-own", "BasicDNSRelation")
	link("nb-own", "registration", "ipnet-own", "SimpleRelation")
	link("ipnet-own", "registrant", "cr-owasp", "SimpleRelation")
	link("nb-own", "contains", "ip-own", "SimpleRelation")
	link("nb-cdn", "contains", "ip-cdn", "SimpleRelation")
	link("as-own", "announces", "nb-own", "SimpleRelation")
	link("as-own", "registration", "autnum-own", "SimpleRelation")
	link("autnum-own", "registrant", "cr-owasp", "SimpleRelation")
	link("as-cdn", "announces", "nb-cdn", "SimpleRelation")
	link("as-cdn", "registration", "autnum-cdn", "SimpleRelation")
	link("cert", "san_dns_name", "www.owasp.org", "SimpleRelation")
	link("cert", "issuer_contact", "cr-digicert", "SimpleRelation")
	link("cr-digicert", "organization", "digicert", "SimpleRelation")

	// Utica University shares a person with OWASP's contact and uses its
	// own CDN; none of it belongs to OWASP.
	link("cr-utica", "organization", "utica", "SimpleRelation")
	link("cr-utica", "person", "person", "SimpleRelation")
	link("dr-utica", "registrant_contact", "cr-utica", "SimpleRelation")
	link("utica.edu", "registration", "dr-utica", "SimpleRelation")
	link("utica.edu", "node", "www.utica.edu", "SimpleRelation")
	link("www.utica.edu", "dns_record", "x.cloudflare.com", "BasicDNSRelation")

	return VendorGraph{PlannedGraph{FakeGraph: g}}
}
