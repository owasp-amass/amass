// SPDX-License-Identifier: Apache-2.0
package ai

import (
	"regexp"
	"sort"
	"strings"
)

// Curated relation vocabulary is intentionally conservative: these are
// interchangeable expressions for a *stored edge label*, not inferred facts.
// Dynamic aliases cover every additional label registered in the current OAM
// catalog (underscores, hyphens, spaces, common singular/plural forms).
// All interpretations remain constrained to real catalog relationships.
var relationVocabulary = map[string][]string{
	"node":               {"subdomain hierarchy", "hostname hierarchy", "dns name hierarchy", "child hostname", "child domain", "parent hostname", "parent domain", "dns tree", "fqdn tree", "subdomain node"},
	"dns_record":         {"dns records", "dns record", "dns resolution", "dns mappings", "dns mapping", "dns lookup", "dns lookup records", "dns resource record", "dns resource records"},
	"ptr_record":         {"reverse dns", "reverse dns lookup", "reverse dns record", "reverse dns records", "ptr lookup", "ptr records", "reverse resolution"},
	"website":            {"website", "websites", "web site", "web sites", "homepage", "home page", "web presence", "official site", "official website"},
	"registration":       {"registration", "registrations", "domain registration", "registration record", "registration records", "whois registration", "rdap registration"},
	"registrant_contact": {"registrant", "registrant contact", "registrant details", "domain registrant", "registered contact", "registrant information"},
	"organization":       {"organization", "organisations", "organisation", "corporate entity", "corporate organization", "business entity"},
	"subsidiary":         {"subsidiary", "subsidiaries", "subsidiary relationship", "subsidiary relationships", "parent company relationship", "corporate parent relationship"},
	"org_unit":           {"organization unit", "organisational unit", "organizational unit", "business unit", "division", "department"},
	"provider":           {"provider", "service provider", "cloud provider", "hosting provider", "provided by"},
	"verified_for":       {"verification", "domain verification", "domain ownership verification", "verified for", "verified association"},
	"certificate":        {"certificate", "certificates", "tls cert", "ssl cert", "server certificate", "tls certificate"},
	"san_dns_name":       {"subject alternative name", "subject alternative names", "san", "sans", "certificate san", "certificate dns name", "certificate dns names"},
	"contains":           {"containment", "contains", "contained within", "encompasses", "includes"},
	"ip_address":         {"ip address", "ip addresses", "network address", "network addresses"},
	"location":           {"location", "locations", "physical location", "geolocation"},
	"account":            {"account", "accounts", "user account", "cloud account"},
	"contact":            {"contact", "contacts", "point of contact"},
	"domain":             {"domain", "domain name", "domain names", "url domain", "url hostname"},
	// Labels whose meaning depends on relation content (A, AAAA, MX, TXT,
	// CNAME records are all "dns_record" edges distinguished by RR type) are
	// deliberately absent until the planner can filter on that content.
	"port":         {"open port", "open ports", "exposed service", "exposed services", "network service", "listening service"},
	"name_server":  {"name server", "name servers", "nameserver", "nameservers", "registered name servers"},
	"product_used": {"product used", "products used", "software in use", "technology used", "technologies used"},
	"announces":    {"announces", "announced by", "bgp announcement", "bgp announcements", "bgp origin"},
	"member":       {"member", "members", "membership", "member of"},
}

var aliasPunctuation = regexp.MustCompile(`[^a-z0-9]+`)

func normalizeSchemaAlias(raw string) string {
	raw = strings.TrimSpace(strings.ToLower(raw))
	raw = aliasPunctuation.ReplaceAllString(raw, " ")
	return strings.Join(strings.Fields(raw), " ")
}

// searchableFieldVocabulary provides human-facing vocabulary for indexed
// selector fields. Field names are only presented to the model when actually
// registered on an OAM asset type.
var searchableFieldVocabulary = map[string][]string{
	"name":                {"name", "asset name", "hostname", "title", "display name"},
	"legal_name":          {"legal name", "registered name", "official name", "legal entity name"},
	"unique_id":           {"unique id", "unique identifier", "identifier", "external id"},
	"id":                  {"id", "record id", "identifier"},
	"registration_id":     {"registration number", "registration id", "company registration", "corporate registration number"},
	"jurisdiction":        {"jurisdiction", "registration jurisdiction", "country of incorporation"},
	"address":             {"address", "ip address", "street address", "physical address"},
	"url":                 {"url", "uri", "web address", "link", "website url"},
	"domain":              {"domain", "domain name", "registered domain"},
	"cidr":                {"cidr", "subnet", "network prefix", "network block", "ip range"},
	"number":              {"number", "asn number", "as number", "autonomous system number"},
	"handle":              {"handle", "registration handle", "rdap handle", "registry handle"},
	"serial_number":       {"serial number", "certificate serial", "certificate serial number"},
	"subject_common_name": {"common name", "certificate common name", "subject cn"},
	"e164":                {"e164", "telephone number", "phone number", "international number"},
	"full_name":           {"full name", "person name", "name"},
	"first_name":          {"first name", "given name"},
	"family_name":         {"family name", "last name", "surname"},
	"username":            {"username", "login", "user name"},
	"account_number":      {"account number", "account id"},
	"account_type":        {"account type", "account category"},
	"service_type":        {"service type", "service category", "network service type"},
	"product_name":        {"product name", "software name", "product title"},
	"product_type":        {"product type", "software category"},
	"start_address":       {"start address", "first ip address", "range start"},
	"end_address":         {"end address", "last ip address", "range end"},
	"parent_handle":       {"parent handle", "parent registry handle"},
	"whois_server":        {"whois server", "registry server", "rdap server"},
	"postal_code":         {"postal code", "zip code", "zipcode"},
	"country":             {"country", "nation"},
	"city":                {"city", "municipality"},
	"locality":            {"locality", "town", "district"},
	"reference_number":    {"reference number", "transaction reference"},
	"scheme":              {"scheme", "url scheme", "protocol"},
	"punycode":            {"punycode", "idn", "internationalized domain name"},
	"extension":           {"extension", "tld", "top level domain"},
	"amount":              {"amount", "sum", "transfer amount", "payment amount"},
	"type":                {"type", "kind", "category", "file type", "object type"},
	"id_type":             {"identifier type", "id type", "identifier category"},
	"country_code":        {"country code", "international dialing code", "phone country code"},
	"province":            {"province", "state", "region", "administrative division"},
	"street_name":         {"street name", "road name", "street", "road"},
	"building":            {"building", "building name", "property name"},
	"building_number":     {"building number", "street number", "house number"},
	"unit":                {"unit", "suite", "apartment", "office unit"},
	"account_id":          {"account id", "account identifier", "cloud account id"},
}

// relationLabelAliases derives spelling and inflection variants for EVERY
// registered relation label, then adds carefully curated semantic synonyms.
// This avoids needing to maintain a handcrafted entry for each new label.
func relationLabelAliases(label string) []string {
	aliases := []string{label, strings.ReplaceAll(label, "_", " "), strings.ReplaceAll(label, "-", " ")}
	aliases = append(aliases, relationVocabulary[strings.ToLower(label)]...)
	all := append([]string(nil), aliases...)
	for _, raw := range aliases {
		words := strings.Fields(normalizeSchemaAlias(raw))
		if len(words) == 0 {
			continue
		}
		last := words[len(words)-1]
		// A trailing preposition is not a noun to pluralize.
		switch last {
		case "to", "of", "by", "for", "with", "in", "on", "under", "over", "from", "at":
			continue
		}
		// Only a transparent English plural inflection is generated. Do not
		// stem or fuzzy-match unfamiliar words into unrelated OAM labels.
		switch {
		case strings.HasSuffix(last, "s"):
			continue
		case strings.HasSuffix(last, "y") && len(last) > 1:
			words[len(words)-1] = strings.TrimSuffix(last, "y") + "ies"
		case strings.HasSuffix(last, "ch") || strings.HasSuffix(last, "sh"):
			words[len(words)-1] = last + "es"
		default:
			words[len(words)-1] = last + "s"
		}
		all = append(all, strings.Join(words, " "))
	}
	seen := map[string]bool{}
	result := make([]string, 0, len(all))
	for _, raw := range all {
		term := normalizeSchemaAlias(raw)
		if term == "" || seen[term] {
			continue
		}
		seen[term] = true
		result = append(result, term)
	}
	return result
}

// searchableFieldAliases provides a discoverable form for every OAM
// indexed field, even if there is no hand-curated semantic expansion.
func searchableFieldAliases(field string) []string {
	aliases := []string{field, strings.ReplaceAll(field, "_", " "), strings.ReplaceAll(field, "-", " ")}
	aliases = append(aliases, searchableFieldVocabulary[field]...)
	seen := map[string]bool{}
	var result []string
	for _, a := range aliases {
		normalized := normalizeSchemaAlias(a)
		if normalized == "" || seen[normalized] {
			continue
		}
		seen[normalized] = true
		result = append(result, normalized)
	}
	return result
}

// schemaRelationAliasCandidates returns every *registered* OAM label that can
// match an explicit user phrase. An ambiguous alias produces multiple labels
// and MUST NOT be silently reduced to one.
func schemaRelationAliasCandidates(phrase string, catalog []RelationshipSchema) []string {
	needle := normalizeSchemaAlias(phrase)
	if needle == "" {
		return nil
	}
	available := map[string]bool{}
	for _, r := range catalog {
		if r.Label != "" {
			available[r.Label] = true
		}
	}
	var matched []string
	for label := range available {
		aliases := relationLabelAliases(label)
		for _, alias := range aliases {
			if normalizeSchemaAlias(alias) == needle {
				matched = append(matched, label)
				break
			}
		}
	}
	sort.Strings(matched)
	return matched
}

// The catalog vocabulary is prompt context, not an alternate ontology.
// Bounds keep local-model prompts practical even for a large schema.
func compactRelationshipVocabulary(catalog []RelationshipSchema) string {
	unique := map[string]bool{}
	for _, r := range catalog {
		unique[r.Label] = true
	}
	labels := make([]string, 0, len(unique))
	for label := range unique {
		labels = append(labels, label)
	}
	sort.Strings(labels)
	var lines []string
	for _, label := range labels {
		aliases := relationVocabulary[strings.ToLower(label)]
		if len(aliases) > 8 {
			aliases = aliases[:8]
		}
		if len(aliases) == 0 {
			continue
		}
		lines = append(lines, label+": "+strings.Join(aliases, ", "))
	}
	return strings.Join(lines, "\n")
}
func compactSearchVocabulary(selectors []AssetSearchSchema) string {
	fields := map[string]bool{}
	for _, selector := range selectors {
		for _, field := range selector.Fields {
			fields[field] = true
		}
	}
	sorted := make([]string, 0, len(fields))
	for field := range fields {
		sorted = append(sorted, field)
	}
	sort.Strings(sorted)
	var lines []string
	for _, field := range sorted {
		aliases := searchableFieldAliases(field)
		if len(aliases) > 7 {
			aliases = aliases[:7]
		}
		lines = append(lines, field+": "+strings.Join(aliases, ", "))
	}
	return strings.Join(lines, "\n")
}

// Intent-operation paraphrases are semantic signals for goal planning, NOT
// stand-ins for OAM edge labels. In particular "owns" and "associated with"
// must not be treated as synonyms for an observed ownership relationship.
var investigationOperationVocabulary = map[string][]string{
	"inventory": {"list", "show", "enumerate", "find all", "what are the", "which ones",
		"catalog", "inventory", "discover in database", "count", "how many", "give me every"},
	"association": {"associated with", "related to", "connected to", "linked to",
		"correlated with", "affiliated with", "tied to", "associated assets",
		"connected assets", "relationships of", "relationships with"},
	"hierarchy": {"under", "beneath", "children of", "descendants of", "parent of",
		"ancestors of", "within the hierarchy", "in the tree", "direct children",
		"all descendants", "subdomains under"},
	"attribution": {"attributed to", "registered to", "registrant", "who controls",
		"who operates", "who manages", "who owns", "ultimate parent", "parent company",
		"subsidiary of", "corporate family", "legal entity"},
	"evidence": {"evidence for", "prove", "supporting sources", "source tags",
		"confidence", "how was this discovered", "why is this associated",
		"how do we know", "show provenance", "witnessed path"},
	"comparison": {"compare", "versus", "vs", "better supported", "strongest evidence",
		"which route", "shortest path", "most sources", "rank", "difference between",
		"which has more"},
	"temporal": {"first discovered", "last seen", "recently observed", "historical",
		"when was", "newest", "oldest", "seen since", "observed before"},
	"filter": {"only", "excluding", "except", "without", "within", "where",
		"matching", "limited to", "with attribute", "with property"},
}

func compactOperationVocabulary() string {
	intents := make([]string, 0, len(investigationOperationVocabulary))
	for k := range investigationOperationVocabulary {
		intents = append(intents, k)
	}
	sort.Strings(intents)
	var lines []string
	for _, kind := range intents {
		values := investigationOperationVocabulary[kind]
		if len(values) > 7 {
			values = values[:7]
		}
		lines = append(lines, kind+": "+strings.Join(values, ", "))
	}
	return strings.Join(lines, "\n")
}

// CuratedRelationLabels returns the OAM labels that have curated aliases,
// sorted. Tests use it to reject aliases for labels OAM does not register.
func CuratedRelationLabels() []string {
	labels := make([]string, 0, len(relationVocabulary))
	for label := range relationVocabulary {
		labels = append(labels, label)
	}
	sort.Strings(labels)
	return labels
}
