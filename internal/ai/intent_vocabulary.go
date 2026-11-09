// SPDX-License-Identifier: Apache-2.0
package ai

import (
 "sort"
 "strings"
)

// Intent vocabulary is an interpretation aid, not an OAM schema extension.
// Only names registered by the active OAM selector/relationship catalog can
// become candidate asset types. In particular "addresses" intentionally
// remains ambiguous between network and physical addresses.
var intentVocabulary = map[string][]string{
 "FQDN": {
  "subdomain", "subdomains", "subdomain name", "subdomain names",
  "hostname", "hostnames", "dns hostname", "dns hostnames",
  "dns name", "dns names",
 },
 "IPAddress": {
  "address", "addresses", "ip", "ips", "ip address", "ip addresses",
  "ipv4", "ipv6", "ipv4 address", "ipv4 addresses",
  "ipv6 address", "ipv6 addresses", "network address", "network addresses",
 },
 "Location": {
  "address", "addresses", "physical address", "physical addresses",
  "postal address", "postal addresses", "street address", "street addresses",
  "geographic location", "geographic locations",
 },
 "Organization": {
  "company", "companies", "business", "businesses", "firm", "firms",
  "corporation", "corporations", "legal entity", "legal entities",
  "org", "orgs",
 },
 "Person": {"individual", "individuals", "people"},
 "Netblock": {"network", "networks", "network block", "network blocks",
  "ip range", "ip ranges", "subnet", "subnets", "cidr", "cidrs"},
 "AutonomousSystem": {"asn", "asns", "autonomous system", "autonomous systems"},
 "TLSCertificate": {"tls certificate", "tls certificates",
  "ssl certificate", "ssl certificates", "x509 certificate", "x509 certificates"},
 "URL": {"url", "urls", "web url", "web urls"},
 "DomainRecord": {"domain registration", "domain registrations",
  "domain record", "domain records"},
 "ContactRecord": {"contact record", "contact records"},
 "Service": {"service", "services"},
 "Product": {"product", "products"},
 "Account": {"account", "accounts"},
}

func normalizeIntentTerm(raw string)string{
 raw=strings.ToLower(strings.Join(strings.Fields(strings.TrimSpace(raw))," "))
 raw=strings.TrimSuffix(raw," assets")
 raw=strings.TrimSuffix(raw," asset")
 return strings.TrimSpace(raw)
}

// intentTypeCandidates resolves all linguistic meanings before choosing one.
// Unknown/ambiguous words remain unresolved; the active catalog alone decides
// which resulting types are valid and which transitions are possible.
func intentTypeCandidates(raw string,selectors []AssetSearchSchema,relations []RelationshipSchema)[]string{
 term:=normalizeIntentTerm(raw)
 if term==""{return nil}
 registered:=map[string]bool{}
 for _,s:=range selectors{registered[s.Type]=true}
 for _,r:=range relations{registered[r.SourceType]=true;registered[r.DestinationType]=true}
 var matches []string
 for typ:=range registered{
  for _,alias:=range intentAssetAliases(typ){
   if term==alias{matches=append(matches,typ);break}
  }
 }
 sort.Strings(matches)
 return matches
}

// compactIntentVocabulary gives the model semantic examples, not permission
// to invent types, selector fields, graph edges or legal ownership.
func compactIntentVocabulary(selectors []AssetSearchSchema,relations []RelationshipSchema)string{
 registered:=map[string]bool{}
 for _,s:=range selectors{registered[s.Type]=true}
 for _,r:=range relations{registered[r.SourceType]=true;registered[r.DestinationType]=true}
 types:=make([]string,0,len(registered))
 for typ:=range registered{types=append(types,typ)}
 sort.Strings(types)
 var rows []string
 for _,typ:=range types{
  aliases:=intentVocabulary[typ]
  if len(aliases)==0{continue}
  rows=append(rows,typ+": "+strings.Join(aliases,", "))
 }
 return strings.Join(rows,"\n")
}

func subdomainTerm(raw string)bool{
 switch normalizeIntentTerm(raw){
 case "subdomain","subdomains","subdomain name","subdomain names":
  return true
 default:
  return false
 }
}
