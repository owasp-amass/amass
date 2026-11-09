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
var relationVocabulary=map[string][]string{
 "node":{"subdomain hierarchy","hostname hierarchy","dns name hierarchy","child hostname","child domain","parent hostname","parent domain","dns tree","fqdn tree","subdomain node"},
 "dns_record":{"dns records","dns record","dns resolution","dns mappings","dns mapping","dns lookup","dns lookup records","dns resource record","dns resource records"},
 "ptr_record":{"reverse dns","reverse dns lookup","reverse dns record","reverse dns records","ptr lookup","ptr records","reverse resolution"},
 "website":{"website","websites","web site","web sites","homepage","home page","web presence","official site","official website"},
 "registration":{"registration","registrations","domain registration","registration record","registration records","whois registration","rdap registration"},
 "registrant_contact":{"registrant","registrant contact","registrant details","domain registrant","registered contact","registrant information"},
 "organization":{"organization","organisations","organisation","corporate entity","corporate organization","business entity"},
 "subsidiary":{"subsidiary","subsidiaries","subsidiary relationship","subsidiary relationships","parent company relationship","corporate parent relationship"},
 "org_unit":{"organization unit","organisational unit","organizational unit","business unit","division","department"},
 "provider":{"provider","service provider","cloud provider","hosting provider","provided by"},
 "verified_for":{"verification","domain verification","domain ownership verification","verified for","verified association"},
 "certificate":{"certificate","certificates","tls cert","ssl cert","server certificate","tls certificate"},
 "san_dns_name":{"subject alternative name","subject alternative names","san","sans","certificate san","certificate dns name","certificate dns names"},
 "contains":{"containment","contains","contained within","encompasses","includes"},
 "service":{"service","services","exposed service","network service"},
 "ip_address":{"ip address","ip addresses","network address","network addresses"},
 "netblock":{"netblock","netblocks","ip block","ip blocks","network range"},
 "location":{"location","locations","physical location","geolocation"},
 "product":{"product","products","software product","application"},
 "account":{"account","accounts","user account","cloud account"},
 "contact":{"contact","contacts","point of contact"},
 "email":{"email","email address","email addresses","mailbox"},
 "domain":{"domain","domain name","domain names","url domain","url hostname"},
 "redirect":{"redirect","redirects","redirection","http redirect","url redirect"},
 "cname_record":{"cname","cname record","canonical name","alias record","dns alias"},
 "a_record":{"a record","ipv4 record","dns a record"},
 "aaaa_record":{"aaaa record","ipv6 record","dns aaaa record"},
 "mx_record":{"mx record","mail exchange","mail exchanger","mail server record"},
 "ns_record":{"ns record","nameserver","name server","name servers"},
 "txt_record":{"txt record","dns txt","text record"},
 "autonomous_system":{"autonomous system","autonomous systems","asn association","bgp origin"},
 "belongs_to":{"belongs to","membership","member of"},
 "ownership":{"ownership","owned by","owns","owner"},
 "associated_with":{"association","associated with","related to","connected with"},
}

var aliasPunctuation=regexp.MustCompile(`[^a-z0-9]+`)

func normalizeSchemaAlias(raw string)string{
 raw=strings.TrimSpace(strings.ToLower(raw))
 raw=aliasPunctuation.ReplaceAllString(raw," ")
 return strings.Join(strings.Fields(raw)," ")
}

// searchableFieldVocabulary provides human-facing vocabulary for indexed
// selector fields. Field names are only presented to the model when actually
// registered on an OAM asset type.
var searchableFieldVocabulary=map[string][]string{
 "name":{"name","asset name","hostname","title","display name"},
 "legal_name":{"legal name","registered name","official name","legal entity name"},
 "unique_id":{"unique id","unique identifier","identifier","external id"},
 "id":{"id","record id","identifier"},
 "registration_id":{"registration number","registration id","company registration","corporate registration number"},
 "jurisdiction":{"jurisdiction","registration jurisdiction","country of incorporation"},
 "address":{"address","ip address","street address","physical address"},
 "url":{"url","uri","web address","link","website url"},
 "domain":{"domain","domain name","registered domain"},
 "cidr":{"cidr","subnet","network prefix","network block","ip range"},
 "number":{"number","asn number","as number","autonomous system number"},
 "handle":{"handle","registration handle","rdap handle","registry handle"},
 "serial_number":{"serial number","certificate serial","certificate serial number"},
 "subject_common_name":{"common name","certificate common name","subject cn"},
 "e164":{"e164","telephone number","phone number","international number"},
 "full_name":{"full name","person name","name"},
 "first_name":{"first name","given name"},
 "family_name":{"family name","last name","surname"},
 "username":{"username","login","user name"},
 "account_number":{"account number","account id"},
 "account_type":{"account type","account category"},
 "service_type":{"service type","service category","network service type"},
 "product_name":{"product name","software name","product title"},
 "product_type":{"product type","software category"},
 "start_address":{"start address","first ip address","range start"},
 "end_address":{"end address","last ip address","range end"},
 "parent_handle":{"parent handle","parent registry handle"},
 "whois_server":{"whois server","registry server","rdap server"},
 "postal_code":{"postal code","zip code","zipcode"},
 "country":{"country","nation"},
 "city":{"city","municipality"},
 "locality":{"locality","town","district"},
 "reference_number":{"reference number","transaction reference"},
 "scheme":{"scheme","url scheme","protocol"},
 "punycode":{"punycode","idn","internationalized domain name"},
 "extension":{"extension","tld","top level domain"},
}

// schemaRelationAliasCandidates returns every *registered* OAM label that can
// match an explicit user phrase. An ambiguous alias produces multiple labels
// and MUST NOT be silently reduced to one.
func schemaRelationAliasCandidates(phrase string,catalog []RelationshipSchema)[]string{
 needle:=normalizeSchemaAlias(phrase)
 if needle==""{return nil}
 available:=map[string]bool{}
 for _,r:=range catalog{if r.Label!=""{available[r.Label]=true}}
 var matched []string
 for label:=range available{
  aliases:=[]string{label,strings.ReplaceAll(label,"_"," "),strings.ReplaceAll(label,"-"," ")}
  aliases=append(aliases,relationVocabulary[strings.ToLower(label)]...)
  // Treat singular/plural variants as linguistic forms only, never by
  // doing substring matching on asset values.
  for _,base:=range append([]string(nil),aliases...){
   normalized:=normalizeSchemaAlias(base)
   if normalized!=""&&!strings.HasSuffix(normalized,"s"){aliases=append(aliases,normalized+"s")}
  }
  for _,alias:=range aliases{
   if normalizeSchemaAlias(alias)==needle{matched=append(matched,label);break}
  }
 }
 sort.Strings(matched)
 return matched
}

// The catalog vocabulary is prompt context, not an alternate ontology.
// Bounds keep local-model prompts practical even for a large schema.
func compactRelationshipVocabulary(catalog []RelationshipSchema)string{
 unique:=map[string]bool{}
 for _,r:=range catalog{unique[r.Label]=true}
 labels:=make([]string,0,len(unique))
 for label:=range unique{labels=append(labels,label)}
 sort.Strings(labels)
 var lines []string
 for _,label:=range labels{
  aliases:=relationVocabulary[strings.ToLower(label)]
  if len(aliases)>8{aliases=aliases[:8]}
  if len(aliases)==0{continue}
  lines=append(lines,label+": "+strings.Join(aliases,", "))
 }
 return strings.Join(lines,"\n")
}
func compactSearchVocabulary(selectors []AssetSearchSchema)string{
 fields:=map[string]bool{}
 for _,selector:=range selectors{for _,field:=range selector.Fields{fields[field]=true}}
 sorted:=make([]string,0,len(fields))
 for field:=range fields{sorted=append(sorted,field)}
 sort.Strings(sorted)
 var lines []string
 for _,field:=range sorted{
  aliases:=searchableFieldVocabulary[field]
  if len(aliases)>6{aliases=aliases[:6]}
  if len(aliases)>0{lines=append(lines,field+": "+strings.Join(aliases,", "))}
 }
 return strings.Join(lines,"\n")
}
