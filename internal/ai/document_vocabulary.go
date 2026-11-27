// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package ai

import (
	"fmt"
	"net/netip"
	"net/url"
	"reflect"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"

	"github.com/owasp-amass/amass/v5/internal/semantics"
	oam "github.com/owasp-amass/open-asset-model"
	oamorg "github.com/owasp-amass/open-asset-model/org"
	oampeople "github.com/owasp-amass/open-asset-model/people"
	oamplat "github.com/owasp-amass/open-asset-model/platform"
)

// documentAssetTypes are the Open Asset Model asset types a document's text
// can name. Record types (DomainRecord, IPNetRecord, ContactRecord...) come
// from registries, not from prose, and Files and Services are what Amass
// observes, so they are left out.
var documentAssetTypes = []oam.AssetType{
	oam.Organization, oam.Person, oam.FQDN, oam.IPAddress, oam.Netblock, oam.AutonomousSystem, oam.URL,
	oam.Identifier, oam.Phone, oam.StreetAddress, oam.GeoLocation, oam.Product, oam.ProductRelease,
	oam.StorageBucket,
}

// assetHints tell the model what value to give for each asset type.
var assetHints = map[string]string{
	"Organization":     "the organization's name as written",
	"Person":           "the person's full name",
	"FQDN":             "a host or domain name, such as vpn.example.edu",
	"IPAddress":        "an IPv4 or IPv6 address",
	"Netblock":         "an address range in CIDR form, such as 192.0.2.0/24",
	"AutonomousSystem": "an autonomous system number, such as AS64496",
	"URL":              "a full http or https URL",
	"Identifier":       "an email address, or an identifier such as an LEI, DUNS or EIN",
	"Phone":            "a phone or fax number as written",
	"StreetAddress":    "a full street address",
	"GeoLocation":      "latitude,longitude in decimal degrees",
	"Product":          "a product or software name, such as Workday or Microsoft 365",
	"ProductRelease":   "a product with its version, such as Apache HTTP Server 2.4.62",
	"StorageBucket":    "a cloud storage bucket name or URL",
}

// documentAttributeTypes are the asset types the model may give field values
// for, with their OAM struct; the field names come from its JSON tags.
var documentAttributeTypes = map[oam.AssetType]any{
	oam.Organization:   oamorg.Organization{},
	oam.Person:         oampeople.Person{},
	oam.Product:        oamplat.Product{},
	oam.ProductRelease: oamplat.ProductRelease{},
}

// attributeKeyFields are fields that identify an asset rather than describe
// it; the asset's name is its finding's subject.
var attributeKeyFields = map[string]bool{"unique_id": true, "id": true, "name": true, "product_name": true,
	"full_name": true}

// docVocabulary is what the document model may report: OAM asset types, the
// OAM relations between them, the statement catalog's natural-reading
// predicates, and the OAM fields of the types that have descriptive fields.
type docVocabulary struct {
	rules      semantics.StatementPredicates
	types      []string
	assetTypes map[string]bool
	// oamRelations maps subject type -> relation label -> object types.
	oamRelations  map[string]map[string][]string
	fields        map[string][]string
	predicates    []string
	relationLines []string
}

var (
	vocabOnce sync.Once
	vocab     *docVocabulary
)

// documentVocabulary builds the vocabulary once, from OAM and the statement
// catalog, so it follows OAM as it grows.
func documentVocabulary() *docVocabulary {
	vocabOnce.Do(func() {
		v := &docVocabulary{rules: statementRules(), assetTypes: map[string]bool{},
			oamRelations: map[string]map[string][]string{}, fields: map[string][]string{}}
		for _, t := range documentAssetTypes {
			v.types = append(v.types, string(t))
			v.assetTypes[string(t)] = true
		}

		predicates := map[string]bool{}
		for _, p := range v.rules.Predicates {
			predicates[p.Name] = true
			v.relationLines = append(v.relationLines, fmt.Sprintf("%s -[%s]-> %s: %s",
				strings.Join(p.SubjectTypes, "|"), p.Name, strings.Join(p.ObjectTypes, "|"), p.Description))
		}
		for _, subject := range documentAssetTypes {
			labels := oam.GetAssetOutgoingRelations(subject)
			sort.Strings(labels)
			for _, label := range labels {
				var objects []string
				for _, rtype := range []oam.RelationType{oam.SimpleRelation, oam.BasicDNSRelation} {
					for _, dst := range oam.GetTransformAssetTypes(subject, label, rtype) {
						if v.assetTypes[string(dst)] && !slices.Contains(objects, string(dst)) {
							objects = append(objects, string(dst))
						}
					}
				}
				if len(objects) == 0 {
					continue
				}
				if v.oamRelations[string(subject)] == nil {
					v.oamRelations[string(subject)] = map[string][]string{}
				}
				v.oamRelations[string(subject)][label] = objects
				predicates[label] = true
				v.relationLines = append(v.relationLines, fmt.Sprintf("%s -[%s]-> %s (OAM): the subject's %s is the object",
					subject, label, strings.Join(objects, "|"), strings.ReplaceAll(label, "_", " ")))
			}
		}
		for p := range predicates {
			v.predicates = append(v.predicates, p)
		}
		sort.Strings(v.predicates)

		for t, sample := range documentAttributeTypes {
			rt := reflect.TypeOf(sample)
			for i := range rt.NumField() {
				f := rt.Field(i)
				name, _, _ := strings.Cut(f.Tag.Get("json"), ",")
				if name == "" || name == "-" || attributeKeyFields[name] {
					continue
				}
				switch f.Type.Kind() {
				case reflect.String, reflect.Int, reflect.Bool, reflect.Slice:
					v.fields[string(t)] = append(v.fields[string(t)], name)
				}
			}
		}
		vocab = v
	})
	return vocab
}

// allows reports whether predicate relates subject to object: a statement
// catalog predicate with fitting types, or an OAM relation OAM allows between
// the two types.
func (v *docVocabulary) allows(subject, predicate, object string) bool {
	if p, ok := v.rules.Predicate(predicate); ok {
		return slices.Contains(p.SubjectTypes, subject) && slices.Contains(p.ObjectTypes, object)
	}
	return slices.Contains(v.oamRelations[subject][predicate], object)
}

var (
	domainName = regexp.MustCompile(`^(?i)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{0,61}[a-z0-9]$`)
	emailAddr  = regexp.MustCompile(`^(?i)[a-z0-9._%+'-]+@([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$`)
)

// nameTypes are the asset types whose value is a name.
var nameTypes = map[string]bool{"Organization": true, "Person": true, "Product": true, "ProductRelease": true}

// checkValue returns why value cannot be an asset of type t, or "".
func checkValue(t, value string) string {
	if value == "" || len(value) > maxStatementTerm {
		return fmt.Sprintf("empty or overlong %s", t)
	}
	ok := true
	switch t {
	case "FQDN":
		ok = domainName.MatchString(strings.TrimSuffix(value, "."))
	case "IPAddress":
		_, err := netip.ParseAddr(value)
		ok = err == nil
	case "Netblock":
		_, err := netip.ParsePrefix(value)
		ok = err == nil
	case "AutonomousSystem":
		ok = asNumber(value) > 0
	case "URL":
		u, err := url.Parse(value)
		ok = err == nil && (u.Scheme == "http" || u.Scheme == "https") && u.Host != ""
	case "Identifier":
		ok = emailAddr.MatchString(value) || strings.IndexFunc(value, func(r rune) bool { return r >= '0' && r <= '9' }) >= 0
	case "Phone":
		ok = digits(value) >= 7
	case "StreetAddress":
		ok = digits(value) > 0 && strings.IndexFunc(value, func(r rune) bool { return r > '9' }) >= 0
	case "GeoLocation":
		ok = geoPoint(value)
	case "StorageBucket":
		ok = !strings.ContainsAny(value, " \t")
	default:
		if nameTypes[t] {
			ok = properName(value)
		}
	}
	if !ok {
		return fmt.Sprintf("%q is not a %s", value, t)
	}
	if what := semantics.MisnamedDocumentName(t, value); what != "" {
		return fmt.Sprintf("%q names %s, not a %s", value, what, t)
	}
	return ""
}

// asNumber reads an autonomous system number written as 64496 or AS64496.
func asNumber(value string) int {
	v := strings.TrimSpace(strings.TrimPrefix(strings.ToUpper(value), "AS"))
	n, err := strconv.Atoi(v)
	if err != nil {
		return 0
	}
	return n
}

func digits(s string) int {
	n := 0
	for _, r := range s {
		if r >= '0' && r <= '9' {
			n++
		}
	}
	return n
}

// geoPoint reports whether value is "latitude,longitude".
func geoPoint(value string) bool {
	lat, lon, ok := strings.Cut(value, ",")
	if !ok {
		return false
	}
	a, err1 := strconv.ParseFloat(strings.TrimSpace(lat), 64)
	b, err2 := strconv.ParseFloat(strings.TrimSpace(lon), 64)
	return err1 == nil && err2 == nil && a >= -90 && a <= 90 && b >= -180 && b <= 180
}
