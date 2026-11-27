// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package graph

import (
	"encoding/json"
	"regexp"
	"strings"
)

func AddUnique(list *[]string, v string) {
	for _, x := range *list {
		if x == v {
			return
		}
	}
	*list = append(*list, v)
}

// AssetLabel is the human name of an asset without its ID, the name an
// answer uses for it.
func AssetLabel(a Asset) string {
	// a service is told apart by where it listens, not by its type
	if a.Type == "Service" {
		if v := serviceLabel(ContentString(a, "unique_id")); v != "" {
			return v
		}
	}
	if v := ContentString(a, "name", "legal_name", "url", "subject_common_name", "cidr", "address", "number",
		"handle", "service_type"); v != "" {
		return v
	}

	return a.Key
}

// serviceLabel turns a service's unique ID, host:protocol:port with a hash
// of what answered appended (www.owasp.org:tcp:443-57189b4b0f07b1e3), into
// where the service listens (www.owasp.org:tcp:443). An ID that names no
// listening place returns empty, so the service keeps its type.
func serviceLabel(uid string) string {
	if !strings.Contains(uid, ":") {
		return ""
	}
	i := strings.LastIndexByte(uid, '-')
	if i <= 0 || len(uid)-i-1 < 8 || strings.Trim(uid[i+1:], "0123456789abcdef") != "" {
		return uid
	}
	return uid[:i]
}

// ContentString returns the first non-empty string or number content field.
func ContentString(a Asset, keys ...string) string {
	data, err := json.Marshal(a.Content)
	if err != nil {
		return ""
	}

	var fields map[string]json.RawMessage
	if json.Unmarshal(data, &fields) != nil {
		return ""
	}
	for _, key := range keys {
		raw, ok := fields[key]
		if !ok {
			continue
		}

		var s string
		if json.Unmarshal(raw, &s) == nil && s != "" {
			return s
		}

		var n json.Number
		if json.Unmarshal(raw, &n) == nil && n != "" && n != "0" {
			return n.String()
		}
	}

	return ""
}

func FQDNName(a Asset) string {
	name := ContentString(a, "name")
	if name == "" {
		name = a.Key
	}

	return strings.ToLower(strings.TrimSuffix(name, "."))
}

// RegisteredDomain approximates the registrable domain of name: the last two
// labels, or three under a two-letter country code with a generic second
// level (example.co.uk).
func RegisteredDomain(name string) string {
	labels := strings.Split(strings.ToLower(strings.TrimSuffix(name, ".")), ".")
	n := len(labels)
	if n <= 2 {
		return strings.Join(labels, ".")
	}

	switch labels[n-2] {
	case "co", "com", "net", "org", "ac", "gov", "edu", "ne", "or", "go":
		if len(labels[n-1]) == 2 {
			return strings.Join(labels[n-3:], ".")
		}
	}

	return strings.Join(labels[n-2:], ".")
}

var DomainName = regexp.MustCompile(`(?i)^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)*\.[a-z]{2,}$`)

var CamelBoundary1 = regexp.MustCompile("([a-z0-9])([A-Z])")
var CamelBoundary2 = regexp.MustCompile("([A-Z])([A-Z][a-z])")
