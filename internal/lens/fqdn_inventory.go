// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package lens

import (
	"regexp"
	"strings"
)

// Only unambiguous FQDN inventory questions qualify for this fast path.
// "Associated" in this narrow mode means descending stored OAM "node"
// edges, not DNS-record association, organization attribution or validation.
// Ambiguous questions still fall through to the model planner.
var fqdnInventoryQuestion = regexp.MustCompile(`(?i)^\s*(?:(?:which|what|list|show)(?:\s+(?:all|the))?\s+(?:fqdn|fqdns|fully qualified domain name|fully qualified domain names|hostname|hostnames|dns names?|subdomain|subdomains|subdomain names?)(?:\s+assets)?(?:\s+(?:are|were))?(?:\s+(?:associated|connected|related)\s+with|\s+(?:under|beneath|within|for|of))|(?:list|show)\s+(?:all\s+)?(?:subdomains|subdomain names|hostnames)\s+(?:of|under|for))\s+([a-z0-9][a-z0-9.-]*\.[a-z]{2,})(?:\s*\?)?\s*$`)

// subdomainInventoryQuestion accepts the everyday wordings of a subdomain
// listing, such as "what are all the subdomains within example.com?" or
// "list the hostnames in example.com's DNS namespace". The question must
// name exactly one domain and nothing else.
var subdomainInventoryQuestion = regexp.MustCompile(`(?i)^\s*(?:(?:what|which)(?:\s+(?:are|were))?\s+|(?:list|show|give me|find|get|enumerate|name)\s+)?(?:all\s+)?(?:of\s+)?(?:the\s+)?(?:known\s+|discovered\s+)?(?:subdomains?|subdomain names|hostnames|fqdns|dns names)(?:\s+(?:that\s+)?(?:are|were|exist))?\s+(?:in|within|under|beneath|below|of|for|on)\s+(?:the\s+)?([a-z0-9][a-z0-9.-]*\.[a-z]{2,})(?:'s)?(?:\s+(?:dns\s+)?(?:namespace|domain|zone))?\s*\??\s*$`)

func FQDNInventoryHost(question string) (string, bool) {
	for _, re := range []*regexp.Regexp{fqdnInventoryQuestion, subdomainInventoryQuestion} {
		if m := re.FindStringSubmatch(question); len(m) == 2 {
			return strings.ToLower(m[1]), true
		}
	}

	return "", false
}

var subdomainInventoryLanguage = regexp.MustCompile(`(?i)\bsubdomains?\b|\bdns\s+namespace\b`)

// Inventory limits. An inventory is listed by Go and never sent to the
// model, so it can return far more names than a model-evaluated search.
const (
	DefaultInventoryNames = 1000
	MaxInventoryNames     = 10000
)

func IsSubdomainInventoryQuestion(question string) bool {
	return subdomainInventoryLanguage.MatchString(question)
}
