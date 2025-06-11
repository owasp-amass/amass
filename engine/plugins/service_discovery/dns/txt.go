// SPDX-License-Identifier: Apache-2.0
// Copyright © Jeff Foley 2017-2025.

// Package dns provides a service-discovery check that mines cached DNS
// TXT-records for “verification” strings which reveal third-party
// services in use.  Every log line includes component=txt_service_discovery
// so you can grep that single token.
package dns

import (
	"strings"
	"time"

	"log/slog"

	"github.com/miekg/dns"
	"github.com/owasp-amass/amass/v4/engine/plugins/support"
	et "github.com/owasp-amass/amass/v4/engine/types"
	oamdns "github.com/owasp-amass/open-asset-model/dns"
	"github.com/owasp-amass/open-asset-model/general"
)

const (
	pluginName   = "txt_service_discovery" // shared with plugin.go
	componentKey = "component"             // uniform log key
)

// matchers maps TXT-record substrings to friendly service names.
var matchers = map[string]string{
	"airtable-verification":           "Airtable",
	"aliyun-site-verification":        "Aliyun",
	"anodot-domain-verification":      "Anodot",
	"apperio-domain-verification":     "Apperio",
	"apple-domain-verification":       "Apple",
	"atlassian-domain-verification":   "Atlassian",
	"bugcrowd-verification":           "Bugcrowd",
	"canva-site-verification":         "Canva",
	"cisco-ci-domain-verification":    "Cisco",
	"cursor-domain-verification":      "Cursor",
	"docusign=":                       "Docusign",
	"dropbox-domain-verification":     "Dropbox",
	"facebook-domain-verification":    "Facebook",
	"globalsign-smime-dv":             "Globalsign",
	"google-site-verification":        "Google",
	"hubspot-developer-verification":  "HubSpot",
	"knowbe4-site-verification":       "Knowbe4",
	"krisp-domain-verification":       "Krisp",
	"lastpass-verification-code":      "Lastpass",
	"mailru-verification":             "Mailru",
	"miro-verification":               "Miro",
	"mongodb-site-verification":       "MongoDB",
	"notion-domain-verification":      "Notion",
	"onetrust-domain-verification":    "OneTrust",
	"openai-domain-verification":      "OpenAI",
	"pendo-domain-verification":       "Pendo",
	"postman-domain-verification":     "Postman",
	"segment-site-verification":       "Segment",
	"status-page-domain-verification": "StatusPage",
	"stripe-verification":             "Stripe",
	"twilio-domain-verification":      "Twilio",
	"yahoo-verification-key":          "Yahoo",
	"yandex-verification":             "Yandex",
	"zoom-domain-verification":        "Zoom",
}

// txtServiceDiscovery inspects cached DNS TXT records and tags the FQDN
// with discovered services.
type txtServiceDiscovery struct {
	name   string
	source *et.Source
}

// check implements the HandlerFunc expected by the Engine registry.
func (t *txtServiceDiscovery) check(e *et.Event) error {
	log := slog.Default().With(componentKey, pluginName)

	if e == nil || e.Entity == nil {
		log.Info("event or entity is nil – skipping")
		return nil
	}

	entity := e.Entity
	fqdn, ok := entity.Asset.(*oamdns.FQDN)
	if !ok {
		log.Info("entity is not an FQDN – skipping")
		return nil
	}

	log = log.With("fqdn", fqdn.Name)

	// Determine the TTL window shared with the core DNS-TXT plugin.
	since, err := support.TTLStartTime(e.Session.Config(), "FQDN", "FQDN", pluginName)
	if err != nil {
		since = time.Now().Add(-24 * time.Hour)
		log.Info("no TTL config found – using 24-hour fallback")
	} else {
		log.Info("using TTL window", "since", since.Format(time.RFC3339))
	}

	// Pull TXT records from cache.
	var entries []string
	if tags, err := e.Session.Cache().GetEntityTags(entity, since, "dns_record"); err == nil {
		for _, tag := range tags {
			if prop, ok := tag.Property.(*oamdns.DNSRecordProperty); ok && prop.Header.RRType == int(dns.TypeTXT) {
				entries = append(entries, prop.Data)
			}
		}
	} else {
		log.Info("cache access error", "error", err)
	}

	if len(entries) == 0 {
		log.Info("no TXT entries found – nothing to analyse")
		return nil
	}

	log.Info("analysing TXT entries", "count", len(entries))

	// Build findings when patterns match.
	var findings []*support.Finding
	for _, txt := range entries {
		log.Info("TXT entry", "text", truncate(txt, 120))
		for needle, svc := range matchers {
			if strings.Contains(txt, needle) {
				log.Info("service match",
					"service", svc,
					"needle", needle,
					"txt_snippet", truncate(txt, 80),
				)
				findings = append(findings, &support.Finding{
					From:     entity,
					FromName: fqdn.Name,
					To:       entity,
					ToName:   svc,
					ToMeta:   txt,
					Rel:      &general.SimpleRelation{Name: "TXT record"},
				})
			}
		}
	}

	if len(findings) > 0 {
		log.Info("emitting findings", "count", len(findings))
		support.ProcessAssetsWithSource(e, findings, t.source, t.name, t.name)
	} else {
		log.Info("no service strings matched any TXT entries")
	}

	return nil
}

// truncate returns s if it is already short, otherwise keeps the first n
// runes and appends “…”.
func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}