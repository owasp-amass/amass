// Copyright © by Jeff Foley 2017-2025. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package dns

import (
	"log/slog"
	"strings"
	"time"

	"github.com/miekg/dns"
	"github.com/owasp-amass/amass/v5/engine/plugins/support"
	et "github.com/owasp-amass/amass/v5/engine/types"
	oamdns "github.com/owasp-amass/open-asset-model/dns"
	"github.com/owasp-amass/open-asset-model/general"
)

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

type txtHandler struct {
	name   string
	source *et.Source
	plugin *dnsPlugin
}

func (r *txtHandler) check(e *et.Event) error {
	// Create context attributes for consistent logging
	ctxAttr := slog.Group("plugin", "name", r.plugin.name, "handler", r.name)

	if e.Entity == nil {
		e.Session.Log().Error("entity is nil", ctxAttr)
		return nil
	}

	if e.Entity.Asset == nil {
		e.Session.Log().Error("entity asset is nil", ctxAttr)
		return nil
	}

	entity := e.Entity
	fqdn, ok := entity.Asset.(*oamdns.FQDN)
	if !ok {
		return nil
	}

	since, err := support.TTLStartTime(e.Session.Config(), "FQDN", "FQDN", r.plugin.name)
	if err != nil {
		since = time.Now().Add(-24 * time.Hour) // fall‑back window
	}

	var txtEntries []string
	if tags, err := e.Session.Cache().GetEntityTags(entity, since, "dns_record"); err == nil {
		for _, tag := range tags {
			if prop, ok := tag.Property.(*oamdns.DNSRecordProperty); ok && prop.Header.RRType == int(dns.TypeTXT) {
				txtEntries = append(txtEntries, prop.Data)
			}
		}
	}

	var findings []*support.Finding
	for _, txt := range txtEntries {
		for needle, svc := range matchers {
			if strings.Contains(txt, needle) {
				findings = append(findings, &support.Finding{
					From:     entity,
					FromName: fqdn.Name,
					To:       entity,
					ToName:   svc,
					ToMeta:   truncate(txt, 180),
					Rel:      &general.SimpleRelation{Name: "TXT record"},
				})
				break // Only match first pattern per TXT record
			}
		}
	}
	if len(findings) == 0 {
		return nil
	}

	// Process the findings
	return nil
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
