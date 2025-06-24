// SPDX‑License‑Identifier: Apache‑2.0
// Copyright © Jeff Foley 2017‑2025.

package dns

import (
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/miekg/dns"
	"github.com/owasp-amass/amass/v4/engine/plugins/support"
	et     "github.com/owasp-amass/amass/v4/engine/types"
	oamdns "github.com/owasp-amass/open-asset-model/dns"
	oam    "github.com/owasp-amass/open-asset-model"
)

const pluginName = "txt_service_discovery"

// A (constantly growing) list of verification strings → human‑readable service.
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
	"facebook-domain-verification":    "Facebook",
	"globalsign-domain-verification":  "GlobalSign",
	"google-site-verification":        "Google",
	"hubspot-site-verification":       "HubSpot",
	"mailru-verification":             "Mail.ru",
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

// Handler implementation ----------------------------------------------------

type txtServiceDiscovery struct {
	name   string
	source *et.Source
}

func (t *txtServiceDiscovery) check(e *et.Event) error {
	ctx := slog.Group("plugin", "name", t.name)

	// Sanity‑check the event.
	if e == nil || e.Entity == nil {
		return fmt.Errorf("nil event or entity")
	}
	fqdn, ok := e.Entity.Asset.(*oamdns.FQDN)
	if !ok {
		// Not our problem – quietly ignore.
		return nil
	}

	// Work out how far back in cache we should look.
	since, err := support.TTLStartTime(e.Session.Config(), "FQDN", "FQDN", pluginName)
	if err != nil {
		since = time.Now().Add(-24 * time.Hour)
	}

	// Pull TXT records for this FQDN from the asset cache.
	var txtEntries []string
	tags, err := e.Session.Cache().GetEntityTags(e.Entity, since, "dns_record")
	if err == nil {
		for _, tag := range tags {
			if prop, ok := tag.Property.(*oamdns.DNSRecordProperty); ok &&
				prop.Header.RRType == int(dns.TypeTXT) {
				txtEntries = append(txtEntries, prop.Data)
			}
		}
	}

	if len(txtEntries) == 0 {
		return nil
	}

	// Look for verification strings.
	var findings []*support.Finding
	for _, txt := range txtEntries {
		for needle, svc := range matchers {
			if strings.Contains(txt, needle) {
				e.Session.Log().Info("service detected from TXT record",
					ctx,
					slog.String("service", svc),
					slog.String("fqdn", fqdn.Name),
					slog.String("txt", truncate(txt, 120)),
				)

				findings = append(findings, &support.Finding{
					Asset: &oamdns.Service{
						Name: svc,
						// We hang the service off the *same* FQDN entity.
						FQDN: fqdn.Name,
					},
				})
			}
		}
	}

	// Persist any discoveries & queue follow‑up processing.
	if len(findings) > 0 {
		support.ProcessAssetsWithSource(e, findings, t.source, t.name, t.name)
	}

	return nil
}

// Utility: make long TXT blobs readable in logs.
func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
