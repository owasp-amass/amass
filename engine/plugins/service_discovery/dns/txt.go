// SPDX‑License‑Identifier: Apache‑2.0
// Copyright © OWASP Amass contributors.

package dns

import (
	"log/slog"

	et "github.com/owasp-amass/amass/v4/engine/types"
	oamdns "github.com/owasp-amass/open-asset-model/dns"
	oam "github.com/owasp-amass/open-asset-model"
)

const pluginName = "txt_service_discovery"

// A mapping of verification‑token prefixes → human‑readable SaaS names.
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

// txtServiceDiscovery is the handler attached by plugin.go
type txtServiceDiscovery struct {
	name   string
	source *et.Source
}

// check is invoked for every FQDN asset passed through the engine.
func (t *txtServiceDiscovery) check(e *et.Event) error {
	if e == nil || e.Entity == nil {
		return fmt.Errorf("%s: received nil event or entity", t.name)
	}

	fqdn, ok := e.Entity.Asset.(*oamdns.FQDN)
	if !ok {
		// Not an FQDN asset – ignore silently.
		return nil
	}

	ctx := e.Session.Log().WithGroup("plugin").With(
		slog.String("name", t.name),
		slog.String("fqdn", fqdn.Name),
	)

	// Look back as far as the configured TTL for DNS data (fallback: 24 h).
	since, err := support.TTLStartTime(e.Session.Config(), "FQDN", "FQDN", pluginName)
	if err != nil {
		since = time.Now().Add(-24 * time.Hour)
	}

	// Pull any TXT records already cached for this FQDN.
	var txts []string
	tags, err := e.Session.Cache().GetEntityTags(e.Entity, since, "dns_record")
	if err == nil {
		for _, tag := range tags {
			if prop, ok := tag.Property.(*oamdns.DNSRecordProperty); ok &&
				prop.Header.RRType == int(dns.TypeTXT) {
				txts = append(txts, prop.Data)
			}
		}
	}

	if len(txts) == 0 {
		return nil // nothing to inspect
	}

	var findings []*support.Finding

scanLoop:
	for _, txt := range txts {
		for needle, serviceName := range matchers {
			if strings.Contains(txt, needle) {
				ctx.Info("service detected from TXT record",
					slog.String("service", serviceName),
					slog.String("txt", truncate(txt, 120)),
				)

				findings = append(findings, &support.Finding{
					Entity: &oamsvc.Service{
						Name: serviceName,
						FQDN: fqdn.Name,
					},
				})
				// A single TXT string can only represent one SaaS verification,
				// so once matched break to next TXT entry.
				continue scanLoop
			}
		}
	}

	if len(findings) > 0 {
		support.ProcessAssetsWithSource(e, findings, t.source, t.name, t.name)
	}

	return nil
}

// truncate shortens long TXT blobs for readable logging.
func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max] + "…"
}
