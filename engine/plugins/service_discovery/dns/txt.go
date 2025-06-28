package dns

import (
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/miekg/dns"
	"github.com/owasp-amass/amass/v4/engine/plugins/support"
	et "github.com/owasp-amass/amass/v4/engine/types"
	oam "github.com/owasp-amass/open-asset-model/dns"
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

type txtServiceDiscovery struct {
	name   string
	source *et.Source
}

func (t *txtServiceDiscovery) check(e *et.Event) error {
	// Create context attributes for consistent logging
	ctxAttr := slog.Group("plugin", "name", t.name, "handler", "check")

	e.Session.Log().Info("TXT service discovery check started", ctxAttr)

	// Validate event and entity
	if e == nil {
		e.Session.Log().Error("event is nil", ctxAttr)
		return fmt.Errorf("event is nil")
	}

	if e.Entity == nil {
		e.Session.Log().Error("entity is nil", ctxAttr)
		return fmt.Errorf("entity is nil")
	}

	if e.Entity.Asset == nil {
		e.Session.Log().Error("entity asset is nil", ctxAttr)
		return fmt.Errorf("entity asset is nil")
	}

	e.Session.Log().Info("event validation passed", ctxAttr, slog.String("assetType", fmt.Sprintf("%T", e.Entity.Asset)))

	entity := e.Entity
	fqdn, ok := entity.Asset.(*oam.FQDN)
	if !ok {
		e.Session.Log().Info("entity is not an FQDN – skipping", ctxAttr, slog.String("actualType", fmt.Sprintf("%T", entity.Asset)))
		return nil
	}

	e.Session.Log().Info("processing FQDN for TXT service discovery", ctxAttr, slog.String("domain", fqdn.Name))

	since, err := support.TTLStartTime(e.Session.Config(), "FQDN", "FQDN", pluginName)
	if err != nil {
		since = time.Now().Add(-24 * time.Hour) // fall‑back window
		e.Session.Log().Info("no TTL config – defaulting to 24h", ctxAttr, slog.String("domain", fqdn.Name))
	} else {
		e.Session.Log().Info("TTL start time determined", ctxAttr, slog.String("domain", fqdn.Name), slog.Time("since", since))
	}

	var txtEntries []string
	tags, cacheErr := e.Session.Cache().GetEntityTags(entity, since, "dns_record")
	if cacheErr != nil {
		e.Session.Log().Error("cache access error", slog.String("err", cacheErr.Error()), ctxAttr, slog.String("domain", fqdn.Name))
	} else {
		e.Session.Log().Info("retrieved entity tags from cache", ctxAttr, slog.String("domain", fqdn.Name), slog.Int("tagCount", len(tags)))

		for i, tag := range tags {
			if prop, ok := tag.Property.(*oam.DNSRecordProperty); ok && prop.Header.RRType == int(dns.TypeTXT) {
				txtEntries = append(txtEntries, prop.Data)
				e.Session.Log().Info("found TXT record in cache", ctxAttr,
					slog.String("domain", fqdn.Name),
					slog.Int("tagIndex", i),
					slog.String("txtData", truncate(prop.Data, 100)))
			} else {
				e.Session.Log().Info("skipping non-TXT tag", ctxAttr,
					slog.String("domain", fqdn.Name),
					slog.Int("tagIndex", i),
					slog.String("tagType", fmt.Sprintf("%T", tag.Property)))
			}
		}
	}

	if len(txtEntries) == 0 {
		e.Session.Log().Info("no TXT records found – nothing to analyse", ctxAttr, slog.String("domain", fqdn.Name))
		return nil
	}

	e.Session.Log().Info("found TXT records for analysis", ctxAttr,
		slog.String("domain", fqdn.Name),
		slog.Int("recordCount", len(txtEntries)))

	var findings []*support.Finding
	for i, txt := range txtEntries {
		e.Session.Log().Info("analyzing TXT record", ctxAttr,
			slog.String("domain", fqdn.Name),
			slog.Int("recordIndex", i),
			slog.String("txtContent", truncate(txt, 150)))

		matchFound := false
		for needle, svc := range matchers {
			if strings.Contains(txt, needle) {
				matchFound = true
				e.Session.Log().Info("service detected via TXT",
					slog.String("service", svc),
					slog.String("needle", needle),
					slog.String("domain", fqdn.Name),
					slog.String("txtRecord", truncate(txt, 180)),
					ctxAttr,
				)

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

		if !matchFound {
			e.Session.Log().Info("no service patterns matched in TXT record", ctxAttr,
				slog.String("domain", fqdn.Name),
				slog.Int("recordIndex", i),
				slog.String("txtContent", truncate(txt, 100)))
		}
	}

	if len(findings) == 0 {
		e.Session.Log().Info("no services matched any TXT strings", ctxAttr, slog.String("domain", fqdn.Name))
		return nil
	}

	e.Session.Log().Info("emitting findings", slog.Int("count", len(findings)), ctxAttr, slog.String("domain", fqdn.Name))

	// Process the findings
	support.ProcessAssetsWithSource(e, findings, t.source, t.name, t.name)

	e.Session.Log().Info("TXT service discovery check completed", ctxAttr, slog.String("domain", fqdn.Name))
	return nil
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}