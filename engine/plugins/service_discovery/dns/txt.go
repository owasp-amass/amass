package dns

import (
    "strings"

    "github.com/miekg/dns"
    "github.com/owasp-amass/amass/v4/engine/plugins/support"
    et "github.com/owasp-amass/amass/v4/engine/types"
    dbt "github.com/owasp-amass/asset-db/types"
    oamdns "github.com/owasp-amass/open-asset-model/dns"
    "github.com/owasp-amass/open-asset-model/general"
)

// matchers maps TXT‑record substrings to friendly service names.
var matchers = map[string]string{
    "airtable-verification":          "Airtable",
    "aliyun-site-verification":       "Aliyun",
    "anodot-domain-verification":     "Anodot",
    "apperio-domain-verification":    "Apperio",
    "apple-domain-verification":      "Apple",
    "atlassian-domain-verification":  "Atlassian",
    "bugcrowd-verification":          "Bugcrowd",
    "canva-site-verification":        "Canva",
    "cisco-ci-domain-verification":   "Cisco",
    "cursor-domain-verification":     "Cursor",
    "docusign=":                       "Docusign",
    "dropbox-domain-verification":    "Dropbox",
    "facebook-domain-verification":   "Facebook",
    "globalsign-smime-dv":            "Globalsign",
    "google-site-verification":       "Google",
    "hubspot-developer-verification": "HubSpot",
    "knowbe4-site-verification":      "Knowbe4",
    "krisp-domain-verification":      "Krisp",
    "lastpass-verification-code":     "Lastpass",
    "mailru-verification":            "Mailru",
    "miro-verification":              "Miro",
    "mongodb-site-verification":      "MongoDB",
    "notion-domain-verification":     "Notion",
    "onetrust-domain-verification":   "OneTrust",
    "openai-domain-verification":     "OpenAI",
    "pendo-domain-verification":      "Pendo",
    "postman-domain-verification":    "Postman",
    "segment-site-verification":      "Segment",
    "status-page-domain-verification": "StatusPage",
    "stripe-verification":            "Stripe",
    "twilio-domain-verification":     "Twilio",
    "yahoo-verification-key":         "Yahoo",
    "yandex-verification":            "Yandex",
    "zoom-domain-verification":       "Zoom",
}

// txtServiceDiscovery provides TXT‑record inspection for the service‑discovery framework.
// It is instantiated from plugin.go and registered as a handler there.
type txtServiceDiscovery struct {
    name   string
    source *et.Source
}

// check satisfies the HandlerFunc signature expected by the registry.
// Instead of performing live DNS lookups, it relies entirely on TXT records
// already cached by the core DNS TXT plugin.
func (t *txtServiceDiscovery) check(e *et.Event) error {
    if e == nil || e.Entity == nil {
        return nil
    }

    entity := e.Entity // *dbt.Entity

    fqdn, ok := entity.Asset.(*oamdns.FQDN)
    if !ok || fqdn == nil {
        return nil
    }

    // Look back through the TTL window for cached TXT‑record properties.
    since, err := support.TTLStartTime(e.Session.Config(), "FQDN", "FQDN", t.name)
    if err != nil {
        return err
    }

    var entries []string
    if tags, err := e.Session.Cache().GetEntityTags(entity, since, "dns_record"); err == nil {
        for _, tag := range tags {
            if prop, ok := tag.Property.(*oamdns.DNSRecordProperty); ok && prop.Header.RRType == int(dns.TypeTXT) {
                if data, ok := prop.Data.(string); ok {
                    entries = append(entries, data)
                }
            }
        }
    }

    // If no TXT records are present in cache, nothing to do.
    if len(entries) == 0 {
        return nil
    }

    // Match patterns and build findings.
    var findings []*support.Finding
    for _, txt := range entries {
        for pattern, service := range matchers {
            if strings.Contains(txt, pattern) {
                findings = append(findings, &support.Finding{
                    From:     entity,
                    FromName: fqdn.Name,
                    To:       entity,
                    ToName:   service,
                    ToMeta:   txt,
                    Rel:      &general.SimpleRelation{Name: "TXT record"},
                })
            }
        }
    }

    if len(findings) > 0 {
        support.ProcessAssetsWithSource(e, findings, t.source, t.name, t.name)
    }
    return nil
}
