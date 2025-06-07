package dns

import (
    "strings"

    "github.com/miekg/dns"
    "github.com/owasp-amass/amass/v4/engine/plugins/support"
    et "github.com/owasp-amass/amass/v4/engine/types"
    oamdns "github.com/owasp-amass/open-asset-model/dns"
    "github.com/owasp-amass/open-asset-model/general"
)

// pluginName is the canonical identifier used across logs, cache look‑ups, and the registry.
const pluginName = "txt_service_discovery"

// matchers maps TXT‑record substrings to friendly service names.
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

// txtServiceDiscovery inspects cached DNS TXT records and tags the FQDN with discovered services.
type txtServiceDiscovery struct {
    name   string
    source *et.Source
}

// check implements the HandlerFunc expected by the Engine registry.
// It avoids live DNS look‑ups and relies exclusively on the TXT records
// already stored by the core “engine/plugins/dns/txt.go” plugin.
func (t *txtServiceDiscovery) check(e *et.Event) error {
    if e == nil || e.Entity == nil {
        return nil
    }

    entity := e.Entity // *assetdb.Entity – no explicit import required here
    fqdn, ok := entity.Asset.(*oamdns.FQDN)
    if !ok {
        return nil
    }

    // Determine the TTL window shared with the core DNS‑TXT plugin.
    since, err := support.TTLStartTime(e.Session.Config(), "FQDN", "FQDN", pluginName)
    if err != nil {
        return err
    }

    // Pull TXT records from cache.
    var entries []string
    if tags, err := e.Session.Cache().GetEntityTags(entity, since, "dns_record"); err == nil {
        for _, tag := range tags {
            if prop, ok := tag.Property.(*oamdns.DNSRecordProperty); ok && prop.Header.RRType == int(dns.TypeTXT) {
                entries = append(entries, prop.Data)
            }
        }
    }

    if len(entries) == 0 {
        return nil // nothing to analyse
    }

    // Build findings when patterns match.
    var findings []*support.Finding
    for _, txt := range entries {
        for needle, svc := range matchers {
            if strings.Contains(txt, needle) {
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
        support.ProcessAssetsWithSource(e, findings, t.source, t.name, t.name)
    }
    return nil
}
