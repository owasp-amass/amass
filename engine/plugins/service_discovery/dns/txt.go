package dns

import (
    "strings"

    "github.com/miekg/dns"
    "github.com/owasp-amass/amass/v4/engine/plugins/support"
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
    source *et.Source // kept for future use even if not referenced directly in this file
}

// check satisfies the HandlerFunc signature expected by the registry.
// It inspects the FQDN in the event, queries its TXT records, matches them
// against the known patterns, and emits findings via the common helper.
func (t *txtServiceDiscovery) check(e *et.Event) error {
    // Sanity‑check the event and extract the underlying FQDN asset.
    if e == nil || e.Entity == nil {
        return nil
    }

    entity := e.Entity // *dbt.Entity

    fqdn, ok := entity.Asset.(*oamdns.FQDN)
    if !ok || fqdn == nil {
        return nil
    }

    // Perform a live DNS lookup for TXT records.
    txtRRs, err := support.PerformQuery(fqdn.Name, dns.TypeTXT)
    if err != nil {
        return nil // Non‑fatal: just skip processing on lookup error.
    }

    // Gather all TXT strings.
    var entries []string
    for _, rr := range txtRRs {
        if txt, ok := rr.(*dns.TXT); ok {
            entries = append(entries, txt.Txt...)
        } else {
            entries = append(entries, strings.Fields(rr.String())...)
        }
    }

    // Build findings for matched patterns.
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

    // Emit results through the shared helper.
    if len(findings) > 0 {
        support.ProcessAssetsWithSource(e, findings, t.source, t.name, t.name)
    }
    return nil
}
