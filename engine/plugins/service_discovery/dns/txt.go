package dns

import (
    "fmt"
    "strings"
    "time"

    "github.com/miekg/dns"
    "github.com/owasp-amass/amass/v4/engine/plugins/support"
    et "github.com/owasp-amass/amass/v4/engine/types"
    oamdns "github.com/owasp-amass/open-asset-model/dns"
)

// matchers defines patterns to match specific services based on TXT records
var matchers = map[string]string{
    "airtable-verification":                "Airtable",
    "aliyun-site-verification":             "Aliyun",
    "anodot-domain-verification":           "Anodot",
    "apperio-domain-verification":          "Apperio",
    "apple-domain-verification":            "Apple",
    "atlassian-domain-verification":        "Atlassian",
    "bugcrowd-verification":                "Bugcrowd",
    "canva-site-verification":              "Canva",
    "cisco-ci-domain-verification":         "Cisco",
    "cursor-domain-verification":           "Cursor",
    "docusign=":                             "Docusign",
    "dropbox-domain-verification":          "Dropbox",
    "facebook-domain-verification":         "Facebook",
    "globalsign-smime-dv":                  "Globalsign",
    "google-site-verification":             "Google",
    "hubspot-developer-verification":       "HubSpot",
    "knowbe4-site-verification":            "Knowbe4",
    "krisp-domain-verification":            "Krisp",
    "lastpass-verification-code":           "Lastpass",
    "mailru-verification":                  "Mailru",
    "miro-verification":                    "Miro",
    "mongodb-site-verification":            "MongoDB",
    "notion-domain-verification":           "Notion",
    "onetrust-domain-verification":         "OneTrust",
    "openai-domain-verification":           "OpenAI",
    "pendo-domain-verification":            "Pendo",
    "postman-domain-verification":          "Postman",
    "segment-site-verification":            "Segment",
    "status-page-domain-verification":      "StatusPage",
    "stripe-verification":                  "Stripe",
    "twilio-domain-verification":           "Twilio",
    "yahoo-verification-key":               "Yahoo",
    "yandex-verification":                  "Yandex",
    "zoom-domain-verification":             "Zoom",
}

// txtServiceDiscovery implements the core logic for processing DNS TXT records.
type txtServiceDiscovery struct {
    name   string
    source *et.Source
}

// Check processes incoming FQDN events, looks up TXT records, and emits findings.
// Called by the plugin manager via registry registration.
func (t *txtServiceDiscovery) Check(e *et.Event) error {
    if e == nil || e.Entity == nil || e.Entity.Asset == nil {
        return nil
    }

    fqdn, ok := e.Entity.Asset.(*oamdns.FQDN)
    if !ok {
        return nil
    }

    // Determine the TTL start time
    since, err := support.TTLStartTime(e.Session.Config(), "FQDN", "FQDN", t.name)
    if err != nil {
        return err
    }

    var txtRecords []dns.RR
    var props []*oamdns.DNSRecordProperty

    // Decide whether to retrieve from cache or DNS
    if support.AssetMonitoredWithinTTL(e.Session, e.Entity, t.source, since) {
        props = t.lookup(e, fqdn, since)
    } else {
        txtRecords = t.query(e, fqdn)
        if len(txtRecords) > 0 {
            t.store(e, fqdn, txtRecords)
        }
    }

    if len(txtRecords) > 0 || len(props) > 0 {
        t.process(e, fqdn, txtRecords, props)
        support.AddDNSRecordType(e, int(dns.TypeTXT))
    }
    return nil
}

// query retrieves TXT records via DNS.
func (t *txtServiceDiscovery) query(e *et.Event, fqdn *oamdns.FQDN) []dns.RR {
    return support.Query(e.Session, fqdn, dns.TypeTXT)
}

// lookup fetches stored DNSRecordProperty values.
func (t *txtServiceDiscovery) lookup(e *et.Event, fqdn *oamdns.FQDN, since time.Time) []*oamdns.DNSRecordProperty {
    return support.LoadDNSRecordProperties(e.Session, fqdn, t.source, since)
}

// store saves new DNSRecordProperty values.
func (t *txtServiceDiscovery) store(e *et.Event, fqdn *oamdns.FQDN, records []dns.RR) {
    support.StoreDNSRecordProperties(e.Session, fqdn, t.source, records)
}

// process applies regex matchers to TXT strings and emits findings.
func (t *txtServiceDiscovery) process(e *et.Event, fqdn *oamdns.FQDN, txtRecords []dns.RR, props []*oamdns.DNSRecordProperty) {
    findings := make([]*support.Finding, 0)
    var entries []string

    for _, rr := range txtRecords {
        entries = append(entries, strings.Split(rr.String(), "\n")...)
    }
    for _, prop := range props {
        entries = append(entries, prop.Value)
    }

    for _, txt := range entries {
        for pattern, name := range matchers {
            if strings.Contains(txt, pattern) {
                findings = append(findings, &support.Finding{
                    From:     fqdn,
                    FromName: fqdn.Name,
                    To:       fqdn,
                    ToName:   name,
                    ToMeta:   txt,
                    Rel:      support.SimpleRelation("TXT record"),
                })
            }
        }
    }

    support.ProcessAssetsWithSource(e, findings, t.source, t.name, t.name)
}
