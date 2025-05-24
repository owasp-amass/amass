package dns

import (
    "fmt"
    "log/slog"
    "strings"
    "time"

    et "github.com/owasp-amass/amass/v4/engine/types"
    oamdns "github.com/owasp-amass/open-asset-model/dns"
    oam "github.com/owasp-amass/open-asset-model"
    "github.com/miekg/dns"
    "github.com/owasp-amass/amass/v4/engine/plugins/support"
)

// matchers defines patterns to match specific services based on TXT records
var matchers = map[string]string{
    "airtable-verification": "Airtable",
    "aliyun-site-verification": "Aliyun",
    "anodot-domain-verification": "Anodot",
    "apperio-domain-verification": "Apperio",
    "apple-domain-verification": "Apple",
    "atlassian-domain-verification": "Atlassian",
    "bugcrowd-verification": "Bugcrowd",
    "canva-site-verification": "Canva",
    "cisco-ci-domain-verification": "Cisco",
    "cursor-domain-verification": "Cursor",
    "docusign=": "Docusign",
    "dropbox-domain-verification": "Dropbox",
    "facebook-domain-verification": "Facebook",
    "globalsign-smime-dv": "Globalsign",
    "google-site-verification": "Google",
    "hubspot-developer-verification": "HubSpot",
    "knowbe4-site-verification": "Knowbe4",
    "krisp-domain-verification": "Krisp",
    "lastpass-verification-code": "Lastpass",
    "mailru-verification": "Mailru",
    "miro-verification": "Miro",
    "mongodb-site-verification": "MongoDB",
    "notion-domain-verification": "Notion",
    "onetrust-domain-verification": "OneTrust",
    "openai-domain-verification": "OpenAI",
    "pendo-domain-verification": "Pendo",
    "postman-domain-verification": "Postman",
    "segment-site-verification": "Segment",
    "status-page-domain-verification": "StatusPage",
    "stripe-verification": "Stripe",
    "twilio-domain-verification": "Twilio",
    "yahoo-verification-key": "Yahoo",
    "yandex-verification": "Yandex",
    "zoom-domain-verification": "Zoom",
}

// txtServiceDiscovery defines the structure of the plugin
type txtServiceDiscovery struct {
    name   string
    source *et.Source
}

// NewTXTServiceDiscovery initializes and returns a new instance of the plugin
func NewTXTServiceDiscovery() et.Plugin {
    return &txtServiceDiscovery{
        name: "txt_service_discovery",
        source: &et.Source{
            Name:       "txt_service_discovery",
            Confidence: 100,
        },
    }
}

// Name returns the name of the plugin
func (t *txtServiceDiscovery) Name() string {
    return t.name
}

// Start is called when the plugin is started (currently does nothing)
func (t *txtServiceDiscovery) Start(r et.Registry) error {
    slog.Debug("TXT service discovery plugin started", "plugin", t.name)
    return nil
}

// Stop is called when the plugin is stopped (currently does nothing)
func (t *txtServiceDiscovery) Stop() {
    slog.Debug("TXT service discovery plugin stopped", "plugin", t.name)
}

// Check handles the main logic for processing events and discovering services
func (t *txtServiceDiscovery) Check(e *et.Event) error {
    slog.Debug("TXT service discovery check started", "plugin", t.name)

    // Ensure the event and its associated entity are valid
    if e == nil || e.Entity == nil || e.Entity.Asset == nil {
        slog.Debug("Skipping check - invalid event or entity", "plugin", t.name)
        return nil
    }

    // Extract the FQDN asset from the entity
    fqdn, ok := e.Entity.Asset.(*oamdns.FQDN)
    if !ok {
        slog.Debug("Skipping check - asset is not FQDN", "plugin", t.name, "assetType", fmt.Sprintf("%T", e.Entity.Asset))
        return nil
    }

    slog.Debug("Processing FQDN", "domain", fqdn.Name, "plugin", t.name)

    // Determine the TTL start time for the asset
    since, err := support.TTLStartTime(e.Session.Config(), "FQDN", "FQDN", t.name)
    if err != nil {
        slog.Error("Failed to get TTL start time", "domain", fqdn.Name, "plugin", t.name, "error", err)
        return err
    }
    slog.Debug("TTL start time calculated", "domain", fqdn.Name, "plugin", t.name, "since", since)

    var txtRecords []dns.RR
    var props []*oamdns.DNSRecordProperty

    // Check if the asset has been monitored within the TTL
    if monitored := support.AssetMonitoredWithinTTL(e.Session, e.Entity, t.source, since); monitored {
        slog.Debug("Asset monitored within TTL, retrieving cached records", "domain", fqdn.Name, "plugin", t.name)
        props = t.lookup(e, fqdn, since)
        slog.Debug("Retrieved cached TXT records", "domain", fqdn.Name, "plugin", t.name, "recordCount", len(props))
    } else {
        slog.Debug("Asset not monitored within TTL, querying DNS", "domain", fqdn.Name, "plugin", t.name)
        txtRecords = t.query(e, fqdn)
        slog.Debug("DNS query completed", "domain", fqdn.Name, "plugin", t.name, "recordCount", len(txtRecords))

        if len(txtRecords) > 0 {
            slog.Debug("Storing TXT records", "domain", fqdn.Name, "plugin", t.name, "recordCount", len(txtRecords))
            t.store(e, fqdn, txtRecords)
        } else {
            slog.Debug("No TXT records to store", "domain", fqdn.Name, "plugin", t.name)
        }
    }

    // Process the TXT records if any were found
    if len(txtRecords) > 0 || len(props) > 0 {
        slog.Debug("Processing TXT records", "domain", fqdn.Name, "plugin", t.name, "newRecords", len(txtRecords), "cachedRecords", len(props))
        t.process(e, fqdn, txtRecords, props)
        support.AddDNSRecordType(e, int(dns.TypeTXT))
    } else {
        slog.Debug("No TXT records found to process", "domain", fqdn.Name, "plugin", t.name)
    }

    slog.Debug("TXT service discovery check completed", "domain", fqdn.Name, "plugin", t.name)
    return nil
}

// check provides backward compatibility with existing code
func (t *txtServiceDiscovery) check(e *et.Event) error {
    return t.Check(e)
}