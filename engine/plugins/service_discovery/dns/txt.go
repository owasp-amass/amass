package dns

import (
    "log/slog"
    "strings"
    "time"

    et "github.com/owasp-amass/amass/v4/engine/types"
    oamdns "github.com/owasp-amass/open-asset-model/dns"
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
    return nil
}

// Stop is called when the plugin is stopped (currently does nothing)
func (t *txtServiceDiscovery) Stop() {}

// Check handles the main logic for processing events and discovering services
// Exported to allow access from the registration in plugin.go
func (t *txtServiceDiscovery) Check(e *et.Event) error {
    // Ensure the event and its associated entity are valid
    if e == nil || e.Entity == nil || e.Entity.Asset == nil {
        return nil
    }

    // Extract the FQDN asset from the entity
    fqdn, ok := e.Entity.Asset.(*oamdns.FQDN)
    if !ok {
        return nil
    }

    // Determine the TTL start time for the asset
    since, err := support.TTLStartTime(e.Session.Config(), "FQDN", "FQDN", t.name)
    if err != nil {
        return err
    }

    var txtRecords []dns.RR
    var props []*oamdns.DNSRecordProperty

    // Check if the asset has been monitored within the TTL
    if support.AssetMonitoredWithinTTL(e.Session, e.Entity, t.source, since) {
        // Retrieve cached TXT records
        props = t.lookup(e, fqdn, since)
    } else {
        // Query DNS for TXT records and store them
        txtRecords = t.query(e, fqdn)
        t.store(e, fqdn, txtRecords)
    }

    // Process the TXT records if any were found
    if len(txtRecords) > 0 || len(props) > 0 {
        t.process(e, fqdn, txtRecords, props)
        support.AddDNSRecordType(e, int(dns.TypeTXT))
    }
    return nil
}

// check provides backward compatibility with existing code
func (t *txtServiceDiscovery) check(e *et.Event) error {
    return t.Check(e)
}

// lookup retrieves cached TXT records from the database
func (t *txtServiceDiscovery) lookup(e *et.Event, fqdn *oamdns.FQDN, since time.Time) []*oamdns.DNSRecordProperty {
    var props []*oamdns.DNSRecordProperty

    // Fetch records tagged as "dns_record" from the cache
    if tags, err := e.Session.Cache().GetEntityTags(e.Entity, since, "dns_record"); err == nil {
        for _, tag := range tags {
            // Filter records to include only TXT records
            if prop, ok := tag.Property.(*oamdns.DNSRecordProperty); ok && prop.Header.RRType == int(dns.TypeTXT) {
                props = append(props, prop)
            }
        }
    }

    return props
}

// query performs a DNS query to fetch TXT records for the given FQDN
func (t *txtServiceDiscovery) query(e *et.Event, fqdn *oamdns.FQDN) []dns.RR {
    var txtRecords []dns.RR

    // Perform the DNS query for TXT records
    if rr, err := support.PerformQuery(fqdn.Name, dns.TypeTXT); err == nil {
        txtRecords = append(txtRecords, rr...)
        // Mark the asset as monitored to avoid redundant queries
        support.MarkAssetMonitored(e.Session, e.Entity, t.source)
    }

    return txtRecords
}

// store saves the retrieved TXT records into the database
func (t *txtServiceDiscovery) store(e *et.Event, fqdn *oamdns.FQDN, rr []dns.RR) {
    for _, record := range rr {
        // Ensure the record is of type TXT
        if record.Header().Rrtype != dns.TypeTXT {
            continue
        }

        // Combine the TXT record data into a single string
        txtValue := strings.Join((record.(*dns.TXT)).Txt, " ")
        // Save the record in the database as a DNSRecordProperty
        _, err := e.Session.Cache().CreateEntityProperty(e.Entity, &oamdns.DNSRecordProperty{
            PropertyName: "dns_record",
            Header: oamdns.RRHeader{
                RRType: int(dns.TypeTXT),
                Class:  int(record.Header().Class),
                TTL:    int(record.Header().Ttl),
            },
            Data: txtValue,
        })
        if err != nil {
            slog.Error("Failed to create entity property", "txtValue", txtValue, "error", err)
        }
    }
}

// process analyzes TXT records to identify services based on predefined patterns
func (t *txtServiceDiscovery) process(e *et.Event, fqdn *oamdns.FQDN, txtRecords []dns.RR, props []*oamdns.DNSRecordProperty) {
    // Analyze newly queried TXT records
    for _, record := range txtRecords {
        txtValue := strings.Join((record.(*dns.TXT)).Txt, " ")
        for pattern, serviceName := range matchers {
            if strings.Contains(txtValue, pattern) {
                // Log the discovered service
                slog.Info("Discovered "+serviceName+" service in TXT record",
                    "domain", fqdn.Name,
                    "plugin", t.name)
                break
            }
        }
    }

    // Analyze cached TXT records
    for _, prop := range props {
        for pattern, serviceName := range matchers {
            if strings.Contains(prop.Data, pattern) {
                // Log the discovered service
                slog.Info("Discovered "+serviceName+" service in cached TXT record",
                    "domain", fqdn.Name,
                    "plugin", t.name)
                break
            }
        }
    }
}