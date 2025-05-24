package dns

import (
    "fmt"
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
    slog.Debug("TXT service discovery plugin started", "plugin", t.name)
    return nil
}

// Stop is called when the plugin is stopped (currently does nothing)
func (t *txtServiceDiscovery) Stop() {
    slog.Debug("TXT service discovery plugin stopped", "plugin", t.name)
}

// Check handles the main logic for processing events and discovering services
// Exported to allow access from the registration in plugin.go
func (t *txtServiceDiscovery) Check(e *et.Event) error {
    slog.Debug("TXT service discovery check started", "plugin", t.name)
    
    // Ensure the event and its associated entity are valid
    if e == nil {
        slog.Debug("Skipping check - event is nil", "plugin", t.name)
        return nil
    }
    if e.Entity == nil {
        slog.Debug("Skipping check - entity is nil", "plugin", t.name)
        return nil
    }
    if e.Entity.Asset == nil {
        slog.Debug("Skipping check - asset is nil", "plugin", t.name)
        return nil
    }

    // Extract the FQDN asset from the entity
    fqdn, ok := e.Entity.Asset.(*oamdns.FQDN)
    if !ok {
        slog.Debug("Skipping check - asset is not FQDN", 
            "plugin", t.name, 
            "assetType", fmt.Sprintf("%T", e.Entity.Asset))
        return nil
    }

    slog.Debug("Processing FQDN", "domain", fqdn.Name, "plugin", t.name)

    // Determine the TTL start time for the asset
    since, err := support.TTLStartTime(e.Session.Config(), "FQDN", "FQDN", t.name)
    err != nil {
        slog.Error("Failed to get TTL start time", 
            "domain", fqdn.Name, 
            "plugin", t.name, 
            "error", err)
        return err
    }
    slog.Debug("TTL start time calculated", 
        "domain", fqdn.Name, 
        "plugin", t.name, 
        "since", since)

    var txtRecords []dns.RR
    var props []*oamdns.DNSRecordProperty

    // Check if the asset has been monitored within the TTL
    if monitored := support.AssetMonitoredWithinTTL(e.Session, e.Entity, t.source, since); monitored {
        slog.Debug("Asset monitored within TTL, retrieving cached records", 
            "domain", fqdn.Name, 
            "plugin", t.name)
        // Retrieve cached TXT records
        props = t.lookup(e, fqdn, since)
        slog.Debug("Retrieved cached TXT records", 
            "domain", fqdn.Name, 
            "plugin", t.name, 
            "recordCount", len(props))
    } else {
        slog.Debug("Asset not monitored within TTL, querying DNS", 
            "domain", fqdn.Name, 
            "plugin", t.name)
        // Query DNS for TXT records and store them
        txtRecords = t.query(e, fqdn)
        slog.Debug("DNS query completed", 
            "domain", fqdn.Name, 
            "plugin", t.name, 
            "recordCount", len(txtRecords))
        
        if len(txtRecords) > 0 {
            slog.Debug("Storing TXT records", 
                "domain", fqdn.Name, 
                "plugin", t.name, 
                "recordCount", len(txtRecords))
            t.store(e, fqdn, txtRecords)
        } else {
            slog.Debug("No TXT records to store", 
                "domain", fqdn.Name, 
                "plugin", t.name)
        }
    }

    // Process the TXT records if any were found
    if len(txtRecords) > 0 || len(props) > 0 {
        slog.Debug("Processing TXT records", 
            "domain", fqdn.Name, 
            "plugin", t.name, 
            "newRecords", len(txtRecords), 
            "cachedRecords", len(props))
        t.process(e, fqdn, txtRecords, props)
        support.AddDNSRecordType(e, int(dns.TypeTXT))
    } else {
        slog.Debug("No TXT records found to process", 
            "domain", fqdn.Name, 
            "plugin", t.name)
    }
    
    slog.Debug("TXT service discovery check completed", 
        "domain", fqdn.Name, 
        "plugin", t.name)
    return nil
}

// check provides backward compatibility with existing code
func (t *txtServiceDiscovery) check(e *et.Event) error {
    return t.Check(e)
}

// lookup retrieves cached TXT records from the database
func (t *txtServiceDiscovery) lookup(e *et.Event, fqdn *oamdns.FQDN, since time.Time) []*oamdns.DNSRecordProperty {
    slog.Debug("Looking up cached TXT records", 
        "domain", fqdn.Name, 
        "plugin", t.name,
        "since", since)
        
    var props []*oamdns.DNSRecordProperty

    // Fetch records tagged as "dns_record" from the cache
    tags, err := e.Session.Cache().GetEntityTags(e.Entity, since, "dns_record")
    if err != nil {
        slog.Error("Failed to retrieve entity tags", 
            "domain", fqdn.Name, 
            "plugin", t.name, 
            "error", err)
        return props
    }
    
    slog.Debug("Retrieved entity tags", 
        "domain", fqdn.Name, 
        "plugin", t.name, 
        "tagCount", len(tags))

    // Filter records to include only TXT records
    for i, tag := range tags {
        prop, ok := tag.Property.(*oamdns.DNSRecordProperty)
        if !ok {
            slog.Debug("Skipping non-DNSRecordProperty tag", 
                "domain", fqdn.Name, 
                "plugin", t.name, 
                "tagIndex", i,
                "propertyType", fmt.Sprintf("%T", tag.Property))
            continue
        }
        
        if prop.Header.RRType != int(dns.TypeTXT) {
            slog.Debug("Skipping non-TXT DNS record", 
                "domain", fqdn.Name, 
                "plugin", t.name, 
                "tagIndex", i,
                "rrType", prop.Header.RRType)
            continue
        }
        
        props = append(props, prop)
        slog.Debug("Found cached TXT record", 
            "domain", fqdn.Name, 
            "plugin", t.name, 
            "tagIndex", i,
            "data", prop.Data)
    }

    slog.Debug("Lookup completed", 
        "domain", fqdn.Name, 
        "plugin", t.name, 
        "recordCount", len(props))
    return props
}

// query performs a DNS query to fetch TXT records for the given FQDN
func (t *txtServiceDiscovery) query(e *et.Event, fqdn *oamdns.FQDN) []dns.RR {
    slog.Debug("Starting DNS query for TXT records", 
        "domain", fqdn.Name, 
        "plugin", t.name)
    
    var txtRecords []dns.RR

    // Perform the DNS query for TXT records
    rr, err := support.PerformQuery(fqdn.Name, dns.TypeTXT)
    if err != nil {
        slog.Error("DNS query failed", 
            "domain", fqdn.Name, 
            "plugin", t.name, 
            "error", err)
        return txtRecords
    }
    
    txtRecords = append(txtRecords, rr...)
    slog.Debug("DNS query successful", 
        "domain", fqdn.Name, 
        "plugin", t.name, 
        "recordCount", len(txtRecords))
    
    // Mark the asset as monitored to avoid redundant queries
    support.MarkAssetMonitored(e.Session, e.Entity, t.source)
    slog.Debug("Asset marked as monitored", 
        "domain", fqdn.Name, 
        "plugin", t.name)

    return txtRecords
}

// store saves the retrieved TXT records into the database
func (t *txtServiceDiscovery) store(e *et.Event, fqdn *oamdns.FQDN, rr []dns.RR) {
    slog.Debug("Storing TXT records", 
        "domain", fqdn.Name, 
        "plugin", t.name, 
        "recordCount", len(rr))
    
    recordsStored := 0
    for i, record := range rr {
        // Ensure the record is of type TXT
        if record.Header().Rrtype != dns.TypeTXT {
            slog.Debug("Skipping non-TXT record", 
                "domain", fqdn.Name, 
                "plugin", t.name, 
                "recordIndex", i,
                "recordType", record.Header().Rrtype)
            continue
        }

        // Combine the TXT record data into a single string
        txtValue := strings.Join((record.(*dns.TXT)).Txt, " ")
        slog.Debug("Storing TXT record", 
            "domain", fqdn.Name, 
            "plugin", t.name, 
            "recordIndex", i,
            "value", txtValue)
            
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
            slog.Error("Failed to create entity property", 
                "domain", fqdn.Name,
                "plugin", t.name,
                "txtValue", txtValue, 
                "error", err)
        } else {
            recordsStored++
            slog.Debug("TXT record stored successfully", 
                "domain", fqdn.Name,
                "plugin", t.name,
                "recordIndex", i)
        }
    }
    
    slog.Debug("TXT record storage completed", 
        "domain", fqdn.Name, 
        "plugin", t.name,
        "recordsStored", recordsStored)
}

// process analyzes TXT records to identify services based on predefined patterns
func (t *txtServiceDiscovery) process(e *et.Event, fqdn *oamdns.FQDN, txtRecords []dns.RR, props []*oamdns.DNSRecordProperty) {
    slog.Debug("Starting TXT record processing", 
        "domain", fqdn.Name, 
        "plugin", t.name,
        "newRecords", len(txtRecords),
        "cachedRecords", len(props))

    // Analyze newly queried TXT records
    for i, record := range txtRecords {
        txtValue := strings.Join((record.(*dns.TXT)).Txt, " ")
        slog.Debug("Analyzing TXT record", 
            "domain", fqdn.Name, 
            "plugin", t.name,
            "recordIndex", i,
            "value", txtValue)
            
        matchFound := false
        for pattern, serviceName := range matchers {
            if strings.Contains(txtValue, pattern) {
                matchFound = true
                // Log the discovered service
                slog.Info("Discovered "+serviceName+" service in TXT record",
                    "domain", fqdn.Name,
                    "plugin", t.name,
                    "pattern", pattern,
                    "txtValue", txtValue)
                break
            }
        }
        
        if !matchFound {
            slog.Debug("No service pattern matches in TXT record", 
                "domain", fqdn.Name,
                "plugin", t.name,
                "txtValue", txtValue)
        }
    }

    // Analyze cached TXT records
    for i, prop := range props {
        slog.Debug("Analyzing cached TXT record", 
            "domain", fqdn.Name, 
            "plugin", t.name,
            "recordIndex", i,
            "value", prop.Data)
            
        matchFound := false
        for pattern, serviceName := range matchers {
            if strings.Contains(prop.Data, pattern) {
                matchFound = true
                // Log the discovered service
                slog.Info("Discovered "+serviceName+" service in cached TXT record",
                    "domain", fqdn.Name,
                    "plugin", t.name,
                    "pattern", pattern,
                    "txtValue", prop.Data)
                break
            }
        }
        
        if !matchFound {
            slog.Debug("No service pattern matches in cached TXT record", 
                "domain", fqdn.Name,
                "plugin", t.name,
                "txtValue", prop.Data)
        }
    }
    
    slog.Debug("Completed TXT record processing", 
        "domain", fqdn.Name, 
        "plugin", t.name)
}