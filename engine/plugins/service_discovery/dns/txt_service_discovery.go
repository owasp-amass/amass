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

type txtServiceDiscovery struct {
    name   string
    source *et.Source
}

func NewTXTServiceDiscovery() et.Plugin {
    return &txtServiceDiscovery{
        name: "txt_service_discovery",
        source: &et.Source{
            Name:       "txt_service_discovery",
            Confidence: 100,
        },
    }
}

func (t *txtServiceDiscovery) Name() string {
    return t.name
}

func (t *txtServiceDiscovery) Start(r et.Registry) error {
    return nil
}

func (t *txtServiceDiscovery) Stop() {}

func (t *txtServiceDiscovery) check(e *et.Event) error {
    if e == nil || e.Entity == nil || e.Entity.Asset == nil {
        return nil
    }

    // Extract the FQDN asset from the entity
    fqdn, ok := e.Entity.Asset.(*oamdns.FQDN)
    if !ok {
        return nil
    }

    since, err := support.TTLStartTime(e.Session.Config(), "FQDN", "FQDN", t.name)
    if err != nil {
        return err
    }

    var txtRecords []dns.RR
    var props []*oamdns.DNSRecordProperty
    if support.AssetMonitoredWithinTTL(e.Session, e.Entity, t.source, since) {
        props = t.lookup(e, fqdn, since) // Pass the FQDN asset
    } else {
        txtRecords = t.query(e, fqdn) // Pass the FQDN asset
        t.store(e, fqdn, txtRecords) // Pass the FQDN asset
    }

    if len(txtRecords) > 0 || len(props) > 0 {
        t.process(e, fqdn, txtRecords, props) // Pass the FQDN asset
        support.AddDNSRecordType(e, int(dns.TypeTXT))
    }
    return nil
}

func (t *txtServiceDiscovery) lookup(e *et.Event, fqdn *oamdns.FQDN, since time.Time) []*oamdns.DNSRecordProperty {
    var props []*oamdns.DNSRecordProperty

    if tags, err := e.Session.Cache().GetEntityTags(e.Entity, since, "dns_record"); err == nil {
        for _, tag := range tags {
            if prop, ok := tag.Property.(*oamdns.DNSRecordProperty); ok && prop.Header.RRType == int(dns.TypeTXT) {
                props = append(props, prop)
            }
        }
    }

    return props
}

func (t *txtServiceDiscovery) query(e *et.Event, fqdn *oamdns.FQDN) []dns.RR {
    var txtRecords []dns.RR

    if rr, err := support.PerformQuery(fqdn.Name, dns.TypeTXT); err == nil {
        txtRecords = append(txtRecords, rr...)
        support.MarkAssetMonitored(e.Session, e.Entity, t.source)
    }

    return txtRecords
}

func (t *txtServiceDiscovery) store(e *et.Event, fqdn *oamdns.FQDN, rr []dns.RR) {
    for _, record := range rr {
        if record.Header().Rrtype != dns.TypeTXT {
            continue
        }

        txtValue := strings.Join((record.(*dns.TXT)).Txt, " ")
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

func (t *txtServiceDiscovery) process(e *et.Event, fqdn *oamdns.FQDN, txtRecords []dns.RR, props []*oamdns.DNSRecordProperty) {
    matchers := map[string]string{
        "airtable-verification": "Airtable",
        "aliyun-site-verification": "Aliyun",
        "anodot-domain-verification": "Anodot",
        "apperio-domain-verification": "Apperio",
        "apple-domain-verification": "Apple",
        "atlassian-domain-verification": "Atlassian",
        "bugcrowd-verification": "Bugcrowd",
        "canva-site-verification": "Canva",
        "cisco-ci-domain-verification": "Cisco",
        "cursor-domain-verification-64a3xw": "Cursor",
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

    for _, record := range txtRecords {
        txtValue := strings.Join((record.(*dns.TXT)).Txt, " ")
        for pattern, serviceName := range matchers {
            if strings.Contains(txtValue, pattern) {
                slog.Info("Discovered "+serviceName+" service in TXT record",
                    "domain", fqdn.Name,
                    "plugin", t.name)
                break
            }
        }
    }

    for _, prop := range props {
        for pattern, serviceName := range matchers {
            if strings.Contains(prop.Data, pattern) {
                slog.Info("Discovered "+serviceName+" service in cached TXT record",
                    "domain", fqdn.Name,
                    "plugin", t.name)
                break
            }
        }
    }
}