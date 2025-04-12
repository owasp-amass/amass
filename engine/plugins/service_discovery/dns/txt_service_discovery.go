package dns

import (
    "log/slog"
    "strings"
    "time"

    et "github.com/owasp-amass/amass/v4/engine/types"
    oamdns "github.com/owasp-amass/open-asset-model/dns"
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
    since := time.Time{} // Get all TXT records
    
    // Get entity tags that contain TXT records
    tags, err := e.Session.Cache().GetEntityTags(e.Entity, since, "dns_record")
    if err != nil {
        return err
    }
    
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
    
    var foundName string
    // Process each tag to find TXT records
    for _, tag := range tags {
        if prop, ok := tag.Property.(*oamdns.DNSRecordProperty); ok {
            // Check if it's a TXT record (type 16)
            if prop.Header.RRType == 16 {
                // Check for service patterns in the TXT record data
                for pattern, serviceName := range matchers {
                    if strings.Contains(prop.Data, pattern) {
                        foundName = serviceName
                        break
                    }
                }
                if foundName != "" {
                    break
                }
            }
        }
    }
    
    if foundName != "" {
        fqdn, _ := e.Entity.Asset.(*oamdns.FQDN)
        domainName := "unknown"
        if fqdn != nil {
            domainName = fqdn.Name
        }
        slog.Info("Discovered "+foundName+" service in TXT record", 
            "domain", domainName,
            "plugin", t.name)
    }
    return nil
}