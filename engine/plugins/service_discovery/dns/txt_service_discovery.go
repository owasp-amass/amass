package dns

import (
    "log/slog"
    "strings"
    "time"

    et "github.com/owasp-amass/amass/v4/engine/types"
    dbt "github.com/owasp-amass/asset-db/types"
    oamdns "github.com/owasp-amass/open-asset-model/dns"
    "github.com/owasp-amass/amass/v4/engine/plugins/support"
)

type txtServiceDiscovery struct {
    name   string
    source *et.Source
}

func NewTXTServiceDiscovery() et.Plugin {
    return &txtServiceDiscovery{
        name: "txt_service_discovery",
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
    since := time.Time{}

    // Use the exported type or constructor from the dns plugin
    txtPlugin := &dnsTXT{
        name:   "dnsTXT",
        source: t.source,
    }

    // Use the dnsTXT lookup method to fetch TXT records
    txtRecords := txtPlugin.lookup(e, e.Entity, since)

    matchers := map[string]string{
        "google-site-verification":        "Google",
        "status-page-domain-verification": "StatusPage Domain",
        "facebook-domain-verification=":   "Facebook",
    }

    var foundName string
    for _, rec := range txtRecords {
        for pattern, serviceName := range matchers {
            if strings.Contains(rec.Data, pattern) {
                foundName = serviceName
                break
            }
        }
        if foundName != "" {
            break
        }
    }

    if foundName != "" {
        slog.Info("Discovered "+foundName+" service in TXT record", "entity", e.Entity)
    }
    return nil
}