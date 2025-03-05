package dns

import (
    "errors"
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
    tags, err := e.Session.Cache().GetEntityTags(e.Entity, since, t.source.Name)
    if err != nil {
        slog.Error("failed to get entity tags", "error", err)
        return err
    }

    // Mapping of record to names
    matchers := map[string]string{
        "google-site-verification":       "Google",
        "status-page-domain-verification": "StatusPage Domain",
		"facebook-domain-verification=":  "Facebook"
    }

    var foundName string
    for _, tag := range tags {
        if dnsProp, ok := tag.Property.(*oamdns.DNSRecordProperty); ok {
            for pattern, name := range matchers {
                if strings.Contains(dnsProp.Data, pattern) {
                    foundName = name
                    break
                }
            }
            if foundName != "" {
                break
            }
        }
    }

    if foundName != "" {
        slog.Info("Discovered "+foundName+" service in TXT record", "entity", e.Entity)
    }
    return nil
}