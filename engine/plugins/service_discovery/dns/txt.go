// SPDX-License-Identifier: Apache-2.0
// Copyright © Jeff Foley 2017-2025.
//
// Package dns provides a service‑discovery check that inspects cached DNS
// TXT records for third‑party “verification” strings that reveal services in
// use. All log messages go through the engine session logger so they appear
// in the standard enum log file. Each log line carries consistent
// slog.Group metadata (plugin & handler) so you can grep on a single token.
package dns

import (
    "fmt"
    "strings"
    "time"

    "log/slog"

    "github.com/miekg/dns"
    "github.com/owasp-amass/amass/v4/engine/plugins/support"
    et "github.com/owasp-amass/amass/v4/engine/types"
    oamdns "github.com/owasp-amass/open-asset-model/dns"
    "github.com/owasp-amass/open-asset-model/general"
)

const (
    pluginName   = "txt_service_discovery" // kept in‑sync with plugin.go registration
)

// matchers maps TXT‑record substrings to human‑readable service names.
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

// txtServiceDiscovery implements a HandlerFunc registered with the Engine.
type txtServiceDiscovery struct {
    name   string
    source *et.Source
}

// check inspects cached TXT records, builds findings, and logs via
// e.Session.Log() so messages land in the enum log file (same approach as
// company_enrich.go).
func (t *txtServiceDiscovery) check(e *et.Event) error {
    // Build the slog.Group once so every log entry carries identical context.
    lg := func() slog.Logger { return *e.Session.Log() } // helper to satisfy generics
    grp := slog.Group("plugin", "name", pluginName, "handler", t.name)

    if e == nil || e.Entity == nil {
        e.Session.Log().Debug("event or entity is nil – skipping", grp)
        return nil
    }

    entity := e.Entity
    fqdn, ok := entity.Asset.(*oamdns.FQDN)
    if !ok {
        e.Session.Log().Debug("entity is not an FQDN – skipping", grp)
        return nil
    }

    // Determine the TTL window we share with the core DNS‑TXT plugin.
    since, err := support.TTLStartTime(e.Session.Config(), "FQDN", "FQDN", pluginName)
    if err != nil {
        since = time.Now().Add(-24 * time.Hour)
        e.Session.Log().Debug("no TTL config – defaulting to 24h", grp)
    }

    // Pull TXT records from the graph cache.
    var entries []string
    if tags, err := e.Session.Cache().GetEntityTags(entity, since, "dns_record"); err == nil {
        for _, tag := range tags {
            if prop, ok := tag.Property.(*oamdns.DNSRecordProperty); ok && prop.Header.RRType == int(dns.TypeTXT) {
                entries = append(entries, prop.Data)
            }
        }
    } else {
        msg := fmt.Sprintf("cache access error: %v", err)
        e.Session.Log().Error(msg, grp)
    }

    if len(entries) == 0 {
        e.Session.Log().Debug("no TXT records found – nothing to analyse", grp)
        return nil
    }

    // Analyse records.
    var findings []*support.Finding
    for _, txt := range entries {
        for needle, svc := range matchers {
            if strings.Contains(txt, needle) {
                e.Session.Log().Info("service detected via TXT", slog.String("service", svc), slog.String("needle", needle), grp)

                findings = append(findings, &support.Finding{
                    From:     entity,
                    FromName: fqdn.Name,
                    To:       entity,
                    ToName:   svc,
                    ToMeta:   truncate(txt, 180),
                    Rel:      &general.SimpleRelation{Name: "TXT record"},
                })
                break // one match per TXT is plenty
            }
        }
    }

    if len(findings) == 0 {
        e.Session.Log().Debug("no services matched any TXT strings", grp)
        return nil
    }

    e.Session.Log().Info("emitting findings", slog.Int("count", len(findings)), grp)
    support.ProcessAssetsWithSource(e, findings, t.source, t.name, t.name)
    return nil
}

// truncate keeps the first n runes and appends an ellipsis if the input is too long.
func truncate(s string, n int) string {
    if len(s) <= n {
        return s
    }
    return s[:n] + "…"
}
