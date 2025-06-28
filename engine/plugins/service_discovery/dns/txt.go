// SPDX-License-Identifier: Apache-2.0
// Copyright © Jeff Foley 2017-2025.
//
// Package dns provides a service‑discovery check that inspects cached DNS
// TXT records for third‑party “verification” strings that reveal external
// services in use. All log messages are written via e.Session.Log(), just
// like engine/plugins/api/aviato/company_enrich.go, so the output lands in
// the shared enum log file.
package dns

import (
        "strings"
    "time"

    "log/slog"

    "github.com/miekg/dns"
    "github.com/owasp-amass/amass/v4/engine/plugins/support"
    et "github.com/owasp-amass/amass/v4/engine/types"
    oamdns "github.com/owasp-amass/open-asset-model/dns"
    "github.com/owasp-amass/open-asset-model/general"
)

const pluginName = "txt_service_discovery" 

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

type txtServiceDiscovery struct {
    name   string
    source *et.Source
}


func (t *txtServiceDiscovery) check(e *et.Event) error {
    ctxAttr := slog.Group(
        "ctx",
        slog.String("plugin", pluginName),
        slog.String("handler", t.name),
    )


    if e == nil || e.Entity == nil {
        e.Session.Log().Debug("event or entity is nil – skipping", ctxAttr)
        return nil
    }


    entity := e.Entity
    fqdn, ok := entity.Asset.(*oamdns.FQDN)
    if !ok {
        e.Session.Log().Debug("entity is not an FQDN – skipping", ctxAttr)
        return nil
    }


    since, err := support.TTLStartTime(e.Session.Config(), "FQDN", "FQDN", pluginName)
    if err != nil {
        since = time.Now().Add(-24 * time.Hour) // fall‑back window
        e.Session.Log().Debug("no TTL config – defaulting to 24h", ctxAttr)
    }

    var txtEntries []string
    tags, cacheErr := e.Session.Cache().GetEntityTags(entity, since, "dns_record")
    if cacheErr != nil {
        e.Session.Log().Error("cache access error", slog.String("err", cacheErr.Error()), ctxAttr)
    } else {
        for _, tag := range tags {
            if prop, ok := tag.Property.(*oamdns.DNSRecordProperty); ok && prop.Header.RRType == int(dns.TypeTXT) {
                txtEntries = append(txtEntries, prop.Data)
            }
        }
    }

    if len(txtEntries) == 0 {
        e.Session.Log().Debug("no TXT records found – nothing to analyse", ctxAttr)
        return nil
    }


    var findings []*support.Finding
    for _, txt := range txtEntries {
        for needle, svc := range matchers {
            if strings.Contains(txt, needle) {
                e.Session.Log().Info(
                    "service detected via TXT",
                    slog.String("service", svc),
                    slog.String("needle", needle),
                    ctxAttr,
                )

                findings = append(findings, &support.Finding{
                    From:     entity,
                    FromName: fqdn.Name,
                    To:       entity,
                    ToName:   svc,
                    ToMeta:   truncate(txt, 180),
                    Rel:      &general.SimpleRelation{Name: "TXT record"},
                })
                break 
            }
        }
    }

    if len(findings) == 0 {
        e.Session.Log().Debug("no services matched any TXT strings", ctxAttr)
        return nil
    }

    e.Session.Log().Info("emitting findings", slog.Int("count", len(findings)), ctxAttr)
    support.ProcessAssetsWithSource(e, findings, t.source, t.name, t.name)
    return nil
}


func truncate(s string, n int) string {
    if len(s) <= n {
        return s
    }
    return s[:n] + "…"
}