package dns

import (
    "errors"
    "log/slog"
    "time"

    "github.com/miekg/dns"
    "github.com/owasp-amass/amass/v4/engine/plugins/support"
    et "github.com/owasp-amass/amass/v4/engine/types"
    dbt "github.com/owasp-amass/asset-db/types"
    oam "github.com/owasp-amass/open-asset-model"
    oamdns "github.com/owasp-amass/open-asset-model/dns"
    "github.com/owasp-amass/resolve"
)

type dnsTXT struct {
    name   string
    plugin *dnsPlugin
}

func (d *dnsTXT) check(e *et.Event) error {
    slog.Info("txt-info-001: Starting check method", "event", e)
    _, ok := e.Entity.Asset.(*oamdns.FQDN)
    if !ok {
        slog.Error("txt-error-001: failed to extract the FQDN asset", "event", e)
        return errors.New("failed to extract the FQDN asset")
    }

    since, err := support.TTLStartTime(e.Session.Config(), "FQDN", "FQDN", d.plugin.name)
    if err != nil {
        slog.Error("txt-error-002: failed to get TTL start time", "error", err, "event", e)
        return err
    }

    var txtRecords []*resolve.ExtractedAnswer
    src := d.plugin.source
    if support.AssetMonitoredWithinTTL(e.Session, e.Entity, src, since) {
        slog.Info("txt-info-002: Asset monitored within TTL, performing lookup", "event", e)
        txtRecords = d.lookup(e, e.Entity, since)
    } else {
        slog.Info("txt-info-003: Asset not monitored within TTL, performing query", "event", e)
        txtRecords = d.query(e, e.Entity)
    }

    if len(txtRecords) > 0 {
        slog.Info("txt-info-004: TXT records found, processing", "event", e, "txtRecords", txtRecords)
        d.process(e, e.Entity, txtRecords)
    } else {
        slog.Warn("txt-error-003: no TXT records found", "event", e)
    }
    return nil
}

func (d *dnsTXT) lookup(e *et.Event, fqdn *dbt.Entity, since time.Time) []*resolve.ExtractedAnswer {
    slog.Info("txt-info-005: Starting lookup method", "event", e, "fqdn", fqdn, "since", since)
    var txtRecords []*resolve.ExtractedAnswer

    n, ok := fqdn.Asset.(*oamdns.FQDN)
    if !ok || n == nil {
        slog.Error("txt-error-004: failed to cast asset to FQDN", "event", e, "fqdn", fqdn)
        return txtRecords
    }

    if assets := d.plugin.lookupWithinTTL(e.Session, n.Name, oam.FQDN, since, oam.BasicDNSRelation, int(dns.TypeTXT)); len(assets) > 0 {
        for _, a := range assets {
            txtRecords = append(txtRecords, &resolve.ExtractedAnswer{
                Type: dns.TypeTXT,
                Data: a.Asset.(*oamdns.FQDN).Name,
            })
        }
    } else {
        slog.Warn("txt-error-005: no assets found within TTL", "event", e, "fqdn", fqdn)
    }
    return txtRecords
}

func (d *dnsTXT) query(e *et.Event, name *dbt.Entity) []*resolve.ExtractedAnswer {
    slog.Info("txt-info-006: Starting query method", "event", e, "name", name)
    var txtRecords []*resolve.ExtractedAnswer

    fqdn, ok := name.Asset.(*oamdns.FQDN)
    if !ok {
        slog.Error("txt-error-006: failed to cast asset to FQDN in query", "event", e, "name", name)
        return txtRecords
    }

    if rr, err := support.PerformQuery(fqdn.Name, dns.TypeTXT); err == nil {
        txtRecords = append(txtRecords, rr...)
        support.MarkAssetMonitored(e.Session, name, d.plugin.source)
    } else {
        slog.Error("txt-error-007: failed to perform DNS query", "error", err, "event", e, "fqdn", fqdn)
    }

    return txtRecords
}

func (d *dnsTXT) store(e *et.Event, fqdn *dbt.Entity, rr []*resolve.ExtractedAnswer) {
    slog.Info("txt-info-007: Starting store method", "event", e, "fqdn", fqdn, "rr", rr)
    for _, record := range rr {
        if record.Type != dns.TypeTXT {
            continue
        }

        txtValue := record.Data

        _, err := e.Session.Cache().CreateEntityProperty(fqdn, &oamdns.DNSRecordProperty{
            PropertyName: "dns_record",
            Header: oamdns.RRHeader{
                RRType: 16,
                Class:  1,
                TTL:    300,
            },
            Data: txtValue,
        })
        if err != nil {
            slog.Error("txt-error-008: failed to create entity property", "error", err, "event", e, "fqdn", fqdn, "txtValue", txtValue)
        }
    }
}

func (d *dnsTXT) process(e *et.Event, fqdn *dbt.Entity, txtRecords []*resolve.ExtractedAnswer) {
    slog.Info("txt-info-008: Starting process method", "event", e, "fqdn", fqdn, "txtRecords", txtRecords)
    d.store(e, fqdn, txtRecords)

    for _, record := range txtRecords {
        e.Session.Log().Info("TXT record discovered", "fqdn", fqdn.Asset.(*oamdns.FQDN).Name, "txt", record.Data, slog.Group("plugin", "name", d.plugin.name, "handler", d.name))
    }
}