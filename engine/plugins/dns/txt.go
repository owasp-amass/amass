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
    "github.com/owasp-amass/open-asset-model/general"
    "github.com/owasp-amass/resolve"
)

type dnsTXT struct {
    name   string
    plugin *dnsPlugin
}

func (d *dnsTXT) check(e *et.Event) error {
    _, ok := e.Entity.Asset.(*oamdns.FQDN)
    if !ok {
        return errors.New("failed to extract the FQDN asset")
    }

    since, err := support.TTLStartTime(e.Session.Config(), "FQDN", "FQDN", d.plugin.name)
    if err != nil {
        return err
    }

    var txtRecords []*resolve.ExtractedAnswer
    src := d.plugin.source
    if support.AssetMonitoredWithinTTL(e.Session, e.Entity, src, since) {
        txtRecords = d.lookup(e, e.Entity, since)
    } else {
        txtRecords = d.query(e, e.Entity)
    }

    if len(txtRecords) > 0 {
        d.process(e, e.Entity, txtRecords)
    }
    return nil
}

func (d *dnsTXT) lookup(e *et.Event, fqdn *dbt.Entity, since time.Time) []*resolve.ExtractedAnswer {
    var txtRecords []*resolve.ExtractedAnswer

    n, ok := fqdn.Asset.(*oamdns.FQDN)
    if !ok || n == nil {
        return txtRecords
    }

    if assets := d.plugin.lookupWithinTTL(e.Session, n.Name, oam.FQDN, since, oam.BasicDNSRelation, dns.TypeTXT); len(assets) > 0 {
        for _, a := range assets {
            txtRecords = append(txtRecords, &resolve.ExtractedAnswer{
                Type: dns.TypeTXT,
                Data: a.Asset.(*oamdns.FQDN).Name,
            })
        }
    }
    return txtRecords
}

func (d *dnsTXT) query(e *et.Event, name *dbt.Entity) []*resolve.ExtractedAnswer {
    var txtRecords []*resolve.ExtractedAnswer

    fqdn := name.Asset.(*oamdns.FQDN)
    if rr, err := support.PerformQuery(fqdn.Name, dns.TypeTXT); err == nil {
        txtRecords = append(txtRecords, rr...)
        support.MarkAssetMonitored(e.Session, name, d.plugin.source)
    }

    return txtRecords
}

func (d *dnsTXT) process(e *et.Event, fqdn *dbt.Entity, txtRecords []*resolve.ExtractedAnswer) {
    for _, record := range txtRecords {
        if record.Type != dns.TypeTXT {
            continue
        }

        _, _ = e.Session.Cache().CreateEntityProperty(fqdn, &oamdns.DNSProperty{
            Name:  "TXT",
            Value: record.Data,
        })

        e.Session.Log().Info("TXT record discovered", "fqdn", fqdn.Asset.(*oamdns.FQDN).Name, "txt", record.Data, slog.Group("plugin", "name", d.plugin.name, "handler", d.name))
    }
}