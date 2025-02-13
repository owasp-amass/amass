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

type relTXT struct {
    txt    *dbt.Entity
    target *dbt.Entity
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

    var txtRecords []*relTXT
    src := d.plugin.source
    if support.AssetMonitoredWithinTTL(e.Session, e.Entity, src, since) {
        txtRecords = append(txtRecords, d.lookup(e, e.Entity, since)...)
    } else {
        txtRecords = append(txtRecords, d.query(e, e.Entity)...)
    }

    if len(txtRecords) > 0 {
        d.process(e, txtRecords)
    }
    return nil
}

func (d *dnsTXT) lookup(e *et.Event, fqdn *dbt.Entity, since time.Time) []*relTXT {
    var txtRecords []*relTXT

    n, ok := fqdn.Asset.(*oamdns.FQDN)
    if !ok || n == nil {
        return txtRecords
    }

    if assets := d.plugin.lookupWithinTTL(e.Session, n.Name, oam.FQDN, since, oam.BasicDNSRelation, 5); len(assets) > 0 {
        for _, a := range assets {
            txtRecords = append(txtRecords, &relTXT{txt: fqdn, target: a})
        }
    }
    return txtRecords
}

func (d *dnsTXT) query(e *et.Event, name *dbt.Entity) []*relTXT {
    var txtRecords []*relTXT

    fqdn := name.Asset.(*oamdns.FQDN)
    if rr, err := support.PerformQuery(fqdn.Name, dns.TypeTXT); err == nil {
        if records := d.store(e, name, rr); len(records) > 0 {
            txtRecords = append(txtRecords, records...)
            support.MarkAssetMonitored(e.Session, name, d.plugin.source)
        }
    }

    return txtRecords
}

func (d *dnsTXT) store(e *et.Event, fqdn *dbt.Entity, rr []*resolve.ExtractedAnswer) []*relTXT {
    var txtRecords []*relTXT

    for _, record := range rr {
        if record.Type != dns.TypeTXT {
            continue
        }

        if txt, err := e.Session.Cache().CreateAsset(&oamdns.FQDN{Name: record.Data}); err == nil && txt != nil {
            if edge, err := e.Session.Cache().CreateEdge(&dbt.Edge{
                Relation: &oamdns.BasicDNSRelation{
                    Name: "dns_record",
                    Header: oamdns.RRHeader{
                        RRType: int(record.Type),
                        Class:  1,
                    },
                },
                FromEntity: fqdn,
                ToEntity:   txt,
            }); err == nil && edge != nil {
                txtRecords = append(txtRecords, &relTXT{txt: fqdn, target: txt})
                _, _ = e.Session.Cache().CreateEdgeProperty(edge, &general.SourceProperty{
                    Source:     d.plugin.source.Name,
                    Confidence: d.plugin.source.Confidence,
                })
            }
        }
    }

    return txtRecords
}

func (d *dnsTXT) process(e *et.Event, txtRecords []*relTXT) {
    for _, a := range txtRecords {
        target := a.target.Asset.(*oamdns.FQDN)

        _ = e.Dispatcher.DispatchEvent(&et.Event{
            Name:    target.Name,
            Entity:  a.target,
            Session: e.Session,
        })

        e.Session.Log().Info("relationship discovered", "from", d.plugin.source.Name, "relation",
            "txt_record", "to", target.Name, slog.Group("plugin", "name", d.plugin.name, "handler", d.name))
    }
}