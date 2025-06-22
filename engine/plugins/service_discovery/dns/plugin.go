package dns

import (
    "context"
    "log/slog"

    "github.com/owasp-amass/amass/v4/engine/registry"
    et "github.com/owasp-amass/amass/v4/engine/types"

    oam    "github.com/owasp-amass/open-asset-model"
    oamdns "github.com/owasp-amass/open-asset-model/dns"
)

// txtServiceDiscoveryPlugin implements et.Plugin.
type txtServiceDiscoveryPlugin struct{ name string }

func NewDNSPlugin() et.Plugin { return &txtServiceDiscoveryPlugin{name: "txt_service_discovery"} }
func (p *txtServiceDiscoveryPlugin) Name() string   { return p.name }
func (p *txtServiceDiscoveryPlugin) Version() string{ return "0.1.1" }

func (p *txtServiceDiscoveryPlugin) Start(ctx context.Context, r *registry.Registry) error {
    // *** Registration – make sure the EventType and the Transform match ***
    if err := r.RegisterHandler(&et.Handler{
        Plugin:     p,
        Name:       p.name,
        Priority:   9,
        Transforms: []string{string(oam.FQDN)}, // ← trailing comma present
        EventType:  oam.FQDN,
        Callback:   p.check,
    }); err != nil {
        return err
    }
    slog.Info("txt_service_discovery: handler registered") // INFO‑level so it appears in your log
    return nil
}
func (p *txtServiceDiscoveryPlugin) Stop() {}

func (p *txtServiceDiscoveryPlugin) check(ctx context.Context, evt *et.Event, pub *et.Publisher) error {
    fqdn, ok := evt.Asset.(oamdns.FQDN)
    if !ok {
        return nil // filtered out
    }

    // ─── Very simple proof‑of‑life ─────────────────────────────────────────────
    slog.Info("txt_service_discovery: received FQDN", "fqdn", fqdn.Name())

    // publish a synthetic “service discovered” event so that we always see at
    // least one INFO line while you develop the real TXT‑parsing logic.
    dummy := oamdns.TXTRecord{
        Record:  "demo=1",
        FQDN:    fqdn,
        Sources: []oam.SourceRef{evt.ID()}, // keeps provenance intact
    }
    pub.Publish(ctx, &et.Event{Asset: dummy})
    return nil
}
