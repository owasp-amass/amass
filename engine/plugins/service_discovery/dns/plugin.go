// engine/plugins/service_discovery/dns/plugin.go
//
// TXT‑based service‑discovery plugin for Amass.
// Discovers service metadata published in DNS TXT records.
//
// Compile‑time checks ensure this file correctly implements the
// github.com/owasp-amass/amass/v4/engine/types.Plugin interface.

package dns

import (
	"context"
	"log/slog"

	"github.com/owasp-amass/amass/v4/engine/registry"
	et "github.com/owasp-amass/amass/v4/engine/types"

	oam    "github.com/owasp-amass/open-asset-model"      // parent OAM package
	oamdns "github.com/owasp-amass/open-asset-model/dns"  // DNS‑specific assets
)

//--------------------------------------------------------------------
// Plugin boiler‑plate
//--------------------------------------------------------------------

// txtServiceDiscoveryPlugin satisfies et.Plugin.
type txtServiceDiscoveryPlugin struct {
	discover *txtServiceDiscovery
}

// Ensure the interface is implemented at compile time.
var _ et.Plugin = (*txtServiceDiscoveryPlugin)(nil)

// NewDNSPlugin must be exported so that the Amass plugin loader can
// construct an instance via reflection.
func NewDNSPlugin() et.Plugin {
	return &txtServiceDiscoveryPlugin{
		discover: &txtServiceDiscovery{
			name: "txt_service_discovery",
		},
	}
}

// Name returns the unique plugin identifier.
func (p *txtServiceDiscoveryPlugin) Name() string { return p.discover.name }

// Version lets Amass expose plugin versions in diagnostics.
func (p *txtServiceDiscoveryPlugin) Version() string { return "0.1.0" }

// Start is called exactly once after construction.
func (p *txtServiceDiscoveryPlugin) Start(
	ctx context.Context,
	r *registry.Registry,
) error {
	// Register a handler that is invoked for every FQDN event.
	err := r.RegisterHandler(&et.Handler{
		Plugin:     p,
		Name:       p.discover.name,
		Priority:   9,                       // run after core DNS handlers
		Transforms: []string{string(oam.FQDN)}, // ← comma present, alias fixed
		EventType:  oam.FQDN,
		Callback:   p.discover.check,
	})
	if err != nil {
		return err
	}

	slog.Debug("txt_service_discovery: handler registered")
	return nil
}

// Stop is called during engine shutdown (nothing to clean up here).
func (p *txtServiceDiscoveryPlugin) Stop() {}

//--------------------------------------------------------------------
// Service‑discovery logic
//--------------------------------------------------------------------

// txtServiceDiscovery holds any shared state required by the handler.
type txtServiceDiscovery struct {
	name string
}

// check inspects a DNS FQDN asset for TXT records that indicate service
// metadata (for example: "_service=api;_version=1").
func (sd *txtServiceDiscovery) check(
	ctx context.Context,
	evt *et.Event,
	pub *et.Publisher,
) error {
	fqdnAsset, ok := evt.Asset.(oamdns.FQDN)
	if !ok {
		// Not the expected asset type – ignore.
		return nil
	}

	// -----------------------------------------------------------------
	// TODO: implement your TXT‑parsing logic here.
	//
	// Example (pseudo‑code):
	//
	// txtRecords := fqdnAsset.TXT()      // or however the OAM exposes them
	// for each record in txtRecords {
	//     if matches your service‑discovery schema {
	//         generate a new Asset or Event and publish it, e.g.:
	//         pub.Publish(ctx, &et.Event{Asset: newAsset, ...})
	//     }
	// }
	// -----------------------------------------------------------------

	_ = fqdnAsset // placeholder so the compiler is happy until you add logic.
	return nil
}
