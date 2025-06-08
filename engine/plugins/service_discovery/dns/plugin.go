// SPDX-License-Identifier: Apache-2.0
// Copyright © Jeff Foley 2017-2025.

package dns

import (
	"log/slog"

	et "github.com/owasp-amass/amass/v4/engine/types"
	oamdns "github.com/owasp-amass/open-asset-model/dns"
)

// txtPluginManager coordinates the TXT-service-discovery plugin.
type txtPluginManager struct {
	name     string
	log      *slog.Logger
	source   *et.Source
	discover *txtServiceDiscovery
}

/* ---------- factory helpers ---------- */

// NewTXTPlugin is the canonical constructor used by load.go.
func NewTXTPlugin() et.Plugin {
	return &txtPluginManager{
		name: pluginName, // constant defined in dns/txt.go
		source: &et.Source{
			Name:       pluginName,
			Confidence: 100,
		},
	}
}

// NewDNSPlugin remains for backward compatibility.
func NewDNSPlugin() et.Plugin { return NewTXTPlugin() }

/* ---------- et.Plugin interface ---------- */

// Name satisfies et.Plugin.
func (tpm *txtPluginManager) Name() string { return tpm.name }

// Start registers the handler with the engine.
func (tpm *txtPluginManager) Start(r et.Registry) error {
	// Create a scoped logger: plugin name=txt_service_discovery …
	tpm.log = r.Log().WithGroup("plugin").With("name", tpm.name)

	// Worker that performs the TXT-record analysis.
	const handlerSuffix = "-FQDN-Check"
	tpm.discover = &txtServiceDiscovery{
		name:   tpm.name + handlerSuffix,
		source: tpm.source,
	}

	// Register the handler.
	if err := r.RegisterHandler(&et.Handler{
		Plugin:     tpm,
		Name:       tpm.discover.name,
		Priority:   9,                      // below core DNS handlers
		Transforms: []string{"DNSRecord"},  // consume DNS-record events only
		EventType:  (oamdns.FQDN{}).AssetType(),
		Callback:   tpm.discover.check,
	}); err != nil {
		tpm.log.Error("failed to register handler", "error", err)
		return err
	}

	tpm.log.Info("plugin started")
	return nil
}

// Stop is called when the engine shuts down.
func (tpm *txtPluginManager) Stop() {
	if tpm.log != nil {
		tpm.log.Info("plugin stopped")
	}
}
