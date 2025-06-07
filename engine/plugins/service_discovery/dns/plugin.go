// SPDX-License-Identifier: Apache-2.0
// Copyright © Jeff Foley 2017-2025.

package dns

import (
	"log/slog"

	et "github.com/owasp-amass/amass/v4/engine/types"
	oamdns "github.com/owasp-amass/open-asset-model/dns"
)

// txtPluginManager drives the TXT-service-discovery plugin.
type txtPluginManager struct {
	name     string
	log      *slog.Logger
	source   *et.Source
	discover *txtServiceDiscovery
}

/* ---------- factory helpers ---------- */

// NewTXTPlugin is the canonical entry-point looked up by the plugin loader.
func NewTXTPlugin() et.Plugin {
	return &txtPluginManager{
		name: pluginName, // "txt_service_discovery"
		source: &et.Source{
			Name:       pluginName,
			Confidence: 100,
		},
	}
}

// NewDNSPlugin exists for backward compatibility with older loaders.
func NewDNSPlugin() et.Plugin { return NewTXTPlugin() }

/* ---------- et.Plugin interface ---------- */

// Name returns the canonical plugin identifier.
func (tpm *txtPluginManager) Name() string { return tpm.name }

// Start registers the handler with the engine and begins operation.
func (tpm *txtPluginManager) Start(r et.Registry) error {
	// Namespace the logger: every log line begins with  plugin name=txt_service_discovery …
	tpm.log = r.Log().WithGroup("plugin").With("name", tpm.name)

	// Create the handler that does the work.
	tpm.discover = &txtServiceDiscovery{
		name:   tpm.name + "-FQDN-Check", // e.g. txt_service_discovery-FQDN-Check
		source: tpm.source,
	}

	// Register the handler with the registry.
	if err := r.RegisterHandler(&et.Handler{
		Plugin:     tpm,
		Name:       tpm.discover.name,
		Priority:   9,
		Transforms: []string{"DNSRecord"},
		EventType:  (oamdns.FQDN{}).AssetType(),
		Callback:   tpm.discover.check,
	}); err != nil {
		tpm.log.Error("Failed to register handler", "error", err)
		return err
	}

	tpm.log.Info("Plugin started")
	return nil
}

// Stop is invoked by the engine when the plugin is being shut down.
func (tpm *txtPluginManager) Stop() {
	tpm.log.Info("Plugin stopped")
}
