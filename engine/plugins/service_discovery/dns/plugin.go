// SPDX-License-Identifier: Apache-2.0
// Copyright © Jeff Foley 2017-2025.

package dns

import (
	"log/slog"

	et "github.com/owasp-amass/amass/v4/engine/types"
	oamdns "github.com/owasp-amass/open-asset-model/dns"
)

/*
   txtPluginManager – mirrors the structure used by http_probes/plugin.go
*/
type txtPluginManager struct {
	name     string
	log      *slog.Logger
	source   *et.Source
	discover *txtServiceDiscovery
}

/* ---------- factory helpers ---------- */

// NewTXTPlugin is the canonical constructor.
func NewTXTPlugin() et.Plugin {
	return &txtPluginManager{
		name: pluginName, // constant defined in dns/txt.go
		source: &et.Source{
			Name:       pluginName,
			Confidence: 100,
		},
	}
}

// NewDNSPlugin exists only for backward compatibility.
func NewDNSPlugin() et.Plugin { return NewTXTPlugin() }

/* ---------- et.Plugin interface ---------- */

// Name allows the manager to satisfy et.Plugin.
func (tpm *txtPluginManager) Name() string { return tpm.name }

// Start registers the handler with the engine.
func (tpm *txtPluginManager) Start(r et.Registry) error {
	// Namespace logger:  plugin name=txt_service_discovery …
	tpm.log = r.Log().WithGroup("plugin").With("name", tpm.name)

	// Handler that actually does the TXT-record work.
	tpm.discover = &txtServiceDiscovery{
		name:   tpm.name + "-FQDN-Check",
		source: tpm.source,
	}

	// Register with the engine.
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

// Stop is called when the engine shuts down.
func (tpm *txtPluginManager) Stop() { tpm.log.Info("Plugin stopped") }
