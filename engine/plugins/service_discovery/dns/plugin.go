// Copyright © by Jeff Foley 2017-2025. All rights 
// reserved. Use of this source code is governed by Apache 
// 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package dns

import (
	"log/slog"

	et "github.com/owasp-amass/amass/v4/engine/types"
	oamdns "github.com/owasp-amass/open-asset-model/dns"
)

// txtPluginManager wraps the TXT service discovery plugin lifecycle.
type txtPluginManager struct {
	name     string
	log      *slog.Logger
	source   *et.Source
	discover *txt_service_discovery
}

// NewTXTPlugin returns a new instance of the TXT service discovery plugin.
func NewTXTPlugin() et.Plugin {
	return &txtPluginManager{
		name: "txt_service_discovery",
		source: &et.Source{
			Name:       "txt_service_discovery",
			Confidence: 100,
		},
	}
}

// NewDNSPlugin is provided for backward compatibility with the plugin loader.
// It simply returns the TXT plugin under the original DNS‐plugin factory name.
func NewDNSPlugin() et.Plugin {
	return NewTXTPlugin()
}

// Name returns the plugin's name.
func (tpm *txtPluginManager) Name() string {
	return tpm.name
}

// Start registers the plugin handler with the registry.
func (tpm *txtPluginManager) Start(r et.Registry) error {
	tpm.log = r.Log().WithGroup("plugin").With("name", tpm.name)

	tpm.discover = &txtServiceDiscovery{
		name:   tpm.name + "-FQDN-Check",
		source: tpm.source,
	}

	err := r.RegisterHandler(&et.Handler{
		Plugin:     tpm,
		Name:       tpm.discover.name,
		Priority:   9,
		Transforms: []string{"DNSRecord"},
		EventType:  (oamdns.FQDN{}).AssetType(),
		Callback:   tpm.discover.check,
	})
	if err != nil {
		return err
	}

	tpm.log.Info("Plugin started")
	return nil
}

// Stop logs that the plugin has stopped.
func (tpm *txtPluginManager) Stop() {
	tpm.log.Info("Plugin stopped")
}
