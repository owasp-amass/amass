// Copyright © by Jeff Foley 2017-2025. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package dns

import (
	"log/slog"

	et "github.com/owasp-amass/amass/v4/engine/types"
	oamdns "github.com/owasp-amass/open-asset-model/dns" // Correct import alias
)

// txtPluginManager wraps the TXT service discovery plugin lifecycle.
type txtPluginManager struct {
	name     string
	log      *slog.Logger
	source   *et.Source
	discover *txtServiceDiscovery
}

// NewTXTPlugin returns a new instance of the TXT service discovery plugin as an et.Plugin.
func NewTXTPlugin() et.Plugin {
	return &txtPluginManager{
		name: "TXT-Service-Discovery",
		source: &et.Source{
			Name:       "TXT-Service-Discovery",
			Confidence: 100,
		},
	}
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
		Plugin:   tpm,
		Name:     tpm.discover.name,
		Priority: 9, // Explicitly set priority to 9
		Transforms: []string{
			"DNSRecord", // Replace with the correct string or remove if unnecessary
		},
		EventType: "FQDN", // Use a string if dns.FQDN is not a valid expression
		Callback:  tpm.discover.check,
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
