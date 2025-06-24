// Copyright © by Jeff Foley 2017-2025.
// SPDX-License-Identifier: Apache-2.0

package dns

import (
	"log/slog"

	et     "github.com/owasp-amass/amass/v4/engine/types"
	oamdns "github.com/owasp-amass/open-asset-model/dns"
	oam    "github.com/owasp-amass/open-asset-model"
)


const pluginName = "txt_"

// txtPluginManager implements the et.Plugin interface.
type txtPluginManager struct {
	name     string
	log      *slog.Logger
	source   *et.Source
	discover *txtServiceDiscovery
}

func NewTXTPlugin() et.Plugin {
	return &txtPluginManager{
		name: pluginName,
		source: &et.Source{
			Name:       pluginName,
			Confidence: 100,
		},
	}
}

func NewDNSPlugin() et.Plugin { return NewTXTPlugin() }

func (tpm *txtPluginManager) Name() string { return tpm.name }

func (tpm *txtPluginManager) Start(r et.Registry) error {
	tpm.log = r.Log().WithGroup("plugin").With("name", tpm.name)

	tpm.discover = &txtServiceDiscovery{
		name:   tpm.name + "-FQDN-Check",
		log:    tpm.log,
		source: tpm.source,
	}

	// Register a handler that receives every FQDN event and, when a match
	// is found, *creates* new Service assets – hence the Service transform.
	if err := r.RegisterHandler(&et.Handler{
		Plugin:     tpm,
		Name:       tpm.discover.name,
		Priority:   9,
		Transforms: []string{string(oam.FQDN)},
		EventType:  (oamdns.FQDN{}).AssetType(),
		Callback:   tpm.discover.check,
	}); err != nil {
		tpm.log.Error("failed to register handler", "error", err)
		return err
	}

	tpm.log.Info("plugin started")
	return nil
}

func (tpm *txtPluginManager) Stop() {
	if tpm.log != nil {
		tpm.log.Info("plugin stopped")
	}
}
