package dns

import (
	"log/slog"

	et "github.com/owasp-amass/amass/v4/engine/types"
	oamdns "github.com/owasp-amass/open-asset-model/dns"
)

type txtPluginManager struct {
	name     string
	log      *slog.Logger
	source   *et.Source
	discover *txtServiceDiscovery
}

func NewTXTPlugin() et.Plugin {
	return &txtPluginManager{
		name: pluginName, "txt_service_discovery"
		source: &et.Source{
			Name:       pluginName,
			Confidence: 100,
		},
	}
}

// Back-compat factory.
func NewDNSPlugin() et.Plugin { return NewTXTPlugin() }

func (tpm *txtPluginManager) Start(r et.Registry) error {
	tpm.log = r.Log().WithGroup("plugin").With("name", tpm.name)

	tpm.discover = &txtServiceDiscovery{
		name:   tpm.name + "-FQDN-Check", // "txt_service_discovery-FQDN-Check"
		source: tpm.source,
	}

	return r.RegisterHandler(&et.Handler{
		Plugin:     tpm,
		Name:       tpm.discover.name,
		Priority:   9,
		Transforms: []string{"DNSRecord"},
		EventType:  (oamdns.FQDN{}).AssetType(),
		Callback:   tpm.discover.check,
	})
}

func (tpm *txtPluginManager) Stop() { tpm.log.Info("Plugin stopped") }
