package dns

import (
	"log/slog"

	et "github.com/owasp-amass/amass/v4/engine/types"
	oamdns "github.com/owasp-amass/open-asset-model/dns"
)

const pluginName = "txt_service_discovery"

type txtPluginManager struct {
	name     string
	log      *slog.Logger
	source   *et.Source
	discover *txtServiceDiscovery
}

func NewDNSPlugin() et.Plugin { // ← constructor the loader calls
	return &txtPluginManager{
		name: pluginName,
		source: &et.Source{
			Name:       pluginName,
			Confidence: 100,
		},
	}
}

// Optional legacy wrapper
func NewTXTPlugin() et.Plugin { return NewDNSPlugin() }

func (tpm *txtPluginManager) Name() string { return tpm.name }

func (tpm *txtPluginManager) Start(r et.Registry) error {
	tpm.log = r.Log().WithGroup("plugin").With("name", tpm.name)

	// Make the source visible to –src / graph users
	if err := r.RegisterSource(tpm.source); err != nil {
		return err
	}

	tpm.discover = &txtServiceDiscovery{
		name:   tpm.name + "-FQDN-Check",
		source: tpm.source,
		//   log: tpm.log,            // handy if txtServiceDiscovery logs
	}

	if err := r.RegisterHandler(&et.Handler{
		Plugin:     tpm,
		Name:       tpm.discover.name,
		Priority:   9,
		Transforms: []string{string((oamdns.FQDN{}).AssetType())},
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
