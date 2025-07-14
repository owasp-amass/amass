package dns

import (
	"log/slog"

	et "github.com/owasp-amass/amass/v5/engine/types"
	oam "github.com/owasp-amass/open-asset-model"
)

const pluginName = "txt_service_discovery"

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

func (tpm *txtPluginManager) Name() string { return tpm.name }

func (tpm *txtPluginManager) Start(r et.Registry) error {
	tpm.log = r.Log().WithGroup("plugin").With("name", tpm.name)

	const handlerSuffix = "-FQDN-Check"
	tpm.discover = &txtServiceDiscovery{
		name:   tpm.name + handlerSuffix,
		source: tpm.source,
	}

	if err := r.RegisterHandler(&et.Handler{
		Plugin:     tpm,
		Name:       tpm.discover.name,
		Priority:   9,
		Transforms: []string{string(oam.FQDN)},
		EventType:  oam.FQDN,
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