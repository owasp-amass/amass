package dns

import (
	"log/slog"

	et "github.com/owasp-amass/amass/v4/engine/types"
	"github.com/owasp-amass/amass/v4/requests"
)

const pluginName = "TXT-Service-Discovery"

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

// NewDNSPlugin provides backward compatibility with the plugin loader
func NewDNSPlugin() et.Plugin {
	return NewTXTPlugin()
}

// Name returns the plugin's name
func (tpm *txtPluginManager) Name() string {
	return tpm.name
}

// Start initializes and registers the plugin handlers
func (tpm *txtPluginManager) Start(r et.Registry) error {
	tpm.log = r.Log().WithGroup("plugin").With("name", tpm.name)
	tpm.log.Info("starting TXT service discovery plugin")

	// Initialize the discovery handler
	tpm.discover = &txtServiceDiscovery{
		name:   tpm.name + "-Handler",
		source: tpm.source,
	}

	// Register handler for DNS requests
	if err := tpm.registerHandler(r); err != nil {
		tpm.log.Error("failed to register DNS handler", "error", err)
		return err
	}

	tpm.log.Info("TXT service discovery plugin started successfully")
	return nil
}

// registerHandler registers the plugin handler with the registry
func (tpm *txtPluginManager) registerHandler(r et.Registry) error {
	return r.RegisterHandler(&et.Handler{
		Plugin:   tpm,
		Name:     tpm.discover.name,
		Priority: 9,
		Callback: func(data pipeline.Data) pipeline.Data {
			if req, ok := data.(*requests.DNSRequest); ok {
				return tpm.discover.processDNSRequest(req)
			}
			return data
		},
	})
}

// Stop cleanly shuts down the plugin
func (tpm *txtPluginManager) Stop() {
	if tpm.log != nil {
		tpm.log.Info("TXT service discovery plugin stopped")
	}
}
