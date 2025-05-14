package dns

import (
    "github.com/owasp-amass/amass/v4/engine/plugins/support"
    et "github.com/owasp-amass/amass/v4/engine/types"
)

type dnsPlugin struct {
    name string
}

func NewDNSPlugin() et.Plugin {
    return &dnsPlugin{
        name: "dns_service_discovery",
    }
}

func (p *dnsPlugin) Name() string {
    return p.name
}

func (p *dnsPlugin) Start(r et.Registry) error {
    // Register the TXT service discovery plugin with priority 9
    txtDiscovery := NewTXTServiceDiscovery()
    
    // The proper way to register the handler with the Check method
    if err := r.RegisterHandler(&et.Handler{
        Plugin:       txtDiscovery,
        Name:         txtDiscovery.Name(),
        Priority:     9,
        EventType:    "FQDN",
        Callback:     txtDiscovery.(*txtServiceDiscovery).Check, // Use the exported Check method
        MaxInstances: support.MaxHandlerInstances,
    }); err != nil {
        return err
    }

    return nil
}

func (p *dnsPlugin) Stop() {
    // No specific cleanup required for this plugin
}