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
    if err := r.RegisterHandler(&et.Handler{
        Plugin:     txtDiscovery,
        Name:       txtDiscovery.Name(),
        Priority:   9,
        EventType:  "FQDN", // Replace with the appropriate event type if needed
        Callback:   txtDiscovery.check, // Ensure the `check` method is implemented in txtServiceDiscovery
        MaxInstances: support.MaxHandlerInstances,
    }); err != nil {
        return err
    }

    return nil
}

func (p *dnsPlugin) Stop() {
    // No specific cleanup required for this plugin
}