package dns

import (
    "sync"

    "github.com/owasp-amass/amass/v4/engine/plugins/support"
    et "github.com/owasp-amass/amass/v4/engine/types"
)

// dnsPlugin manages DNS-based service discovery plugins
type dnsPlugin struct {
    name      string
    registry  et.Registry
    plugins   []et.Plugin
    pluginMux sync.Mutex
}

// NewDNSPlugin returns an initialized DNS service discovery plugin manager
func NewDNSPlugin() et.Plugin {
    return &dnsPlugin{
        name:    "dns_service_discovery",
        plugins: []et.Plugin{},
    }
}

// Name implements the Service interface
func (p *dnsPlugin) Name() string {
    return p.name
}

// Start implements the Service interface
func (p *dnsPlugin) Start(r et.Registry) error {
    p.registry = r
    
    // Initialize and register the TXT service discovery plugin
    txtDiscovery := NewTXTServiceDiscovery()
    if err := p.registerHandler(txtDiscovery, 9, "FQDN"); err != nil {
        return err
    }
    
    return nil
}

// Stop implements the Service interface
func (p *dnsPlugin) Stop() {
    p.pluginMux.Lock()
    defer p.pluginMux.Unlock()
    
    // Stop all registered plugins
    for _, plugin := range p.plugins {
        plugin.Stop()
    }
    p.plugins = []et.Plugin{}
}

// registerHandler registers a plugin as a handler with the registry and adds it to the managed plugins list
func (p *dnsPlugin) registerHandler(plugin et.Plugin, priority int, eventType string) error {
    p.pluginMux.Lock()
    defer p.pluginMux.Unlock()
    
    // Add the plugin to our managed list
    p.plugins = append(p.plugins, plugin)
    
    // Get the appropriate callback function based on plugin type
    var callback et.HandlerCallback
    if txtPlugin, ok := plugin.(*txtServiceDiscovery); ok {
        callback = txtPlugin.Check
    } else {
        return nil
    }
    
    // Register the handler with the registry
    return p.registry.RegisterHandler(&et.Handler{
        Plugin:       plugin,
        Name:         plugin.Name(),
        Priority:     priority,
        EventType:    eventType,
        Callback:     callback,
        MaxInstances: support.MaxHandlerInstances,
    })
}