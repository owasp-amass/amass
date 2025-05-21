package dns

import (
    "log"
    "sync"

    "github.com/owasp-amass/amass/v4/engine/plugins/support"
    et "github.com/owasp-amass/amass/v4/engine/types"
    oam "github.com/owasp-amass/open-asset-model"
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
    log.Println("[dnsPlugin] Initializing DNS service discovery plugin manager")
    return &dnsPlugin{
        name:    "dns_service_discovery",
        plugins: []et.Plugin{},
    }
}

// Name implements the Service interface
func (p *dnsPlugin) Name() string {
    log.Printf("[dnsPlugin] Returning plugin name: %s", p.name)
    return p.name
}

// Start implements the Service interface
func (p *dnsPlugin) Start(r et.Registry) error {
    log.Println("[dnsPlugin] Starting DNS service discovery plugin manager")
    p.registry = r

    // Initialize and register the TXT service discovery plugin
    log.Println("[dnsPlugin] Initializing TXT service discovery plugin")
    txtDiscovery := NewTXTServiceDiscovery()
    if err := p.registerHandler(txtDiscovery, 9, oam.FQDN); err != nil {
        log.Printf("[dnsPlugin] Failed to register TXT service discovery plugin: %v", err)
        return err
    }
    log.Println("[dnsPlugin] Successfully registered TXT service discovery plugin")

    return nil
}

// Stop implements the Service interface
func (p *dnsPlugin) Stop() {
    log.Println("[dnsPlugin] Stopping DNS service discovery plugin manager")
    p.pluginMux.Lock()
    defer p.pluginMux.Unlock()

    // Stop all registered plugins
    for _, plugin := range p.plugins {
        log.Printf("[dnsPlugin] Stopping plugin: %s", plugin.Name())
        plugin.Stop()
    }
    p.plugins = []et.Plugin{}
    log.Println("[dnsPlugin] All plugins stopped")
}

// registerHandler registers a plugin as a handler with the registry and adds it to the managed plugins list
func (p *dnsPlugin) registerHandler(plugin et.Plugin, priority int, eventType oam.AssetType) error {
    log.Printf("[dnsPlugin] Registering plugin: %s with priority: %d and event type: %v", plugin.Name(), priority, eventType)
    p.pluginMux.Lock()
    defer p.pluginMux.Unlock()

    // Add the plugin to our managed list
    p.plugins = append(p.plugins, plugin)
    log.Printf("[dnsPlugin] Plugin added to managed list: %s", plugin.Name())

    // Get the appropriate callback function based on plugin type
    var callback func(*et.Event) error
    if txtPlugin, ok := plugin.(*txtServiceDiscovery); ok {
        callback = txtPlugin.Check
        log.Printf("[dnsPlugin] Using Check callback for plugin: %s", plugin.Name())
    } else {
        log.Printf("[dnsPlugin] Plugin type assertion failed for: %s", plugin.Name())
        return nil
    }

    // Register the handler with the registry
    err := p.registry.RegisterHandler(&et.Handler{
        Plugin:       plugin,
        Name:         plugin.Name(),
        Priority:     priority,
        EventType:    eventType,
        Callback:     callback,
        MaxInstances: support.MaxHandlerInstances,
    })
    if err != nil {
        log.Printf("[dnsPlugin] Failed to register handler for plugin: %s, error: %v", plugin.Name(), err)
        return err
    }
    log.Printf("[dnsPlugin] Successfully registered handler for plugin: %s", plugin.Name())

    return nil
}