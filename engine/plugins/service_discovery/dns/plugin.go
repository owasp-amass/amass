package dns

import (
    et "github.com/owasp-amass/amass/v4/engine/types"
    "sync"
)

type dnsPlugin struct {
    name      string
    plugins   []et.Plugin
    pluginMux sync.Mutex
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
    p.pluginMux.Lock()
    defer p.pluginMux.Unlock()

    // Initialize and add the TXT service discovery plugin
    txtDiscovery := NewTXTServiceDiscovery()
    r.AddPlugin(txtDiscovery) // Use AddPlugin instead of RegisterPlugin
    p.plugins = append(p.plugins, txtDiscovery)

    return nil
}

func (p *dnsPlugin) Stop() {
    p.pluginMux.Lock()
    defer p.pluginMux.Unlock()

    // Stop all registered plugins
    for _, plugin := range p.plugins {
        plugin.Stop()
    }
    p.plugins = nil
}