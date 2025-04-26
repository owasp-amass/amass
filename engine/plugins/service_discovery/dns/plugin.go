package dns

import (
    "github.com/owasp-amass/amass/v4/engine/plugins/support"
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

    txtDiscovery := NewTXTServiceDiscovery()
    if err := r.RegisterPlugin(txtDiscovery, 9); err != nil {
        return err
    }
    p.plugins = append(p.plugins, txtDiscovery)

    return nil
}

func (p *dnsPlugin) Stop() {
    p.pluginMux.Lock()
    defer p.pluginMux.Unlock()

    for _, plugin := range p.plugins {
        plugin.Stop()
    }
    p.plugins = nil
}