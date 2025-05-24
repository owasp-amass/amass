// engine/plugins/service_discovery/dns/plugin.go
// Updated to align with http_probes plugin structure and logging conventions.
// SPDX-License-Identifier: Apache-2.0

package dns

import (
    "log/slog"
    "sync"

    "github.com/owasp-amass/amass/v4/engine/plugins/support"
    et "github.com/owasp-amass/amass/v4/engine/types"
    oam "github.com/owasp-amass/open-asset-model"
)

// dnsPlugin manages DNS‑based service‑discovery sub‑plugins (e.g. TXT).
// It follows the same skeleton used by service_discovery/http_probes/plugin.go
// so that logging, lifecycle and handler‑registration behaviours are consistent
// across discovery stacks.

type dnsPlugin struct {
    name     string
    source   *et.Source

    // runtime state
    registry et.Registry
    log      *slog.Logger

    // child plugins that this manager started & must stop
    plugins []et.Plugin
    mu      sync.Mutex
}

// NewDNSPlugin instantiates the manager so it can be wired into engine/plugins/load.go.
func NewDNSPlugin() et.Plugin {
    return &dnsPlugin{
        name: "dns_service_discovery",
        source: &et.Source{
            Name:       "dns_service_discovery",
            Confidence: 100,
        },
    }
}

// Name implements et.Plugin.
func (p *dnsPlugin) Name() string { return p.name }

// Start initialises the manager and registers handlers for its children.
func (p *dnsPlugin) Start(r et.Registry) error {
    p.registry = r
    p.log = r.Log().WithGroup("plugin").With("name", p.name)

    // --- register TXT‑based discovery --------------------------------------
    txt := NewTXTServiceDiscovery()
    if err := p.registerHandler(txt, 9, oam.FQDN); err != nil {
        p.log.Error("could not register TXT discovery handler", "err", err)
        return err
    }

    p.log.Info("DNS service‑discovery manager started")
    return nil
}

// Stop terminates all children and releases resources.
func (p *dnsPlugin) Stop() {
    p.mu.Lock()
    defer p.mu.Unlock()

    for _, child := range p.plugins {
        p.log.Info("stopping child plugin", "child", child.Name())
        child.Stop()
    }
    p.plugins = nil
    p.log.Info("DNS service‑discovery manager stopped")
}

// registerHandler wraps a child plugin in an et.Handler and registers it.
func (p *dnsPlugin) registerHandler(child et.Plugin, priority int, evt oam.AssetType) error {
    // capture the child’s Check method if it has one.
    var cb func(*et.Event) error
    switch v := any(child).(type) {
    case interface{ Check(*et.Event) error }:
        cb = v.Check
    default:
        // Child does not expose event processing; still add to list so we can Stop() it.
        p.log.Warn("child plugin exposes no Check method – handler not registered", "child", child.Name())
        return nil
    }

    // remember to Stop() later
    p.mu.Lock()
    p.plugins = append(p.plugins, child)
    p.mu.Unlock()

    return p.registry.RegisterHandler(&et.Handler{
        Plugin:       child,
        Name:         child.Name(),
        Priority:     priority,
        EventType:    evt,
        Callback:     cb,
        MaxInstances: support.MaxHandlerInstances,
    })
}
