// SPDX-License-Identifier: Apache-2.0
// Copyright © OWASP Amass Project

package dns

import (
	"context"
	"log/slog"

	"github.com/owasp-amass/engine/enum"
	et "github.com/owasp-amass/engine/enum/transform"
	oamdns "github.com/owasp-amass/engine/model/dns"
)

// discoverPlugin ties the handler and its state together.
type discoverPlugin struct {
	log      *slog.Logger
	discover *txtServiceDiscovery
}

// New constructs the TXT-service-discovery plugin and registers its handler.
func New(ctx context.Context, r *enum.Enum) error {
	plugin := &discoverPlugin{
		log:      slog.Default().With("plugin", "txt_service_discovery"),
		discover: &txtServiceDiscovery{},
	}

	// Register the handler.
	if err := r.RegisterHandler(&et.Handler{
		Plugin:   plugin,
		Name:     plugin.discover.name,
		Priority: 9,
		// ————— MINIMAL FIX —————
		// Fire after the basic FQDN transform has run, so our handler is invoked.
		Transforms: []string{(oamdns.FQDN{}).AssetType()},
		// ————————————————
		EventType: (oamdns.FQDN{}).AssetType(),
		Callback:  plugin.discover.check,
	}); err != nil {
		plugin.log.Error("failed to register handler", "error", err)
		return err
	}
	return nil
}

// txtServiceDiscovery implements the DNS-TXT inspection logic.
type txtServiceDiscovery struct {
	name string
}

// name returns the plugin’s canonical name.
func (t *txtServiceDiscovery) Name() string {
	if t.name == "" {
		t.name = "dns_txt_service_discovery"
	}
	return t.name
}

// check is invoked for every FQDN after the FQDN transform.
func (t *txtServiceDiscovery) check(ctx context.Context, r *enum.Enum, fqdn *oamdns.FQDN) error {
	log := slog.Default().With(
		slog.Group("plugin", "name", t.Name(), "handler", "check"),
		"domain", fqdn.Name,
	)

	log.Info("processing FQDN for TXT service discovery")

	records := fqdn.Records("TXT")
	if len(records) == 0 {
		return nil
	}

	for _, rec := range records {
		log.Debug("evaluating TXT record", "txt", rec.Value)
		// Your service-detection logic goes here.
	}

	return nil
}
