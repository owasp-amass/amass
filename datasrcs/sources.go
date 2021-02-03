// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package datasrcs

import (
	"context"
	"errors"
	"sort"

	"github.com/OWASP/Amass/v3/config"
	"github.com/OWASP/Amass/v3/requests"
	"github.com/OWASP/Amass/v3/systems"
	"github.com/caffix/eventbus"
	"github.com/caffix/service"
	"github.com/caffix/stringset"
)

// GetAllSources returns a slice of all data source services, initialized and ready.
func GetAllSources(sys systems.System) []service.Service {
	srvs := []service.Service{
		NewAlienVault(sys),
		NewCloudflare(sys),
		NewDNSDB(sys),
		NewDNSDumpster(sys),
		NewIPv4Info(sys),
		NewNetworksDB(sys),
		NewPastebin(sys),
		NewRADb(sys),
		NewRobtex(sys),
		NewShadowServer(sys),
		NewTeamCymru(sys),
		NewTwitter(sys),
		NewUmbrella(sys),
		NewURLScan(sys),
		NewViewDNS(sys),
		NewWhoisXML(sys),
	}

	if scripts, err := sys.Config().AcquireScripts(); err == nil {
		for _, script := range scripts {
			if s := NewScript(script, sys); s != nil {
				srvs = append(srvs, s)
			}
		}
	}

	sort.Slice(srvs, func(i, j int) bool {
		return srvs[i].String() < srvs[j].String()
	})
	return srvs
}

// SelectedDataSources uses the config and available data sources to return the selected data sources.
func SelectedDataSources(cfg *config.Config, avail []service.Service) []service.Service {
	specified := stringset.New()
	specified.InsertMany(cfg.SourceFilter.Sources...)

	available := stringset.New()
	for _, src := range avail {
		available.Insert(src.String())
	}

	if specified.Len() > 0 && cfg.SourceFilter.Include {
		available.Intersect(specified)
	} else {
		available.Subtract(specified)
	}

	var results []service.Service
	for _, src := range avail {
		if available.Has(src.String()) {
			results = append(results, src)
		}
	}

	sort.Slice(results, func(i, j int) bool {
		return results[i].String() < results[j].String()
	})
	return results
}

// ContextConfigBus extracts the Config and EventBus references from the Context argument.
func ContextConfigBus(ctx context.Context) (*config.Config, *eventbus.EventBus, error) {
	var ok bool
	var cfg *config.Config

	if c := ctx.Value(requests.ContextConfig); c != nil {
		cfg, ok = c.(*config.Config)
		if !ok {
			return nil, nil, errors.New("Failed to extract the configuration from the context")
		}
	} else {
		return nil, nil, errors.New("Failed to extract the configuration from the context")
	}

	var bus *eventbus.EventBus
	if b := ctx.Value(requests.ContextEventBus); b != nil {
		bus, ok = b.(*eventbus.EventBus)
		if !ok {
			return nil, nil, errors.New("Failed to extract the event bus from the context")
		}
	} else {
		return nil, nil, errors.New("Failed to extract the event bus from the context")
	}

	return cfg, bus, nil
}

func genNewNameEvent(ctx context.Context, sys systems.System, srv service.Service, name string) {
	cfg, bus, err := ContextConfigBus(ctx)
	if err != nil {
		return
	}

	if domain := cfg.WhichDomain(name); domain != "" {
		bus.Publish(requests.NewNameTopic, eventbus.PriorityHigh, &requests.DNSRequest{
			Name:   name,
			Domain: domain,
			Tag:    srv.Description(),
			Source: srv.String(),
		})
	}
}

func numRateLimitChecks(srv service.Service, num int) {
	for i := 0; i < num; i++ {
		srv.CheckRateLimit()
	}
}
