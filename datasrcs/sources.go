// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package datasrcs

import (
	"context"
	"errors"
	"sort"

	"github.com/OWASP/Amass/v3/config"
	"github.com/OWASP/Amass/v3/eventbus"
	"github.com/OWASP/Amass/v3/net/dns"
	"github.com/OWASP/Amass/v3/requests"
	"github.com/OWASP/Amass/v3/systems"
)

var subRE = dns.AnySubdomainRegex()

// GetAllSources returns a slice of all data source services, initialized and ready.
func GetAllSources(sys systems.System, check bool) []requests.Service {
	srvs := []requests.Service{
		NewAlienVault(sys),
		NewCloudflare(sys),
		NewCommonCrawl(sys),
		NewCrtsh(sys),
		NewDNSDB(sys),
		NewDNSDumpster(sys),
		NewIPToASN(sys),
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

	if check {
		// Check that the data sources have acceptable configurations for operation
		// Filtering in-place: https://github.com/golang/go/wiki/SliceTricks
		i := 0
		for _, s := range srvs {
			if s.CheckConfig() == nil {
				srvs[i] = s
				i++
			}
		}
		srvs = srvs[:i]
	}

	sort.Slice(srvs, func(i, j int) bool {
		return srvs[i].String() < srvs[j].String()
	})
	return srvs
}

func genNewNameEvent(ctx context.Context, sys systems.System, srv requests.Service, name string) {
	cfg, bus, err := ContextConfigBus(ctx)
	if err != nil {
		return
	}

	if domain := cfg.WhichDomain(name); domain != "" {
		bus.Publish(requests.NewNameTopic, eventbus.PriorityHigh, &requests.DNSRequest{
			Name:   name,
			Domain: domain,
			Tag:    srv.Type(),
			Source: srv.String(),
		})
	}
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
