// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package datasrcs

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/OWASP/Amass/v3/config"
	"github.com/OWASP/Amass/v3/eventbus"
	"github.com/OWASP/Amass/v3/net/dns"
	"github.com/OWASP/Amass/v3/net/http"
	"github.com/OWASP/Amass/v3/requests"
	"github.com/OWASP/Amass/v3/stringset"
	"github.com/OWASP/Amass/v3/systems"
	"github.com/PuerkitoBio/goquery"
	"github.com/geziyor/geziyor"
	"github.com/geziyor/geziyor/client"
	"golang.org/x/sync/semaphore"
)

var (
	subRE       = dns.AnySubdomainRegex()
	maxCrawlSem = semaphore.NewWeighted(20)
	nameStripRE = regexp.MustCompile(`^u[0-9a-f]{4}|20|22|25|2b|2f|3d|3a|40`)
)

// GetAllSources returns a slice of all data source services, initialized and ready.
func GetAllSources(sys systems.System) []requests.Service {
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

	sort.Slice(srvs, func(i, j int) bool {
		return srvs[i].String() < srvs[j].String()
	})
	return srvs
}

// Clean up the names scraped from the web.
func cleanName(name string) string {
	var err error

	name, err = strconv.Unquote("\"" + strings.TrimSpace(name) + "\"")
	if err == nil {
		name = subRE.FindString(name)
	}

	name = strings.ToLower(name)
	for {
		name = strings.Trim(name, "-.")

		if i := nameStripRE.FindStringIndex(name); i != nil {
			name = name[i[1]:]
		} else {
			break
		}
	}

	return name
}

func genNewNameEvent(ctx context.Context, sys systems.System, srv requests.Service, name string) {
	cfg := ctx.Value(requests.ContextConfig).(*config.Config)
	bus := ctx.Value(requests.ContextEventBus).(*eventbus.EventBus)
	if cfg == nil || bus == nil {
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

func crawl(ctx context.Context, url string) ([]string, error) {
	results := stringset.New()

	cfg := ctx.Value(requests.ContextConfig).(*config.Config)
	if cfg == nil {
		return results.Slice(), errors.New("crawler error: Failed to obtain the config from Context")
	}

	err := maxCrawlSem.Acquire(ctx, 1)
	if err != nil {
		return results.Slice(), fmt.Errorf("crawler error: %v", err)
	}
	defer maxCrawlSem.Release(1)

	scope := cfg.Domains()
	target := subRE.FindString(url)
	if target != "" {
		scope = append(scope, target)
	}

	var count int
	var m sync.Mutex
	geziyor.NewGeziyor(&geziyor.Options{
		AllowedDomains:     scope,
		StartURLs:          []string{url},
		Timeout:            10 * time.Second,
		RobotsTxtDisabled:  true,
		UserAgent:          http.UserAgent,
		LogDisabled:        true,
		ConcurrentRequests: 5,
		ParseFunc: func(g *geziyor.Geziyor, r *client.Response) {
			for _, n := range subRE.FindAllString(string(r.Body), -1) {
				name := cleanName(n)

				if domain := cfg.WhichDomain(name); domain != "" {
					m.Lock()
					results.Insert(name)
					m.Unlock()
				}
			}

			r.HTMLDoc.Find("a").Each(func(i int, s *goquery.Selection) {
				if href, ok := s.Attr("href"); ok {
					if count < 5 {
						g.Get(r.JoinURL(href), g.Opt.ParseFunc)
						count++
					}
				}
			})
		},
	}).Start()

	return results.Slice(), nil
}
