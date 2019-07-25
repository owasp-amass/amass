// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package sources

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/OWASP/Amass/config"
	eb "github.com/OWASP/Amass/eventbus"
	"github.com/OWASP/Amass/resolvers"
	"github.com/OWASP/Amass/services"
	"github.com/OWASP/Amass/utils"
	"github.com/PuerkitoBio/goquery"
	"github.com/geziyor/geziyor"
	"github.com/geziyor/geziyor/client"
)

var (
	nameStripRE = regexp.MustCompile("^((20)|(25)|(2b)|(2f)|(3d)|(3a)|(40))+")
	maxCrawlSem = utils.NewSimpleSemaphore(50)
)

// GetAllSources returns a slice of all data source services, initialized and ready.
func GetAllSources(cfg *config.Config, bus *eb.EventBus, pool *resolvers.ResolverPool) []services.Service {
	return []services.Service{
		NewAlienVault(cfg, bus, pool),
		NewArchiveIt(cfg, bus, pool),
		NewArchiveToday(cfg, bus, pool),
		NewArquivo(cfg, bus, pool),
		NewAsk(cfg, bus, pool),
		NewBaidu(cfg, bus, pool),
		NewBinaryEdge(cfg, bus, pool),
		NewBing(cfg, bus, pool),
		NewBufferOver(cfg, bus, pool),
		NewCensys(cfg, bus, pool),
		NewCertSpotter(cfg, bus, pool),
		NewCIRCL(cfg, bus, pool),
		NewCommonCrawl(cfg, bus, pool),
		NewCrtsh(cfg, bus, pool),
		NewDNSDB(cfg, bus, pool),
		NewDNSDumpster(cfg, bus, pool),
		NewDNSTable(cfg, bus, pool),
		NewDogpile(cfg, bus, pool),
		NewEntrust(cfg, bus, pool),
		NewExalead(cfg, bus, pool),
		NewGoogle(cfg, bus, pool),
		NewGoogleCT(cfg, bus, pool),
		NewHackerOne(cfg, bus, pool),
		NewHackerTarget(cfg, bus, pool),
		NewIPv4Info(cfg, bus, pool),
		NewLoCArchive(cfg, bus, pool),
		NewMnemonic(cfg, bus, pool),
		NewNetcraft(cfg, bus, pool),
		NewNetworksDB(cfg, bus, pool),
		NewOpenUKArchive(cfg, bus, pool),
		NewPassiveTotal(cfg, bus, pool),
		NewPTRArchive(cfg, bus, pool),
		NewRADb(cfg, bus, pool),
		NewRiddler(cfg, bus, pool),
		NewRobtex(cfg, bus, pool),
		NewSiteDossier(cfg, bus, pool),
		NewSecurityTrails(cfg, bus, pool),
		NewShadowServer(cfg, bus, pool),
		NewShodan(cfg, bus, pool),
		NewSpyse(cfg, bus, pool),
		NewSublist3rAPI(cfg, bus, pool),
		NewTeamCymru(cfg, bus, pool),
		NewThreatCrowd(cfg, bus, pool),
		NewTwitter(cfg, bus, pool),
		NewUKGovArchive(cfg, bus, pool),
		NewUmbrella(cfg, bus, pool),
		NewURLScan(cfg, bus, pool),
		NewViewDNS(cfg, bus, pool),
		NewVirusTotal(cfg, bus, pool),
		NewWayback(cfg, bus, pool),
		NewYahoo(cfg, bus, pool),
	}
}

// Clean up the names scraped from the web.
func cleanName(name string) string {
	name = strings.TrimSpace(strings.ToLower(name))

	for {
		if i := nameStripRE.FindStringIndex(name); i != nil {
			name = name[i[1]:]
		} else {
			break
		}
	}

	name = strings.Trim(name, "-")
	// Remove dots at the beginning of names
	if len(name) > 1 && name[0] == '.' {
		name = name[1:]
	}
	return name
}

func crawl(service services.Service, baseURL, baseDomain, subdomain, domain string) ([]string, error) {
	results := utils.NewSet()

	maxCrawlSem.Acquire(1)
	defer maxCrawlSem.Release(1)

	re := service.Config().DomainRegex(domain)
	if re == nil {
		return results.ToSlice(), fmt.Errorf("crawler error: Failed to obtain regex object for: %s", domain)
	}

	start := fmt.Sprintf("%s/%s/%s", baseURL, strconv.Itoa(time.Now().Year()), subdomain)
	geziyor.NewGeziyor(&geziyor.Options{
		AllowedDomains:              []string{baseDomain},
		StartURLs:                   []string{start},
		Timeout:                     30 * time.Second,
		UserAgent:                   utils.UserAgent,
		RequestDelay:                time.Second,
		RequestDelayRandomize:       true,
		LogDisabled:                 true,
		ConcurrentRequests:          3,
		ConcurrentRequestsPerDomain: 3,
		ParseFunc: func(g *geziyor.Geziyor, r *client.Response) {
			r.HTMLDoc.Find("a").Each(func(i int, s *goquery.Selection) {
				if href, ok := s.Attr("href"); ok {
					if sub := re.FindString(r.JoinURL(href)); sub != "" {
						results.Insert(cleanName(sub))
					}
				}
			})
		},
	}).Start()

	return results.ToSlice(), nil
}
