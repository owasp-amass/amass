// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package sources

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/OWASP/Amass/amass/core"
	eb "github.com/OWASP/Amass/amass/eventbus"
	"github.com/OWASP/Amass/amass/utils"
	"github.com/PuerkitoBio/goquery"
	"github.com/geziyor/geziyor"
	"github.com/geziyor/geziyor/client"
)

var (
	nameStripRE = regexp.MustCompile("^((20)|(25)|(2b)|(2f)|(3d)|(3a)|(40))+")
	maxCrawlSem = utils.NewSimpleSemaphore(50)
)

// GetAllSources returns a slice of all data source services, initialized and ready.
func GetAllSources(config *core.Config, bus *eb.EventBus) []core.Service {
	return []core.Service{
		NewAlienVault(config, bus),
		NewArchiveIt(config, bus),
		NewArchiveToday(config, bus),
		NewArquivo(config, bus),
		NewAsk(config, bus),
		NewBaidu(config, bus),
		NewBinaryEdge(config, bus),
		NewBing(config, bus),
		NewBufferOver(config, bus),
		NewCensys(config, bus),
		NewCertSpotter(config, bus),
		NewCIRCL(config, bus),
		NewCommonCrawl(config, bus),
		NewCrtsh(config, bus),
		NewDNSDB(config, bus),
		NewDNSDumpster(config, bus),
		NewDNSTable(config, bus),
		NewDogpile(config, bus),
		NewEntrust(config, bus),
		NewExalead(config, bus),
		NewGoogle(config, bus),
		NewHackerOne(config, bus),
		NewHackerTarget(config, bus),
		NewIPv4Info(config, bus),
		NewLoCArchive(config, bus),
		NewMnemonic(config, bus),
		NewNetcraft(config, bus),
		NewNetworksDB(config, bus),
		NewOpenUKArchive(config, bus),
		NewPassiveTotal(config, bus),
		NewPTRArchive(config, bus),
		NewRADb(config, bus),
		NewRiddler(config, bus),
		NewRobtex(config, bus),
		NewSiteDossier(config, bus),
		NewSecurityTrails(config, bus),
		NewShadowServer(config, bus),
		NewShodan(config, bus),
		NewSublist3rAPI(config, bus),
		NewTeamCymru(config, bus),
		NewThreatCrowd(config, bus),
		NewTwitter(config, bus),
		NewUKGovArchive(config, bus),
		NewUmbrella(config, bus),
		NewURLScan(config, bus),
		NewViewDNS(config, bus),
		NewVirusTotal(config, bus),
		NewWayback(config, bus),
		NewYahoo(config, bus),
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

func crawl(service core.Service, baseURL, baseDomain, subdomain, domain string) ([]string, error) {
	var results []string

	maxCrawlSem.Acquire(1)
	defer maxCrawlSem.Release(1)

	re := service.Config().DomainRegex(domain)
	if re == nil {
		return results, fmt.Errorf("crawler error: Failed to obtain regex object for: %s", domain)
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
						results = utils.UniqueAppend(results, cleanName(sub))
					}
				}
			})
		},
	}).Start()

	return results, nil
}
