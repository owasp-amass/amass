// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package sources

import (
	"fmt"
	"net"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/OWASP/Amass/amass/core"
	"github.com/OWASP/Amass/amass/utils"
	"github.com/PuerkitoBio/fetchbot"
	"github.com/PuerkitoBio/goquery"
	evbus "github.com/asaskevich/EventBus"
)

var (
	nameStripRE = regexp.MustCompile("^((20)|(25)|(2f)|(3d)|(40))+")
)

// GetAllSources returns a slice of all data source services, initialized and ready.
func GetAllSources(e *core.Enumeration, bus evbus.Bus, config *core.AmassConfig) []core.AmassService {
	return []core.AmassService{
		NewArchiveIt(e, bus, config),
		NewArchiveToday(e, bus, config),
		NewArquivo(e, bus, config),
		NewAsk(e, bus, config),
		NewBaidu(e, bus, config),
		NewCensys(e, bus, config),
		NewCertDB(e, bus, config),
		NewCertSpotter(e, bus, config),
		NewCommonCrawl(e, bus, config),
		NewCrtsh(e, bus, config),
		//NewDNSDB(bus, config),
		NewDNSDumpster(e, bus, config),
		NewDNSTable(e, bus, config),
		NewDogpile(e, bus, config),
		NewEntrust(e, bus, config),
		NewExalead(e, bus, config),
		NewFindSubdomains(e, bus, config),
		NewGoogle(e, bus, config),
		NewHackerTarget(e, bus, config),
		NewIPv4Info(e, bus, config),
		NewLoCArchive(e, bus, config),
		NewNetcraft(e, bus, config),
		NewOpenUKArchive(e, bus, config),
		NewPTRArchive(e, bus, config),
		NewRiddler(e, bus, config),
		NewRobtex(e, bus, config),
		NewSiteDossier(e, bus, config),
		NewThreatCrowd(e, bus, config),
		NewUKGovArchive(e, bus, config),
		NewVirusTotal(e, bus, config),
		NewWayback(e, bus, config),
		NewYahoo(e, bus, config),
	}
}

// Clean up the names scraped from the web.
func cleanName(name string) string {
	if i := nameStripRE.FindStringIndex(name); i != nil {
		name = name[i[1]:]
	}
	name = strings.TrimSpace(strings.ToLower(name))
	// Remove dots at the beginning of names
	if len(name) > 1 && name[0] == '.' {
		name = name[1:]
	}
	return name
}

//-------------------------------------------------------------------------------------------------
// Web archive crawler implementation
//-------------------------------------------------------------------------------------------------

func crawl(service core.AmassService, base, domain, sub string) ([]string, error) {
	var results []string
	var filterMutex sync.Mutex
	filter := make(map[string]struct{})

	year := strconv.Itoa(time.Now().Year())
	mux := fetchbot.NewMux()
	links := make(chan string, 50)
	names := make(chan string, 50)
	linksFilter := make(map[string]struct{})

	mux.HandleErrors(fetchbot.HandlerFunc(func(ctx *fetchbot.Context, res *http.Response, err error) {
		//service.Config.Log.Printf("Crawler error: %s %s - %v", ctx.Cmd.Method(), ctx.Cmd.URL(), err)
	}))

	mux.Response().Method("GET").ContentType("text/html").Handler(fetchbot.HandlerFunc(
		func(ctx *fetchbot.Context, res *http.Response, err error) {
			filterMutex.Lock()
			defer filterMutex.Unlock()

			u := res.Request.URL.String()
			if _, found := filter[u]; found {
				return
			}
			filter[u] = struct{}{}

			linksAndNames(domain, ctx, res, links, names)
		}))

	f := fetchbot.New(fetchbot.HandlerFunc(func(ctx *fetchbot.Context, res *http.Response, err error) {
		mux.Handle(ctx, res, err)
	}))
	setFetcherConfig(f)

	q := f.Start()
	u := fmt.Sprintf("%s/%s/%s", base, year, sub)
	if _, err := q.SendStringGet(u); err != nil {
		return results, fmt.Errorf("Crawler error: GET %s - %v", u, err)
	}

	t := time.NewTimer(10 * time.Second)
loop:
	for {
		select {
		case l := <-links:
			if _, ok := linksFilter[l]; ok {
				continue
			}
			linksFilter[l] = struct{}{}
			q.SendStringGet(l)
		case n := <-names:
			results = utils.UniqueAppend(results, n)
		case <-t.C:
			go func() {
				q.Cancel()
			}()
		case <-q.Done():
			break loop
		case <-service.Quit():
			break loop
		}
	}
	return results, nil
}

func linksAndNames(domain string, ctx *fetchbot.Context, res *http.Response, links, names chan string) error {
	// Process the body to find the links
	doc, err := goquery.NewDocumentFromResponse(res)
	if err != nil {
		return fmt.Errorf("Crawler error: %s %s - %s\n", ctx.Cmd.Method(), ctx.Cmd.URL(), err)
	}

	re := utils.SubdomainRegex(domain)
	doc.Find("a[href]").Each(func(i int, s *goquery.Selection) {
		val, _ := s.Attr("href")
		// Resolve address
		u, err := ctx.Cmd.URL().Parse(val)
		if err != nil {
			return
		}

		if sub := re.FindString(u.String()); sub != "" {
			names <- sub
			links <- u.String()
		}
	})
	return nil
}

func setFetcherConfig(f *fetchbot.Fetcher) {
	d := net.Dialer{}
	f.HttpClient = &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			DialContext:           d.DialContext,
			MaxIdleConns:          200,
			IdleConnTimeout:       5 * time.Second,
			TLSHandshakeTimeout:   5 * time.Second,
			ExpectContinueTimeout: 5 * time.Second,
		},
	}
	f.CrawlDelay = 1 * time.Second
	f.DisablePoliteness = true
	f.UserAgent = utils.UserAgent
}
