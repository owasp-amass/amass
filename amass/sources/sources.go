// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package sources

import (
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/OWASP/Amass/amass/core"
	"github.com/OWASP/Amass/amass/utils"
	"github.com/PuerkitoBio/fetchbot"
	"github.com/PuerkitoBio/goquery"
)

// All data sources are handled through this interface in amass
type DataSource interface {
	// Returns subdomain names from the data source
	Query(domain, sub string) []string

	// Returns the data source's associated organization
	String() string

	// Returns true if the data source supports subdomain name searches
	Subdomains() bool

	// Returns one of the types defined above in the constants
	Type() string
}

// The common functionalities and default behaviors for all data sources
// Most of the base methods are not implemented by each data source
type BaseDataSource struct {
	Service      core.AmassService
	SourceType   string
	Organization string
}

func NewBaseDataSource(srv core.AmassService, stype, org string) *BaseDataSource {
	return &BaseDataSource{
		Service:      srv,
		SourceType:   stype,
		Organization: org,
	}
}

// Place holder that get implemented by each data source
func (bds *BaseDataSource) Query(srv core.AmassService, domain, sub string) []string {
	return []string{}
}

func (bds *BaseDataSource) Type() string {
	return bds.SourceType
}

// If a data source supports searching on subdomains,
// this gets implemented by the data source and returns true
func (bds *BaseDataSource) Subdomains() bool {
	return false
}

func (bds *BaseDataSource) String() string {
	return bds.Organization
}

//-------------------------------------------------------------------------------------------------
// Web archive crawler implementation
//-------------------------------------------------------------------------------------------------

func (bds *BaseDataSource) crawl(base, domain, sub string) ([]string, error) {
	var results []string
	var filterMutex sync.Mutex
	filter := make(map[string]struct{})

	year := strconv.Itoa(time.Now().Year())
	mux := fetchbot.NewMux()
	links := make(chan string, 50)
	names := make(chan string, 50)
	linksFilter := make(map[string]struct{})

	mux.HandleErrors(fetchbot.HandlerFunc(func(ctx *fetchbot.Context, res *http.Response, err error) {
		bds.Service.Config().Log.Printf("Crawler error: %s %s - %v", ctx.Cmd.Method(), ctx.Cmd.URL(), err)
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

			bds.linksAndNames(domain, ctx, res, links, names)
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
		case <-bds.Service.Quit():
			break loop
		}
	}
	return results, nil
}

func (bds *BaseDataSource) linksAndNames(domain string, ctx *fetchbot.Context, res *http.Response, links, names chan string) {
	// Process the body to find the links
	doc, err := goquery.NewDocumentFromResponse(res)
	if err != nil {
		bds.Service.Config().Log.Printf("Crawler error: %s %s - %s\n", ctx.Cmd.Method(), ctx.Cmd.URL(), err)
		return
	}

	re := utils.SubdomainRegex(domain)
	doc.Find("a[href]").Each(func(i int, s *goquery.Selection) {
		val, _ := s.Attr("href")
		// Resolve address
		u, err := ctx.Cmd.URL().Parse(val)
		if err != nil {
			bds.Service.Config().Log.Printf("Crawler failed to parse: %s - %v\n", val, err)
			return
		}

		if sub := re.FindString(u.String()); sub != "" {
			names <- sub
			links <- u.String()
		}
	})
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
	f.UserAgent = utils.USER_AGENT
}

//-------------------------------------------------------------------------------------------------

func GetAllSources(srv core.AmassService) []DataSource {
	return []DataSource{
		NewArchiveIt(srv),
		NewArchiveToday(srv),
		NewArquivo(srv),
		NewAsk(srv),
		NewBaidu(srv),
		NewCensys(srv),
		NewCertDB(srv),
		NewCertSpotter(srv),
		NewCommonCrawl(srv),
		NewCrtsh(srv),
		//NewDNSDB(srv),
		NewDNSDumpster(srv),
		NewDNSTable(srv),
		NewDogpile(srv),
		NewEntrust(srv),
		NewExalead(srv),
		NewFindSubdomains(srv),
		NewGoogle(srv),
		NewHackerTarget(srv),
		NewIPv4Info(srv),
		NewLoCArchive(srv),
		NewNetcraft(srv),
		NewOpenUKArchive(srv),
		NewPTRArchive(srv),
		NewRiddler(srv),
		NewRobtex(srv),
		NewSiteDossier(srv),
		NewThreatCrowd(srv),
		NewUKGovArchive(srv),
		NewVirusTotal(srv),
		NewWaybackMachine(srv),
		NewYahoo(srv),
	}
}

func removeAsteriskLabel(s string) string {
	var index int

	labels := strings.Split(s, ".")
	for i := len(labels) - 1; i >= 0; i-- {
		if strings.TrimSpace(labels[i]) == "*" {
			break
		}
		index = i
	}
	if index == len(labels)-1 {
		return ""
	}
	return strings.Join(labels[index:], ".")
}
