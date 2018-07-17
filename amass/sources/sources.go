// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package sources

import (
	"fmt"
	"log"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/OWASP/Amass/amass/internal/utils"
	"github.com/PuerkitoBio/fetchbot"
	"github.com/PuerkitoBio/goquery"
)

const (
	ARCHIVE = "archive"
	API     = "api"
	CERT    = "cert"
	SCRAPE  = "scrape"
)

// All data sources are handled through this interface in amass
type DataSource interface {
	// Returns subdomain names from the data source
	Query(domain, sub string) []string

	// Sets the logger to be used by this data source
	SetLogger(l *log.Logger)

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
	SourceType   string
	Organization string
	logger       *log.Logger
}

func NewBaseDataSource(stype, org string) *BaseDataSource {
	return &BaseDataSource{
		SourceType:   stype,
		Organization: org,
	}
}

// Place holder that get implemented by each data source
func (bds *BaseDataSource) Query(domain, sub string) []string {
	return []string{}
}

func (bds *BaseDataSource) Type() string {
	return bds.SourceType
}

// If a data source supports searching on subdomains,
// this get implemented by the data source and returns true
func (bds *BaseDataSource) Subdomains() bool {
	return false
}

func (bds *BaseDataSource) SetLogger(l *log.Logger) {
	bds.logger = l
}

func (bds *BaseDataSource) String() string {
	return bds.Organization
}

// All data sources send log messages through this method
func (bds *BaseDataSource) log(msg string) {
	if bds.logger == nil {
		return
	}
	bds.logger.Printf("%s: %s", bds.Organization, msg)
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
		bds.log(fmt.Sprintf("Crawler error: %s %s - %v", ctx.Cmd.Method(), ctx.Cmd.URL(), err))
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
			close(names)
			break loop
		}
	}
	// Makes sure all the names were collected
	for name := range names {
		results = utils.UniqueAppend(results, name)
	}
	return results, nil
}

func (bds *BaseDataSource) linksAndNames(domain string, ctx *fetchbot.Context, res *http.Response, links, names chan string) {
	// Process the body to find the links
	doc, err := goquery.NewDocumentFromResponse(res)
	if err != nil {
		bds.log(fmt.Sprintf("Crawler error: %s %s - %s\n", ctx.Cmd.Method(), ctx.Cmd.URL(), err))
		return
	}

	re := utils.SubdomainRegex(domain)
	doc.Find("a[href]").Each(func(i int, s *goquery.Selection) {
		val, _ := s.Attr("href")
		// Resolve address
		u, err := ctx.Cmd.URL().Parse(val)
		if err != nil {
			bds.log(fmt.Sprintf("Crawler failed to parse: %s - %v\n", val, err))
			return
		}

		if sub := re.FindString(u.String()); sub != "" {
			names <- sub
			links <- u.String()
		}
	})
}

func setFetcherConfig(f *fetchbot.Fetcher) {
	f.HttpClient = &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			DialContext:           utils.DialContext,
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

func GetAllSources() []DataSource {
	return []DataSource{
		NewArchiveIt(),
		NewArchiveToday(),
		NewArquivo(),
		NewAsk(),
		NewBaidu(),
		NewCensys(),
		NewCertDB(),
		NewCertSpotter(),
		NewCommonCrawl(),
		NewCrtsh(),
		NewDNSDB(),
		NewDNSDumpster(),
		NewDogpile(),
		NewEntrust(),
		NewExalead(),
		NewFindSubdomains(),
		NewGoogle(),
		NewHackerTarget(),
		NewIPv4Info(),
		NewLoCArchive(),
		NewNetcraft(),
		NewOpenUKArchive(),
		NewPTRArchive(),
		NewRiddler(),
		NewRobtex(),
		NewSiteDossier(),
		NewThreatCrowd(),
		NewUKGovArchive(),
		NewVirusTotal(),
		NewWaybackMachine(),
		NewYahoo(),
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
