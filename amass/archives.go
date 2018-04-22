// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package amass

import (
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/PuerkitoBio/gocrawl"
	"github.com/PuerkitoBio/goquery"
)

type ArchiveService struct {
	BaseAmassService

	responses chan *AmassRequest
	archives  []Archiver
	filter    map[string]struct{}
}

func NewArchiveService(in, out chan *AmassRequest, config *AmassConfig) *ArchiveService {
	as := &ArchiveService{
		responses: make(chan *AmassRequest, 50),
		filter:    make(map[string]struct{}),
	}
	// Modify the crawler's http client to use our DialContext
	gocrawl.HttpClient.Transport = &http.Transport{
		DialContext:           config.DialContext,
		MaxIdleConns:          200,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 5 * time.Second,
	}
	// Setup the service
	as.BaseAmassService = *NewBaseAmassService("Web Archive Service", config, as)
	as.archives = []Archiver{
		WaybackMachineArchive(as.responses),
		LibraryCongressArchive(as.responses),
		ArchiveIsArchive(as.responses),
		ArchiveItArchive(as.responses),
		ArquivoArchive(as.responses),
		UKWebArchive(as.responses),
		UKGovArchive(as.responses),
	}

	as.input = in
	as.output = out
	return as
}

func (as *ArchiveService) OnStart() error {
	as.BaseAmassService.OnStart()

	go as.processRequests()
	go as.processOutput()
	return nil
}

func (as *ArchiveService) OnStop() error {
	as.BaseAmassService.OnStop()
	return nil
}

func (as *ArchiveService) processRequests() {
loop:
	for {
		select {
		case req := <-as.Input():
			go as.executeAllArchives(req)
		case <-as.Quit():
			break loop
		}
	}
}

func (as *ArchiveService) processOutput() {
	t := time.NewTicker(10 * time.Second)
	defer t.Stop()
loop:
	for {
		select {
		case out := <-as.responses:
			as.SetActive(true)
			if !as.duplicate(out.Name) {
				as.SendOut(out)
			}
		case <-t.C:
			as.SetActive(false)
		case <-as.Quit():
			break loop
		}
	}
}

// Returns true if the subdomain name is a duplicate entry in the filter.
// If not, the subdomain name is added to the filter
func (as *ArchiveService) duplicate(sub string) bool {
	if _, found := as.filter[sub]; found {
		return true
	}
	as.filter[sub] = struct{}{}
	return false
}

func (as *ArchiveService) executeAllArchives(req *AmassRequest) {
	as.SetActive(true)

	for _, archive := range as.archives {
		go archive.Search(req)
	}
}

// Archiver - represents all objects that perform Memento web archive searches for domain names
type Archiver interface {
	Search(req *AmassRequest)
}

type memento struct {
	Name     string
	URL      string
	Output   chan<- *AmassRequest
	Requests chan *AmassRequest
}

func (m *memento) Search(req *AmassRequest) {
	m.Requests <- req
}

func MementoWebArchive(u, name string, out chan<- *AmassRequest) Archiver {
	m := &memento{
		Name:     name,
		URL:      u,
		Output:   out,
		Requests: make(chan *AmassRequest, 100),
	}
	go m.processRequests()
	return m
}

func ArchiveItArchive(out chan<- *AmassRequest) Archiver {
	return MementoWebArchive("https://wayback.archive-it.org/all", "Archive-It", out)
}

func ArchiveIsArchive(out chan<- *AmassRequest) Archiver {
	return MementoWebArchive("http://archive.is", "Archive Today", out)
}

func ArquivoArchive(out chan<- *AmassRequest) Archiver {
	return MementoWebArchive("http://arquivo.pt/wayback", "Arquivo Arc", out)
}

func LibraryCongressArchive(out chan<- *AmassRequest) Archiver {
	return MementoWebArchive("http://webarchive.loc.gov/all", "LoC Archive", out)
}

func UKWebArchive(out chan<- *AmassRequest) Archiver {
	return MementoWebArchive("http://www.webarchive.org.uk/wayback/archive", "Open UK Arc", out)
}

func UKGovArchive(out chan<- *AmassRequest) Archiver {
	return MementoWebArchive("http://webarchive.nationalarchives.gov.uk", "UK Gov Arch", out)
}

func WaybackMachineArchive(out chan<- *AmassRequest) Archiver {
	return MementoWebArchive("http://web.archive.org/web", "Wayback Arc", out)
}

/* Private functions */

func (m *memento) processRequests() {
	var running int
	var queue []*AmassRequest
	done := make(chan struct{}, 10)

	t := time.NewTicker(1 * time.Second)
	defer t.Stop()

	year := time.Now().Year()
	// Only have up to 10 crawlers running at the same time
	for {
		select {
		case sd := <-m.Requests:
			queue = append(queue, sd)
		case <-t.C:
			if running >= 10 || len(queue) <= 0 {
				break
			}

			s := queue[0]
			if len(queue) == 1 {
				queue = []*AmassRequest{}
			} else {
				queue = queue[1:]
			}

			go m.crawl(strconv.Itoa(year), s, done)
			running++
		case <-done:
			running--
		}
	}
}

func (m *memento) crawl(year string, req *AmassRequest, done chan struct{}) {
	domain := req.Domain
	if domain == "" {
		done <- struct{}{}
		return
	}

	ext := &ext{
		DefaultExtender: &gocrawl.DefaultExtender{},
		domainRE:        SubdomainRegex(domain),
		mementoRE:       regexp.MustCompile(m.URL + "/[0-9]+/"),
		filter:          make(map[string]bool), // Filter for not double-checking URLs
		base:            m.URL,
		year:            year,
		sub:             req.Name,
		domain:          domain,
		names:           m.Output,
		source:          m.Name,
	}

	// Set custom options
	opts := gocrawl.NewOptions(ext)
	opts.CrawlDelay = 500 * time.Millisecond
	opts.LogFlags = gocrawl.LogError
	opts.SameHostOnly = true
	opts.MaxVisits = 20

	c := gocrawl.NewCrawlerWithOptions(opts)
	c.Run(fmt.Sprintf("%s/%s/%s", m.URL, year, req.Name))
	done <- struct{}{}
}

type ext struct {
	*gocrawl.DefaultExtender
	domainRE                *regexp.Regexp
	mementoRE               *regexp.Regexp
	filter                  map[string]bool
	flock                   sync.RWMutex
	base, year, sub, domain string
	names                   chan<- *AmassRequest
	source                  string
}

func (e *ext) reducedURL(u *url.URL) string {
	orig := u.String()

	idx := e.mementoRE.FindStringIndex(orig)
	if idx == nil {
		return ""
	}

	i := idx[1]
	return fmt.Sprintf("%s/%s/%s", e.base, e.year, orig[i:])
}

func (e *ext) Log(logFlags gocrawl.LogFlags, msgLevel gocrawl.LogFlags, msg string) {
	return
}

func (e *ext) RequestRobots(ctx *gocrawl.URLContext, robotAgent string) (data []byte, doRequest bool) {
	return nil, false
}

func (e *ext) Filter(ctx *gocrawl.URLContext, isVisited bool) bool {
	if isVisited {
		return false
	}

	u := ctx.URL().String()
	r := e.reducedURL(ctx.URL())

	if !strings.Contains(ctx.URL().Path, e.sub) {
		return false
	}

	e.flock.RLock()
	_, ok := e.filter[r]
	e.flock.RUnlock()

	if ok {
		return false
	}

	if u != r {
		// The more refined version has been requested
		// and will cause the reduced version to be filtered
		e.flock.Lock()
		e.filter[r] = true
		e.flock.Unlock()
	}
	return true
}

func (e *ext) Visit(ctx *gocrawl.URLContext, res *http.Response, doc *goquery.Document) (interface{}, bool) {
	in, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return nil, true
	}

	for _, f := range e.domainRE.FindAllString(string(in), -1) {
		e.names <- &AmassRequest{
			Name:   f,
			Domain: e.domain,
			Tag:    ARCHIVE,
			Source: e.source,
		}
	}
	return nil, true
}
