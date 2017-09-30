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
	"time"

	"github.com/PuerkitoBio/gocrawl"
	"github.com/PuerkitoBio/goquery"
	"github.com/irfansharif/cfilter"
)

type memento struct {
	url        string
	subdomains chan string
	requests   chan string
}

func (m memento) String() string {
	return "Memento Web Archive"
}

func (m *memento) processRequests() {
	var running int
	var queue []string
	var done chan int = make(chan int, 10)

	t := time.NewTicker(1 * time.Second)
	defer t.Stop()

	year := time.Now().Year()
	// only have up to 10 crawlers running at the same time
	for {
		select {
		case sd := <-m.requests:
			queue = append(queue, sd)
		case <-t.C:
			if running < 10 && len(queue) > 0 {
				s := queue[0]
				queue = queue[1:]

				go crawl(m.url, strconv.Itoa(year), s,
					m.subdomains, done, 4*time.Minute)
				running++
			}
		case <-done:
			running--
		}
	}
}

func (m *memento) CheckHistory(subdomain string) {
	m.requests <- subdomain
	return
}

func (m memento) TotalUniqueSubdomains() int {
	return 0
}

func MementoWebArchive(u string, subdomains chan string) Archiver {
	m := new(memento)

	m.url = u
	m.subdomains = subdomains
	m.requests = make(chan string, 100)

	go m.processRequests()
	return m
}

type Ext struct {
	*gocrawl.DefaultExtender
	domainRE                *regexp.Regexp
	mementoRE               *regexp.Regexp
	filter                  *cfilter.CFilter
	base, year, sub, domain string
	names                   chan string
}

func (e *Ext) reducedURL(u *url.URL) string {
	orig := u.String()

	idx := e.mementoRE.FindStringIndex(orig)
	if idx == nil {
		return ""
	}

	i := idx[1]
	return fmt.Sprintf("%s/%s/%s", e.base, e.year, orig[i:])
}

func (e *Ext) Log(logFlags gocrawl.LogFlags, msgLevel gocrawl.LogFlags, msg string) {
	return
}

func (e *Ext) RequestRobots(ctx *gocrawl.URLContext, robotAgent string) (data []byte, doRequest bool) {
	return nil, false
}

func (e *Ext) Filter(ctx *gocrawl.URLContext, isVisited bool) bool {
	if isVisited {
		return false
	}

	u := ctx.URL().String()
	r := e.reducedURL(ctx.URL())

	if !strings.Contains(ctx.URL().Path, e.sub) {
		return false
	}

	if e.filter.Lookup([]byte(r)) {
		return false
	}

	if u != r {
		// the more refined version has been requested
		// and will cause the reduced version to be filtered
		e.filter.Insert([]byte(r))
	}
	return true
}

func (e *Ext) Visit(ctx *gocrawl.URLContext, res *http.Response, doc *goquery.Document) (interface{}, bool) {
	in, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return nil, true
	}

	for _, f := range e.domainRE.FindAllString(string(in), -1) {
		e.names <- f
	}
	return nil, true
}

func crawl(base, year, subdomain string, names chan string, done chan int, timeout time.Duration) {
	domain := ExtractDomain(subdomain)
	if domain == "" {
		done <- 1
		return
	}

	domainre, _ := regexp.Compile(SUBRE + domain)
	mementore, _ := regexp.Compile(base + "/[0-9]+/")
	// cuckoo filter for not double-checking URLs
	filter := cfilter.New()

	ext := &Ext{
		DefaultExtender: &gocrawl.DefaultExtender{},
		domainRE:        domainre,
		mementoRE:       mementore,
		filter:          filter,
		base:            base,
		year:            year,
		sub:             subdomain,
		domain:          domain,
		names:           names,
	}

	// Set custom options
	opts := gocrawl.NewOptions(ext)
	opts.CrawlDelay = 1 * time.Second
	opts.LogFlags = gocrawl.LogError
	opts.SameHostOnly = true
	opts.MaxVisits = 100

	c := gocrawl.NewCrawlerWithOptions(opts)
	go c.Run(fmt.Sprintf("%s/%s/%s", base, year, subdomain))

	<-time.After(timeout)
	c.Stop()
	done <- 1
	return
}
