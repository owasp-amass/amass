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

const NUM_SEARCHES int = 9

// Searcher - represents all objects that perform searches for domain names
type Searcher interface {
	Search(domain string, done chan int)
	fmt.Stringer
}

// searchEngine - A searcher that attempts to discover information using a web search engine
type searchEngine struct {
	name       string
	quantity   int
	limit      int
	subdomains chan *Subdomain
	callback   func(*searchEngine, string, int) string
}

func (se *searchEngine) String() string {
	return se.name
}

func (se *searchEngine) urlByPageNum(domain string, page int) string {
	return se.callback(se, domain, page)
}

func (se *searchEngine) Search(domain string, done chan int) {
	var unique []string

	re := SubdomainRegex(domain)
	num := se.limit / se.quantity
	for i := 0; i < num; i++ {
		page := GetWebPage(se.urlByPageNum(domain, i))
		if page == "" {
			break
		}

		for _, sd := range re.FindAllString(page, -1) {
			u := NewUniqueElements(unique, sd)

			if len(u) > 0 {
				unique = append(unique, u...)
				se.subdomains <- &Subdomain{Name: sd, Domain: domain, Tag: SEARCH}
			}
		}

		time.Sleep(1 * time.Second)
	}
	done <- len(unique)
	return
}

func askURLByPageNum(a *searchEngine, domain string, page int) string {
	pu := strconv.Itoa(a.quantity)
	p := strconv.Itoa(page)
	u, _ := url.Parse("http://www.ask.com/web")

	u.RawQuery = url.Values{"q": {domain}, "pu": {pu}, "page": {p}}.Encode()
	return u.String()
}

func (a *Amass) AskSearch() Searcher {
	as := new(searchEngine)

	as.name = "Ask Search"
	// ask.com appears to be hardcoded at 10 results per page
	as.quantity = 10
	as.limit = 200
	as.subdomains = a.Names
	as.callback = askURLByPageNum
	return as
}

func bingURLByPageNum(b *searchEngine, domain string, page int) string {
	count := strconv.Itoa(b.quantity)
	first := strconv.Itoa((page * b.quantity) + 1)
	u, _ := url.Parse("http://www.bing.com/search")

	u.RawQuery = url.Values{"q": {"domain:" + domain},
		"count": {count}, "first": {first}, "FORM": {"PORE"}}.Encode()
	return u.String()
}

func (a *Amass) BingSearch() Searcher {
	b := new(searchEngine)

	b.name = "Bing Search"
	b.quantity = 20
	b.limit = 400
	b.subdomains = a.Names
	b.callback = bingURLByPageNum
	return b
}

func dogpileURLByPageNum(d *searchEngine, domain string, page int) string {
	qsi := strconv.Itoa(d.quantity * page)

	u, _ := url.Parse("http://www.dogpile.com/search/web")
	u.RawQuery = url.Values{"qsi": {qsi}, "q": {domain}}.Encode()
	return u.String()
}

func (a *Amass) DogpileSearch() Searcher {
	d := new(searchEngine)

	d.name = "Dogpile Search"
	// Dogpile returns roughly 15 results per page
	d.quantity = 15
	d.limit = 300
	d.subdomains = a.Names
	d.callback = dogpileURLByPageNum
	return d
}

func yahooURLByPageNum(y *searchEngine, domain string, page int) string {
	b := strconv.Itoa(y.quantity * page)
	pz := strconv.Itoa(y.quantity)

	u, _ := url.Parse("http://search.yahoo.com/search")
	u.RawQuery = url.Values{"p": {"\"" + domain + "\""}, "b": {b}, "pz": {pz}}.Encode()

	return u.String()
}

func (a *Amass) YahooSearch() Searcher {
	y := new(searchEngine)

	y.name = "Yahoo Search"
	y.quantity = 20
	y.limit = 400
	y.subdomains = a.Names
	y.callback = yahooURLByPageNum
	return y
}

//--------------------------------------------------------------------------------------------
// lookup - A searcher that attempts to discover information on a single web page
type lookup struct {
	name       string
	subdomains chan *Subdomain
	callback   func(string) string
}

func (l *lookup) String() string {
	return l.name
}

func (l *lookup) Search(domain string, done chan int) {
	var unique []string

	re := SubdomainRegex(domain)
	page := GetWebPage(l.callback(domain))
	if page == "" {
		done <- 0
		return
	}

	for _, sd := range re.FindAllString(page, -1) {
		u := NewUniqueElements(unique, sd)

		if len(u) > 0 {
			unique = append(unique, u...)
			l.subdomains <- &Subdomain{Name: sd, Domain: domain, Tag: SEARCH}
		}
	}

	done <- len(unique)
	return
}

func censysURL(domain string) string {
	format := "https://www.censys.io/domain/%s/table"

	return fmt.Sprintf(format, domain)
}

func (a *Amass) CensysSearch() Searcher {
	c := new(lookup)

	c.name = "Censys Search"
	c.subdomains = a.Names
	c.callback = censysURL
	return c
}

func netcraftURL(domain string) string {
	format := "https://searchdns.netcraft.com/?restriction=site+ends+with&host=%s"

	return fmt.Sprintf(format, domain)
}

func (a *Amass) NetcraftSearch() Searcher {
	n := new(lookup)

	n.name = "Netcraft Search"
	n.subdomains = a.Names
	n.callback = netcraftURL
	return n
}

func robtexURL(domain string) string {
	format := "https://www.robtex.com/dns-lookup/%s"

	return fmt.Sprintf(format, domain)
}

func (a *Amass) RobtexSearch() Searcher {
	r := new(lookup)

	r.name = "Robtex Search"
	r.subdomains = a.Names
	r.callback = robtexURL
	return r
}

func virusTotalURL(domain string) string {
	format := "https://www.virustotal.com/en/domain/%s/information/"

	return fmt.Sprintf(format, domain)
}

func (a *Amass) VirusTotalSearch() Searcher {
	vt := new(lookup)

	vt.name = "VirusTotal Search"
	vt.subdomains = a.Names
	vt.callback = virusTotalURL
	return vt
}

//--------------------------------------------------------------------------------------------
// crtshCrawl - A searcher that attempts to discover names from SSL certificates
type crtshCrawl struct {
	name       string
	subdomains chan *Subdomain
}

func (a *Amass) CrtshSearch() Searcher {
	c := new(crtshCrawl)

	c.name = "Crtsh Search"
	c.subdomains = a.Names
	return c
}

func (c *crtshCrawl) String() string {
	return c.name
}

func (c *crtshCrawl) Search(domain string, done chan int) {
	url := "https://crt.sh/?q=" + domain

	ctCrawl(url, "crt.sh", domain, c.subdomains, 30*time.Second)
	done <- 1
}

type ctExt struct {
	*gocrawl.DefaultExtender
	re              *regexp.Regexp
	filter          map[string]bool
	flock           sync.RWMutex
	service, domain string
	names           chan *Subdomain
}

func (e *ctExt) Log(logFlags gocrawl.LogFlags, msgLevel gocrawl.LogFlags, msg string) {
	return
}

func (e *ctExt) RequestRobots(ctx *gocrawl.URLContext, robotAgent string) (data []byte, doRequest bool) {
	return nil, false
}

func (e *ctExt) Filter(ctx *gocrawl.URLContext, isVisited bool) bool {
	if isVisited {
		return false
	}

	u := ctx.URL().String()

	if !strings.Contains(u, e.service) {
		return false
	}

	e.flock.RLock()
	_, ok := e.filter[u]
	e.flock.RUnlock()

	if ok {
		return false
	}

	e.flock.Lock()
	e.filter[u] = true
	e.flock.Unlock()
	return true
}

func (e *ctExt) Visit(ctx *gocrawl.URLContext, res *http.Response, doc *goquery.Document) (interface{}, bool) {
	in, err := ioutil.ReadAll(res.Body)
	if err == nil {
		for _, sd := range e.re.FindAllString(string(in), -1) {
			e.names <- &Subdomain{Name: sd, Domain: e.domain, Tag: SEARCH}
		}
	}
	return nil, true
}

func ctCrawl(url, service, domain string, names chan *Subdomain, timeout time.Duration) {
	ext := &ctExt{
		DefaultExtender: &gocrawl.DefaultExtender{},
		re:              SubdomainRegex(domain),
		filter:          make(map[string]bool), // filter for not double-checking URLs
		service:         service,
		domain:          domain,
		names:           names,
	}

	// Set custom options
	opts := gocrawl.NewOptions(ext)
	opts.CrawlDelay = 50 * time.Millisecond
	opts.LogFlags = gocrawl.LogError
	opts.SameHostOnly = true
	opts.MaxVisits = 200

	c := gocrawl.NewCrawlerWithOptions(opts)
	go c.Run(url)

	<-time.After(timeout)
	c.Stop()
}

func GetWebPage(url string) string {
	resp, err := http.Get(url)
	if err != nil {
		return ""
	}

	in, err := ioutil.ReadAll(resp.Body)
	resp.Body.Close()
	return string(in)
}
