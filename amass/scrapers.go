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
)

const (
	NUM_SEARCHES int = 13
)

type ScraperService struct {
	BaseAmassService

	responses    chan *AmassRequest
	scrapers     []Scraper
	filter       map[string]struct{}
	domainFilter map[string]struct{}
}

func NewScraperService(in, out chan *AmassRequest, config *AmassConfig) *ScraperService {
	ss := &ScraperService{
		responses:    make(chan *AmassRequest, 50),
		filter:       make(map[string]struct{}),
		domainFilter: make(map[string]struct{}),
	}

	ss.BaseAmassService = *NewBaseAmassService("Scraper Service", config, ss)
	ss.scrapers = []Scraper{
		AskSearch(ss.responses, config),
		BaiduSearch(ss.responses, config),
		CensysSearch(ss.responses, config),
		CrtshSearch(ss.responses, config),
		GoogleSearch(ss.responses, config),
		NetcraftSearch(ss.responses, config),
		RobtexSearch(ss.responses, config),
		BingSearch(ss.responses, config),
		DogpileSearch(ss.responses, config),
		YahooSearch(ss.responses, config),
		ThreatCrowdSearch(ss.responses, config),
		VirusTotalSearch(ss.responses, config),
		DNSDumpsterSearch(ss.responses, config),
	}

	ss.input = in
	ss.output = out
	return ss
}

func (ss *ScraperService) OnStart() error {
	ss.BaseAmassService.OnStart()

	go ss.processOutput()
	go ss.executeAllScrapers()
	return nil
}

func (ss *ScraperService) OnStop() error {
	ss.BaseAmassService.OnStop()
	return nil
}

func (ss *ScraperService) processOutput() {
loop:
	for {
		select {
		case req := <-ss.responses:
			if !ss.duplicate(req.Name) {
				ss.SendOut(req)
			}
		case <-ss.Quit():
			break loop
		}
	}
}

// Returns true if the subdomain name is a duplicate entry in the filter.
// If not, the subdomain name is added to the filter
func (ss *ScraperService) duplicate(sub string) bool {
	if _, found := ss.filter[sub]; found {
		return true
	}
	ss.filter[sub] = struct{}{}
	return false
}

func (ss *ScraperService) executeAllScrapers() {
	done := make(chan int)

	ss.SetActive(true)
	// Loop over all the root domains provided in the config
	for _, domain := range ss.Config().Domains() {
		if _, found := ss.domainFilter[domain]; found {
			continue
		}
		// Kick off all the searches
		for _, s := range ss.scrapers {
			go s.Scrape(domain, done)
		}
		// Wait for them to complete
		for i := 0; i < NUM_SEARCHES; i++ {
			<-done
		}
	}
	ss.SetActive(false)
}

// Searcher - represents all types that perform searches for domain names
type Scraper interface {
	Scrape(domain string, done chan int)
	fmt.Stringer
}

// searchEngine - A searcher that attempts to discover information using a web search engine
type searchEngine struct {
	Name     string
	Quantity int
	Limit    int
	Output   chan<- *AmassRequest
	Callback func(*searchEngine, string, int) string
	Config   *AmassConfig
}

func (se *searchEngine) String() string {
	return se.Name
}

func (se *searchEngine) urlByPageNum(domain string, page int) string {
	return se.Callback(se, domain, page)
}

func (se *searchEngine) Scrape(domain string, done chan int) {
	var unique []string

	re := SubdomainRegex(domain)
	num := se.Limit / se.Quantity
	for i := 0; i < num; i++ {
		page := GetWebPageWithDialContext(
			se.Config.DialContext, se.urlByPageNum(domain, i))
		if page == "" {
			break
		}

		for _, sd := range re.FindAllString(page, -1) {
			u := NewUniqueElements(unique, sd)

			if len(u) > 0 {
				unique = append(unique, u...)
				se.Output <- &AmassRequest{
					Name:   sd,
					Domain: domain,
					Tag:    SEARCH,
					Source: se.Name,
				}
			}
		}
		time.Sleep(1 * time.Second)
	}
	done <- len(unique)
}

func askURLByPageNum(a *searchEngine, domain string, page int) string {
	pu := strconv.Itoa(a.Quantity)
	p := strconv.Itoa(page)
	u, _ := url.Parse("http://www.ask.com/web")

	u.RawQuery = url.Values{"q": {domain}, "pu": {pu}, "page": {p}}.Encode()
	return u.String()
}

func AskSearch(out chan<- *AmassRequest, config *AmassConfig) Scraper {
	return &searchEngine{
		Name:     "Ask",
		Quantity: 10, // ask.com appears to be hardcoded at 10 results per page
		Limit:    100,
		Output:   out,
		Callback: askURLByPageNum,
		Config:   config,
	}
}

func baiduURLByPageNum(d *searchEngine, domain string, page int) string {
	pn := strconv.Itoa(page)
	u, _ := url.Parse("https://www.baidu.com/s")

	u.RawQuery = url.Values{"pn": {pn}, "wd": {domain}, "oq": {domain}}.Encode()
	return u.String()
}

func BaiduSearch(out chan<- *AmassRequest, config *AmassConfig) Scraper {
	return &searchEngine{
		Name:     "Baidu",
		Quantity: 20,
		Limit:    100,
		Output:   out,
		Callback: baiduURLByPageNum,
		Config:   config,
	}
}

func bingURLByPageNum(b *searchEngine, domain string, page int) string {
	count := strconv.Itoa(b.Quantity)
	first := strconv.Itoa((page * b.Quantity) + 1)
	u, _ := url.Parse("http://www.bing.com/search")

	u.RawQuery = url.Values{"q": {"domain:" + domain},
		"count": {count}, "first": {first}, "FORM": {"PORE"}}.Encode()
	return u.String()
}

func BingSearch(out chan<- *AmassRequest, config *AmassConfig) Scraper {
	return &searchEngine{
		Name:     "Bing Search",
		Quantity: 20,
		Limit:    200,
		Output:   out,
		Callback: bingURLByPageNum,
		Config:   config,
	}
}

func dogpileURLByPageNum(d *searchEngine, domain string, page int) string {
	qsi := strconv.Itoa(d.Quantity * page)
	u, _ := url.Parse("http://www.dogpile.com/search/web")

	u.RawQuery = url.Values{"qsi": {qsi}, "q": {domain}}.Encode()
	return u.String()
}

func DogpileSearch(out chan<- *AmassRequest, config *AmassConfig) Scraper {
	return &searchEngine{
		Name:     "Dogpile",
		Quantity: 15, // Dogpile returns roughly 15 results per page
		Limit:    90,
		Output:   out,
		Callback: dogpileURLByPageNum,
		Config:   config,
	}
}

func googleURLByPageNum(d *searchEngine, domain string, page int) string {
	pn := strconv.Itoa(page)
	u, _ := url.Parse("https://google.com/search")

	u.RawQuery = url.Values{
		"q":      {domain},
		"btnG":   {"Search"},
		"h1":     {"en-US"},
		"biw":    {""},
		"bih":    {""},
		"gbv":    {"1"},
		"start":  {pn},
		"filter": {"0"},
	}.Encode()
	return u.String()
}

func GoogleSearch(out chan<- *AmassRequest, config *AmassConfig) Scraper {
	return &searchEngine{
		Name:     "Google",
		Quantity: 20,
		Limit:    160,
		Output:   out,
		Callback: googleURLByPageNum,
		Config:   config,
	}
}

func yahooURLByPageNum(y *searchEngine, domain string, page int) string {
	b := strconv.Itoa(y.Quantity * page)
	pz := strconv.Itoa(y.Quantity)

	u, _ := url.Parse("http://search.yahoo.com/search")
	u.RawQuery = url.Values{"p": {"\"" + domain + "\""}, "b": {b}, "pz": {pz}}.Encode()

	return u.String()
}

func YahooSearch(out chan<- *AmassRequest, config *AmassConfig) Scraper {
	return &searchEngine{
		Name:     "Yahoo",
		Quantity: 20,
		Limit:    160,
		Output:   out,
		Callback: yahooURLByPageNum,
		Config:   config,
	}
}

//--------------------------------------------------------------------------------------------
// lookup - A searcher that attempts to discover information on a single web page
type lookup struct {
	Name     string
	Output   chan<- *AmassRequest
	Callback func(string) string
	Config   *AmassConfig
}

func (l *lookup) String() string {
	return l.Name
}

func (l *lookup) Scrape(domain string, done chan int) {
	var unique []string

	re := SubdomainRegex(domain)
	page := GetWebPageWithDialContext(l.Config.DialContext, l.Callback(domain))
	if page == "" {
		done <- 0
		return
	}

	for _, sd := range re.FindAllString(page, -1) {
		u := NewUniqueElements(unique, sd)

		if len(u) > 0 {
			unique = append(unique, u...)
			l.Output <- &AmassRequest{
				Name:   sd,
				Domain: domain,
				Tag:    SEARCH,
				Source: l.Name,
			}
		}
	}
	done <- len(unique)
}

func censysURL(domain string) string {
	format := "https://www.censys.io/domain/%s/table"

	return fmt.Sprintf(format, domain)
}

func CensysSearch(out chan<- *AmassRequest, config *AmassConfig) Scraper {
	return &lookup{
		Name:     "Censys",
		Output:   out,
		Callback: censysURL,
		Config:   config,
	}
}

func netcraftURL(domain string) string {
	format := "https://searchdns.netcraft.com/?restriction=site+ends+with&host=%s"

	return fmt.Sprintf(format, domain)
}

func NetcraftSearch(out chan<- *AmassRequest, config *AmassConfig) Scraper {
	return &lookup{
		Name:     "Netcraft",
		Output:   out,
		Callback: netcraftURL,
		Config:   config,
	}
}

func robtexURL(domain string) string {
	format := "https://www.robtex.com/dns-lookup/%s"

	return fmt.Sprintf(format, domain)
}

func RobtexSearch(out chan<- *AmassRequest, config *AmassConfig) Scraper {
	return &lookup{
		Name:     "Robtex",
		Output:   out,
		Callback: robtexURL,
		Config:   config,
	}
}

func threatCrowdURL(domain string) string {
	format := "https://www.threatcrowd.org/searchApi/v2/domain/report/?domain=%s"

	return fmt.Sprintf(format, domain)
}

func ThreatCrowdSearch(out chan<- *AmassRequest, config *AmassConfig) Scraper {
	return &lookup{
		Name:     "ThreatCrowd",
		Output:   out,
		Callback: threatCrowdURL,
		Config:   config,
	}
}

func virusTotalURL(domain string) string {
	format := "https://www.virustotal.com/en/domain/%s/information/"

	return fmt.Sprintf(format, domain)
}

func VirusTotalSearch(out chan<- *AmassRequest, config *AmassConfig) Scraper {
	return &lookup{
		Name:     "VirusTotal",
		Output:   out,
		Callback: virusTotalURL,
		Config:   config,
	}
}

//--------------------------------------------------------------------------------------------

type dumpster struct {
	Name   string
	Base   string
	Output chan<- *AmassRequest
	Config *AmassConfig
}

func (d *dumpster) String() string {
	return d.Name
}

func (d *dumpster) Scrape(domain string, done chan int) {
	var unique []string

	page := GetWebPageWithDialContext(d.Config.DialContext, d.Base)
	if page == "" {
		done <- 0
		return
	}

	token := d.getCSRFToken(page)
	if token == "" {
		done <- 0
		return
	}

	page = d.postForm(token, domain)
	if page == "" {
		done <- 0
		return
	}

	re := SubdomainRegex(domain)
	for _, sd := range re.FindAllString(page, -1) {
		u := NewUniqueElements(unique, sd)

		if len(u) > 0 {
			unique = append(unique, u...)
			d.Output <- &AmassRequest{
				Name:   sd,
				Domain: domain,
				Tag:    SEARCH,
				Source: d.Name,
			}
		}
	}
	done <- len(unique)
}

func (d *dumpster) getCSRFToken(page string) string {
	re := regexp.MustCompile("<input type='hidden' name='csrfmiddlewaretoken' value='([a-zA-Z0-9]*)' />")

	if subs := re.FindStringSubmatch(page); len(subs) == 2 {
		return strings.TrimSpace(subs[1])
	}
	return ""
}

func (d *dumpster) postForm(token, domain string) string {
	client := &http.Client{
		Transport: &http.Transport{
			DialContext:         d.Config.DialContext,
			TLSHandshakeTimeout: 10 * time.Second,
		},
	}
	params := url.Values{
		"csrfmiddlewaretoken": {token},
		"targetip":            {domain},
	}

	req, err := http.NewRequest("POST", d.Base, strings.NewReader(params.Encode()))
	if err != nil {
		return ""
	}
	// The CSRF token needs to be sent as a cookie
	cookie := &http.Cookie{
		Name:   "csrftoken",
		Domain: "dnsdumpster.com",
		Value:  token,
	}
	req.AddCookie(cookie)

	req.Header.Set("User-Agent", USER_AGENT)
	req.Header.Set("Accept", ACCEPT)
	req.Header.Set("Accept-Language", ACCEPT_LANG)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Referer", "https://dnsdumpster.com")
	req.Header.Set("X-CSRF-Token", token)

	resp, err := client.Do(req)
	if err != nil {
		return ""
	}
	// Now, grab the entire page
	in, err := ioutil.ReadAll(resp.Body)
	resp.Body.Close()
	return string(in)
}

func DNSDumpsterSearch(out chan<- *AmassRequest, config *AmassConfig) Scraper {
	return &dumpster{
		Name:   "DNSDumpster",
		Base:   "https://dnsdumpster.com/",
		Output: out,
		Config: config,
	}
}

//--------------------------------------------------------------------------------------------

type crtsh struct {
	Name   string
	Base   string
	Output chan<- *AmassRequest
	Config *AmassConfig
}

func (c *crtsh) String() string {
	return c.Name
}

func (c *crtsh) Scrape(domain string, done chan int) {
	var unique []string

	// Pull the page that lists all certs for this domain
	page := GetWebPageWithDialContext(c.Config.DialContext, c.Base+"?q=%25."+domain)
	if page == "" {
		done <- 0
		return
	}
	// Get the subdomain name the cert was issued to, and
	// the Subject Alternative Name list from each cert
	results := c.getSubmatches(page)
	for _, rel := range results {
		// Do not go too fast
		time.Sleep(50 * time.Millisecond)
		// Pull the certificate web page
		cert := GetWebPageWithDialContext(c.Config.DialContext, c.Base+rel)
		if cert == "" {
			continue
		}
		// Get all names off the certificate
		names := c.getMatches(cert, domain)
		// Send unique names out
		u := NewUniqueElements(unique, names...)
		if len(u) > 0 {
			unique = append(unique, u...)
		}
	}
	if len(unique) > 0 {
		c.sendAllNames(unique, domain)
	}
	done <- len(unique)
}

func (c *crtsh) sendAllNames(names []string, domain string) {
	for _, name := range names {
		c.Output <- &AmassRequest{
			Name:   name,
			Domain: domain,
			Tag:    SEARCH,
			Source: c.Name,
		}
	}
}

func (c *crtsh) getMatches(content, domain string) []string {
	var results []string

	re := SubdomainRegex(domain)
	for _, s := range re.FindAllString(content, -1) {
		results = append(results, s)
	}
	return results
}

func (c *crtsh) getSubmatches(content string) []string {
	var results []string

	re := regexp.MustCompile("<TD style=\"text-align:center\"><A href=\"([?]id=[a-zA-Z0-9]*)\">[a-zA-Z0-9]*</A></TD>")
	for _, subs := range re.FindAllStringSubmatch(content, -1) {
		results = append(results, strings.TrimSpace(subs[1]))
	}
	return results
}

// CrtshSearch - A searcher that attempts to discover names from SSL certificates
func CrtshSearch(out chan<- *AmassRequest, config *AmassConfig) Scraper {
	return &crtsh{
		Name:   "Cert Search",
		Base:   "https://crt.sh/",
		Output: out,
		Config: config,
	}
}
