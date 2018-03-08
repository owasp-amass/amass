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
	USER_AGENT       = "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.36"
	ACCEPT           = "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8"
	ACCEPT_LANG      = "en-US,en;q=0.8"
)

// Searcher - represents all objects that perform searches for domain names
type Searcher interface {
	Search(domain, misc string, done chan int)
	fmt.Stringer
}

// searchEngine - A searcher that attempts to discover information using a web search engine
type searchEngine struct {
	Name       string
	Quantity   int
	Limit      int
	Subdomains chan *Subdomain
	Callback   func(*searchEngine, string, int) string
}

func (se *searchEngine) String() string {
	return se.Name
}

func (se *searchEngine) urlByPageNum(domain string, page int) string {
	return se.Callback(se, domain, page)
}

func (se *searchEngine) Search(domain, misc string, done chan int) {
	var unique []string

	re := SubdomainRegex(domain)
	num := se.Limit / se.Quantity
	for i := 0; i < num; i++ {
		page := GetWebPage(se.urlByPageNum(domain, i))
		if page == "" {
			break
		}

		for _, sd := range re.FindAllString(page, -1) {
			u := NewUniqueElements(unique, sd)

			if len(u) > 0 {
				unique = append(unique, u...)
				se.Subdomains <- &Subdomain{
					Name:   sd,
					Domain: domain,
					Tag:    SEARCH,
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

func (a *Amass) AskSearch() Searcher {
	return &searchEngine{
		Name:       "Ask Search",
		Quantity:   10, // ask.com appears to be hardcoded at 10 results per page
		Limit:      200,
		Subdomains: a.Names,
		Callback:   askURLByPageNum,
	}
}

func baiduURLByPageNum(d *searchEngine, domain string, page int) string {
	pn := strconv.Itoa(page)
	u, _ := url.Parse("https://www.baidu.com/s")

	u.RawQuery = url.Values{"pn": {pn}, "wd": {domain}, "oq": {domain}}.Encode()
	return u.String()
}

func (a *Amass) BaiduSearch() Searcher {
	return &searchEngine{
		Name:       "Baidu Search",
		Quantity:   20,
		Limit:      200,
		Subdomains: a.Names,
		Callback:   baiduURLByPageNum,
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

func (a *Amass) BingSearch() Searcher {
	return &searchEngine{
		Name:       "Bing Search",
		Quantity:   20,
		Limit:      200,
		Subdomains: a.Names,
		Callback:   bingURLByPageNum,
	}
}

func dogpileURLByPageNum(d *searchEngine, domain string, page int) string {
	qsi := strconv.Itoa(d.Quantity * page)
	u, _ := url.Parse("http://www.dogpile.com/search/web")

	u.RawQuery = url.Values{"qsi": {qsi}, "q": {domain}}.Encode()
	return u.String()
}

func (a *Amass) DogpileSearch() Searcher {
	return &searchEngine{
		Name:       "Dogpile Search",
		Quantity:   15, // Dogpile returns roughly 15 results per page
		Limit:      200,
		Subdomains: a.Names,
		Callback:   dogpileURLByPageNum,
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

func (a *Amass) GoogleSearch() Searcher {
	return &searchEngine{
		Name:       "Google Search",
		Quantity:   20,
		Limit:      150,
		Subdomains: a.Names,
		Callback:   googleURLByPageNum,
	}
}

func yahooURLByPageNum(y *searchEngine, domain string, page int) string {
	b := strconv.Itoa(y.Quantity * page)
	pz := strconv.Itoa(y.Quantity)

	u, _ := url.Parse("http://search.yahoo.com/search")
	u.RawQuery = url.Values{"p": {"\"" + domain + "\""}, "b": {b}, "pz": {pz}}.Encode()

	return u.String()
}

func (a *Amass) YahooSearch() Searcher {
	return &searchEngine{
		Name:       "Yahoo Search",
		Quantity:   20,
		Limit:      200,
		Subdomains: a.Names,
		Callback:   yahooURLByPageNum,
	}
}

//--------------------------------------------------------------------------------------------
// lookup - A searcher that attempts to discover information on a single web page
type lookup struct {
	Name       string
	Subdomains chan *Subdomain
	Callback   func(string) string
}

func (l *lookup) String() string {
	return l.Name
}

func (l *lookup) Search(domain, misc string, done chan int) {
	var unique []string

	re := SubdomainRegex(domain)
	page := GetWebPage(l.Callback(domain))
	if page == "" {
		done <- 0
		return
	}

	for _, sd := range re.FindAllString(page, -1) {
		u := NewUniqueElements(unique, sd)

		if len(u) > 0 {
			unique = append(unique, u...)
			l.Subdomains <- &Subdomain{
				Name:   sd,
				Domain: domain,
				Tag:    SEARCH,
			}
		}
	}
	done <- len(unique)
}

func censysURL(domain string) string {
	format := "https://www.censys.io/domain/%s/table"

	return fmt.Sprintf(format, domain)
}

func (a *Amass) CensysSearch() Searcher {
	return &lookup{
		Name:       "Censys Search",
		Subdomains: a.Names,
		Callback:   censysURL,
	}
}

func crtshURL(domain string) string {
	return "https://crt.sh/?q=%25." + domain
}

// CrtshSearch - A searcher that attempts to discover names from SSL certificates
func (a *Amass) CrtshSearch() Searcher {
	return &lookup{
		Name:       "Crtsh Search",
		Subdomains: a.Names,
		Callback:   crtshURL,
	}
}

func netcraftURL(domain string) string {
	format := "https://searchdns.netcraft.com/?restriction=site+ends+with&host=%s"

	return fmt.Sprintf(format, domain)
}

func (a *Amass) NetcraftSearch() Searcher {
	return &lookup{
		Name:       "Netcraft Search",
		Subdomains: a.Names,
		Callback:   netcraftURL,
	}
}

func robtexURL(domain string) string {
	format := "https://www.robtex.com/dns-lookup/%s"

	return fmt.Sprintf(format, domain)
}

func (a *Amass) RobtexSearch() Searcher {
	return &lookup{
		Name:       "Robtex Search",
		Subdomains: a.Names,
		Callback:   robtexURL,
	}
}

func threatCrowdURL(domain string) string {
	format := "https://www.threatcrowd.org/searchApi/v2/domain/report/?domain=%s"

	return fmt.Sprintf(format, domain)
}

func (a *Amass) ThreatCrowdSearch() Searcher {
	return &lookup{
		Name:       "ThreatCrowd Search",
		Subdomains: a.Names,
		Callback:   threatCrowdURL,
	}
}

func virusTotalURL(domain string) string {
	format := "https://www.virustotal.com/en/domain/%s/information/"

	return fmt.Sprintf(format, domain)
}

func (a *Amass) VirusTotalSearch() Searcher {
	return &lookup{
		Name:       "VirusTotal Search",
		Subdomains: a.Names,
		Callback:   virusTotalURL,
	}
}

//--------------------------------------------------------------------------------------------

type dumpster struct {
	Name       string
	Base       string
	Subdomains chan *Subdomain
}

func (d *dumpster) String() string {
	return d.Name
}

func (d *dumpster) Search(domain, misc string, done chan int) {
	var unique []string

	page := GetWebPage(d.Base)
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
			d.Subdomains <- &Subdomain{
				Name:   sd,
				Domain: domain,
				Tag:    SEARCH,
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
	client := &http.Client{}
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

func (a *Amass) DNSDumpsterSearch() Searcher {
	return &dumpster{
		Name:       "DNSDumpster",
		Base:       "https://dnsdumpster.com/",
		Subdomains: a.Names,
	}
}

//--------------------------------------------------------------------------------------------
// Searches and Lookups for Reverse IP

type reverseIPSearchRequest struct {
	Domain string
	IP     string
	Done   chan int
}

// reverseIPSearchEngine - A searcher that attempts to discover DNS names from an IP address using a search engine
type reverseIPSearchEngine struct {
	Name       string
	Quantity   int
	Limit      int
	Subdomains chan *Subdomain
	Callback   func(*reverseIPSearchEngine, string, int) string
	Requests   chan *reverseIPSearchRequest
}

func (se *reverseIPSearchEngine) String() string {
	return se.Name
}

func (se *reverseIPSearchEngine) urlByPageNum(ip string, page int) string {
	return se.Callback(se, ip, page)
}

func (se *reverseIPSearchEngine) Search(domain, misc string, done chan int) {
	se.Requests <- &reverseIPSearchRequest{
		Domain: domain,
		IP:     misc,
		Done:   done,
	}
}

func (se *reverseIPSearchEngine) performReverseIPSearches() {
	t := time.NewTicker(1 * time.Second)
	defer t.Stop()

	for range t.C {
		se.reverseIPSearch(<-se.Requests)
	}
}

func (se *reverseIPSearchEngine) reverseIPSearch(request *reverseIPSearchRequest) {
	var unique []string

	re := SubdomainRegex(request.Domain)
	num := se.Limit / se.Quantity
	for i := 0; i < num; i++ {
		page := GetWebPage(se.urlByPageNum(request.IP, i))
		if page == "" {
			break
		}

		for _, sd := range re.FindAllString(page, -1) {
			u := NewUniqueElements(unique, sd)

			if len(u) > 0 {
				unique = append(unique, u...)
				se.Subdomains <- &Subdomain{
					Name:   sd,
					Domain: request.Domain,
					Tag:    SEARCH,
				}
			}
		}
		// Do not hit Bing too hard
		time.Sleep(500 * time.Millisecond)
	}
	request.Done <- len(unique)
}

func bingReverseIPURLByPageNum(b *reverseIPSearchEngine, ip string, page int) string {
	count := strconv.Itoa(b.Quantity)
	first := strconv.Itoa((page * b.Quantity) + 1)
	u, _ := url.Parse("http://www.bing.com/search")

	u.RawQuery = url.Values{"q": {"ip:" + ip},
		"count": {count}, "first": {first}, "FORM": {"PORE"}}.Encode()
	return u.String()
}

func (a *Amass) BingReverseIPSearch() Searcher {
	b := &reverseIPSearchEngine{
		Name:       "Bing Reverse IP Search",
		Quantity:   5,
		Limit:      50,
		Subdomains: a.Names,
		Callback:   bingReverseIPURLByPageNum,
		Requests:   make(chan *reverseIPSearchRequest, 200),
	}
	go b.performReverseIPSearches()
	return b
}

type reverseIPLookupRequest struct {
	Domain string
	IP     string
	Done   chan int
}

// reverseIPLookup - A searcher that attempts to discover DNS names from an IP address using a single web page
type reverseIPLookup struct {
	Name       string
	Subdomains chan *Subdomain
	Callback   func(string) string
	Requests   chan *reverseIPLookupRequest
}

func (l *reverseIPLookup) String() string {
	return l.Name
}

func (l *reverseIPLookup) Search(domain, misc string, done chan int) {
	l.Requests <- &reverseIPLookupRequest{
		Domain: domain,
		IP:     misc,
		Done:   done,
	}
}

func (l *reverseIPLookup) performReverseIPLookups() {
	t := time.NewTicker(1 * time.Second)
	defer t.Stop()

	for range t.C {
		l.reverseIPLookup(<-l.Requests)
	}
}

func (l *reverseIPLookup) reverseIPLookup(request *reverseIPLookupRequest) {
	var unique []string

	re := SubdomainRegex(request.Domain)
	page := GetWebPage(l.Callback(request.IP))
	if page == "" {
		request.Done <- 0
		return
	}

	for _, sd := range re.FindAllString(page, -1) {
		u := NewUniqueElements(unique, sd)

		if len(u) > 0 {
			unique = append(unique, u...)
			l.Subdomains <- &Subdomain{
				Name:   sd,
				Domain: request.Domain,
				Tag:    SEARCH,
			}
		}
	}
	request.Done <- len(unique)
}

func shodanReverseIPURL(ip string) string {
	format := "https://www.shodan.io/host/%s"

	return fmt.Sprintf(format, ip)
}

func (a *Amass) ShodanReverseIPSearch() Searcher {
	ss := &reverseIPLookup{
		Name:       "Shodan Reverse IP Search",
		Subdomains: a.Names,
		Callback:   shodanReverseIPURL,
		Requests:   make(chan *reverseIPLookupRequest, 200),
	}
	go ss.performReverseIPLookups()
	return ss
}

//--------------------------------------------------------------------------------------------

func GetWebPage(u string) string {
	client := &http.Client{}

	req, err := http.NewRequest("GET", u, nil)
	if err != nil {
		return ""
	}

	req.Header.Add("User-Agent", USER_AGENT)
	req.Header.Add("Accept", ACCEPT)
	req.Header.Add("Accept-Language", ACCEPT_LANG)

	resp, err := client.Do(req)
	if err != nil {
		return ""
	}

	in, err := ioutil.ReadAll(resp.Body)
	resp.Body.Close()
	return string(in)
}
