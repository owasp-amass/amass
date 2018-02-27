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

func baiduURLByPageNum(d *searchEngine, domain string, page int) string {
	pn := strconv.Itoa(page)
	u, _ := url.Parse("https://www.baidu.com/s")

	u.RawQuery = url.Values{"pn": {pn}, "wd": {domain}, "oq": {domain}}.Encode()
	return u.String()
}

func (a *Amass) BaiduSearch() Searcher {
	b := new(searchEngine)

	b.name = "Baidu Search"
	b.quantity = 20
	b.limit = 200
	b.subdomains = a.Names
	b.callback = baiduURLByPageNum
	return b
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
	b.limit = 200
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
	d.limit = 200
	d.subdomains = a.Names
	d.callback = dogpileURLByPageNum
	return d
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
	g := new(searchEngine)

	g.name = "Google Search"
	g.quantity = 20
	g.limit = 150
	g.subdomains = a.Names
	g.callback = googleURLByPageNum
	return g
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
	y.limit = 200
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

func crtshURL(domain string) string {
	return "https://crt.sh/?q=%25." + domain
}

// CrtshSearch - A searcher that attempts to discover names from SSL certificates
func (a *Amass) CrtshSearch() Searcher {
	c := new(lookup)

	c.name = "Crtsh Search"
	c.subdomains = a.Names
	c.callback = crtshURL
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

func threatCrowdURL(domain string) string {
	format := "https://www.threatcrowd.org/searchApi/v2/domain/report/?domain=%s"

	return fmt.Sprintf(format, domain)
}

func (a *Amass) ThreatCrowdSearch() Searcher {
	tc := new(lookup)

	tc.name = "ThreatCrowd Search"
	tc.subdomains = a.Names
	tc.callback = threatCrowdURL
	return tc
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

type dumpster struct {
	name, base string
	subdomains chan *Subdomain
}

func (d *dumpster) String() string {
	return d.name
}

func (d *dumpster) Search(domain string, done chan int) {
	var unique []string

	page := GetWebPage(d.base)
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
			d.subdomains <- &Subdomain{Name: sd, Domain: domain, Tag: SEARCH}
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

	req, err := http.NewRequest("POST", d.base, strings.NewReader(params.Encode()))
	if err != nil {
		return ""
	}

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

	in, err := ioutil.ReadAll(resp.Body)
	resp.Body.Close()
	return string(in)
}

func (a *Amass) DNSDumpsterSearch() Searcher {
	d := new(dumpster)

	d.name = "DNSDumpster"
	d.base = "https://dnsdumpster.com/"
	d.subdomains = a.Names
	return d
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
