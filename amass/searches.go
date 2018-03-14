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

type SubdomainSearchService struct {
	BaseAmassService

	responses    chan *AmassRequest
	searches     []Searcher
	filter       map[string]struct{}
	domainFilter map[string]struct{}
}

func NewSubdomainSearchService(in, out chan *AmassRequest, config *AmassConfig) *SubdomainSearchService {
	sss := &SubdomainSearchService{
		responses:    make(chan *AmassRequest, 50),
		filter:       make(map[string]struct{}),
		domainFilter: make(map[string]struct{}),
	}

	sss.BaseAmassService = *NewBaseAmassService("Subdomain Name Search Service", config, sss)
	sss.searches = []Searcher{
		AskSearch(sss.responses),
		BaiduSearch(sss.responses),
		CensysSearch(sss.responses),
		CrtshSearch(sss.responses),
		GoogleSearch(sss.responses),
		NetcraftSearch(sss.responses),
		RobtexSearch(sss.responses),
		BingSearch(sss.responses),
		DogpileSearch(sss.responses),
		YahooSearch(sss.responses),
		ThreatCrowdSearch(sss.responses),
		VirusTotalSearch(sss.responses),
		DNSDumpsterSearch(sss.responses),
	}

	sss.input = in
	sss.output = out
	return sss
}

func (sss *SubdomainSearchService) OnStart() error {
	sss.BaseAmassService.OnStart()

	go sss.executeAllSearches()
	go sss.processOutput()
	return nil
}

func (sss *SubdomainSearchService) OnStop() error {
	sss.BaseAmassService.OnStop()
	return nil
}

func (sss *SubdomainSearchService) processOutput() {
loop:
	for {
		select {
		case out := <-sss.responses:
			if !sss.duplicate(out.Name) {
				sss.SendOut(out)
			}
		case <-sss.Quit():
			break loop
		}
	}
}

// Returns true if the subdomain name is a duplicate entry in the filter.
// If not, the subdomain name is added to the filter
func (sss *SubdomainSearchService) duplicate(sub string) bool {
	if _, found := sss.filter[sub]; found {
		return true
	}
	sss.filter[sub] = struct{}{}
	return false
}

func (sss *SubdomainSearchService) executeAllSearches() {
	done := make(chan int)

	sss.SetActive(true)
	// Loop over all the root domains provided in the config
	for _, domain := range sss.Config().Domains {
		if _, found := sss.domainFilter[domain]; found {
			continue
		}
		// Kick off all the searches
		for _, s := range sss.searches {
			go s.Search(domain, done)
		}
		// Wait for them to complete
		for i := 0; i < NUM_SEARCHES; i++ {
			<-done
		}
	}
	sss.SetActive(false)
}

// Searcher - represents all types that perform searches for domain names
type Searcher interface {
	Search(domain string, done chan int)
	fmt.Stringer
}

// searchEngine - A searcher that attempts to discover information using a web search engine
type searchEngine struct {
	Name     string
	Quantity int
	Limit    int
	Output   chan<- *AmassRequest
	Callback func(*searchEngine, string, int) string
}

func (se *searchEngine) String() string {
	return se.Name
}

func (se *searchEngine) urlByPageNum(domain string, page int) string {
	return se.Callback(se, domain, page)
}

func (se *searchEngine) Search(domain string, done chan int) {
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

func AskSearch(out chan<- *AmassRequest) Searcher {
	return &searchEngine{
		Name:     "Ask",
		Quantity: 10, // ask.com appears to be hardcoded at 10 results per page
		Limit:    200,
		Output:   out,
		Callback: askURLByPageNum,
	}
}

func baiduURLByPageNum(d *searchEngine, domain string, page int) string {
	pn := strconv.Itoa(page)
	u, _ := url.Parse("https://www.baidu.com/s")

	u.RawQuery = url.Values{"pn": {pn}, "wd": {domain}, "oq": {domain}}.Encode()
	return u.String()
}

func BaiduSearch(out chan<- *AmassRequest) Searcher {
	return &searchEngine{
		Name:     "Baidu",
		Quantity: 20,
		Limit:    200,
		Output:   out,
		Callback: baiduURLByPageNum,
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

func BingSearch(out chan<- *AmassRequest) Searcher {
	return &searchEngine{
		Name:     "Bing",
		Quantity: 20,
		Limit:    200,
		Output:   out,
		Callback: bingURLByPageNum,
	}
}

func dogpileURLByPageNum(d *searchEngine, domain string, page int) string {
	qsi := strconv.Itoa(d.Quantity * page)
	u, _ := url.Parse("http://www.dogpile.com/search/web")

	u.RawQuery = url.Values{"qsi": {qsi}, "q": {domain}}.Encode()
	return u.String()
}

func DogpileSearch(out chan<- *AmassRequest) Searcher {
	return &searchEngine{
		Name:     "Dogpile",
		Quantity: 15, // Dogpile returns roughly 15 results per page
		Limit:    200,
		Output:   out,
		Callback: dogpileURLByPageNum,
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

func GoogleSearch(out chan<- *AmassRequest) Searcher {
	return &searchEngine{
		Name:     "Google",
		Quantity: 20,
		Limit:    150,
		Output:   out,
		Callback: googleURLByPageNum,
	}
}

func yahooURLByPageNum(y *searchEngine, domain string, page int) string {
	b := strconv.Itoa(y.Quantity * page)
	pz := strconv.Itoa(y.Quantity)

	u, _ := url.Parse("http://search.yahoo.com/search")
	u.RawQuery = url.Values{"p": {"\"" + domain + "\""}, "b": {b}, "pz": {pz}}.Encode()

	return u.String()
}

func YahooSearch(out chan<- *AmassRequest) Searcher {
	return &searchEngine{
		Name:     "Yahoo",
		Quantity: 20,
		Limit:    200,
		Output:   out,
		Callback: yahooURLByPageNum,
	}
}

//--------------------------------------------------------------------------------------------
// lookup - A searcher that attempts to discover information on a single web page
type lookup struct {
	Name     string
	Output   chan<- *AmassRequest
	Callback func(string) string
}

func (l *lookup) String() string {
	return l.Name
}

func (l *lookup) Search(domain string, done chan int) {
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

func CensysSearch(out chan<- *AmassRequest) Searcher {
	return &lookup{
		Name:     "Censys",
		Output:   out,
		Callback: censysURL,
	}
}

func crtshURL(domain string) string {
	return "https://crt.sh/?q=%25." + domain
}

// CrtshSearch - A searcher that attempts to discover names from SSL certificates
func CrtshSearch(out chan<- *AmassRequest) Searcher {
	return &lookup{
		Name:     "crtsh",
		Output:   out,
		Callback: crtshURL,
	}
}

func netcraftURL(domain string) string {
	format := "https://searchdns.netcraft.com/?restriction=site+ends+with&host=%s"

	return fmt.Sprintf(format, domain)
}

func NetcraftSearch(out chan<- *AmassRequest) Searcher {
	return &lookup{
		Name:     "Netcraft",
		Output:   out,
		Callback: netcraftURL,
	}
}

func robtexURL(domain string) string {
	format := "https://www.robtex.com/dns-lookup/%s"

	return fmt.Sprintf(format, domain)
}

func RobtexSearch(out chan<- *AmassRequest) Searcher {
	return &lookup{
		Name:     "Robtex",
		Output:   out,
		Callback: robtexURL,
	}
}

func threatCrowdURL(domain string) string {
	format := "https://www.threatcrowd.org/searchApi/v2/domain/report/?domain=%s"

	return fmt.Sprintf(format, domain)
}

func ThreatCrowdSearch(out chan<- *AmassRequest) Searcher {
	return &lookup{
		Name:     "ThreatCrowd",
		Output:   out,
		Callback: threatCrowdURL,
	}
}

func virusTotalURL(domain string) string {
	format := "https://www.virustotal.com/en/domain/%s/information/"

	return fmt.Sprintf(format, domain)
}

func VirusTotalSearch(out chan<- *AmassRequest) Searcher {
	return &lookup{
		Name:     "VirusTotal",
		Output:   out,
		Callback: virusTotalURL,
	}
}

//--------------------------------------------------------------------------------------------

type dumpster struct {
	Name   string
	Base   string
	Output chan<- *AmassRequest
}

func (d *dumpster) String() string {
	return d.Name
}

func (d *dumpster) Search(domain string, done chan int) {
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

func DNSDumpsterSearch(out chan<- *AmassRequest) Searcher {
	return &dumpster{
		Name:   "DNSDumpster",
		Base:   "https://dnsdumpster.com/",
		Output: out,
	}
}
