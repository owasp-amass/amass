// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package amass

import (
	"fmt"
	"net/url"
	"regexp"
	"strconv"
	"time"
)

const NUM_SEARCHES int = 11

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

	re, err := regexp.Compile(SUBRE + domain)
	if err != nil {
		done <- 0
		return
	}

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

func AskSearch(subdomains chan *Subdomain) Searcher {
	a := new(searchEngine)

	a.name = "Ask Search"
	// ask.com appears to be hardcoded at 10 results per page
	a.quantity = 10
	a.limit = 200
	a.subdomains = subdomains
	a.callback = askURLByPageNum
	return a
}

func bingURLByPageNum(b *searchEngine, domain string, page int) string {
	count := strconv.Itoa(b.quantity)
	first := strconv.Itoa((page * b.quantity) + 1)

	u, _ := url.Parse("http://www.bing.com/search")
	u.RawQuery = url.Values{"q": {"domain:" + domain},
		"count": {count}, "first": {first}, "FORM": {"PORE"}}.Encode()

	return u.String()
}

func BingSearch(subdomains chan *Subdomain) Searcher {
	b := new(searchEngine)

	b.name = "Bing Search"
	b.quantity = 20
	b.limit = 400
	b.subdomains = subdomains
	b.callback = bingURLByPageNum
	return b
}

func dogpileURLByPageNum(d *searchEngine, domain string, page int) string {
	qsi := strconv.Itoa(d.quantity * page)

	u, _ := url.Parse("http://www.dogpile.com/search/web")
	u.RawQuery = url.Values{"qsi": {qsi}, "q": {"\"" + domain + "\""}}.Encode()

	return u.String()
}

func DogpileSearch(subdomains chan *Subdomain) Searcher {
	d := new(searchEngine)

	d.name = "Dogpile Search"
	// Dogpile returns roughly 15 results per page
	d.quantity = 15
	d.limit = 300
	d.subdomains = subdomains
	d.callback = dogpileURLByPageNum
	return d
}

func gigablastURLByPageNum(g *searchEngine, domain string, page int) string {
	s := strconv.Itoa(g.quantity * page)

	u, _ := url.Parse("http://www.gigablast.com/search")
	u.RawQuery = url.Values{"q": {domain}, "niceness": {"1"},
		"icc": {"1"}, "dr": {"1"}, "spell": {"0"}, "s": {s}}.Encode()

	return u.String()
}

func GigablastSearch(subdomains chan *Subdomain) Searcher {
	g := new(searchEngine)

	g.name = "Gigablast Search"
	g.subdomains = subdomains
	// Gigablast.com appears to be hardcoded at 10 results per page
	g.quantity = 10
	g.limit = 200
	g.callback = gigablastURLByPageNum
	return g
}

func yahooURLByPageNum(y *searchEngine, domain string, page int) string {
	b := strconv.Itoa(y.quantity * page)
	pz := strconv.Itoa(y.quantity)

	u, _ := url.Parse("http://search.yahoo.com/search")
	u.RawQuery = url.Values{"p": {"\"" + domain + "\""}, "b": {b}, "pz": {pz}}.Encode()

	return u.String()
}

func YahooSearch(subdomains chan *Subdomain) Searcher {
	y := new(searchEngine)

	y.name = "Yahoo Search"
	y.quantity = 20
	y.limit = 400
	y.subdomains = subdomains
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

	re, err := regexp.Compile(SUBRE + domain)
	if err != nil {
		done <- 0
		return
	}

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

func CensysSearch(subdomains chan *Subdomain) Searcher {
	c := new(lookup)

	c.name = "Censys Search"
	c.subdomains = subdomains
	c.callback = censysURL
	return c
}

func crtshURL(domain string) string {
	u, _ := url.Parse("https://crt.sh/")
	u.RawQuery = url.Values{"q": {"%25" + domain}}.Encode()

	return u.String()
}

func CrtshSearch(subdomains chan *Subdomain) Searcher {
	c := new(lookup)

	c.name = "Crtsh Search"
	c.subdomains = subdomains
	c.callback = crtshURL
	return c
}

func netcraftURL(domain string) string {
	format := "https://searchdns.netcraft.com/?restriction=site+ends+with&host=%s"

	return fmt.Sprintf(format, domain)
}

func NetcraftSearch(subdomains chan *Subdomain) Searcher {
	n := new(lookup)

	n.name = "Netcraft Search"
	n.subdomains = subdomains
	n.callback = netcraftURL
	return n
}

func pgpURL(domain string) string {
	u, _ := url.Parse("http://pgp.mit.edu/pks/lookup")
	u.RawQuery = url.Values{"search": {domain}, "op": {"index"}}.Encode()

	return u.String()
}

func PGPSearch(subdomains chan *Subdomain) Searcher {
	p := new(lookup)

	p.name = "PGP Search"
	p.subdomains = subdomains
	p.callback = pgpURL
	return p
}

func robtexURL(domain string) string {
	format := "https://www.robtex.com/dns-lookup/%s"

	return fmt.Sprintf(format, domain)
}

func RobtexSearch(subdomains chan *Subdomain) Searcher {
	r := new(lookup)

	r.name = "Robtex Search"
	r.subdomains = subdomains
	r.callback = robtexURL
	return r
}

func virusTotalURL(domain string) string {
	format := "https://www.virustotal.com/en/domain/%s/information/"

	return fmt.Sprintf(format, domain)
}

func VirusTotalSearch(subdomains chan *Subdomain) Searcher {
	vt := new(lookup)

	vt.name = "VirusTotal Search"
	vt.subdomains = subdomains
	vt.callback = virusTotalURL
	return vt
}
