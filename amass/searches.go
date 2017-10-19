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

const NUM_SEARCHES int = 9

type searchEngine struct {
	name       string
	domain     string
	quantity   int
	limit      int
	subdomains chan *Subdomain
	callback   func(searchEngine, int) string
}

func (se searchEngine) String() string {
	return se.name
}

func (se searchEngine) Domain() string {
	return se.domain
}

func (se searchEngine) Quantity() int {
	return se.quantity
}

func (se searchEngine) Limit() int {
	return se.limit
}

func (se searchEngine) URLByPageNum(page int) string {
	return se.callback(se, page)
}

func (se searchEngine) Search(done chan int) {
	var unique []string

	re, err := regexp.Compile(SUBRE + se.Domain())
	if err != nil {
		done <- 0
		return
	}

	num := se.Limit() / se.Quantity()
	for i := 0; i < num; i++ {
		page := GetWebPage(se.URLByPageNum(i))
		if page == "" {
			break
		}

		for _, sd := range re.FindAllString(page, -1) {
			u := NewUniqueElements(unique, sd)

			if len(u) > 0 {
				unique = append(unique, u...)
				se.subdomains <- &Subdomain{Name: sd, Domain: se.Domain(), Tag: SEARCH}
			}
		}

		time.Sleep(1 * time.Second)
	}

	done <- len(unique)
	return
}

func askURLByPageNum(a searchEngine, page int) string {
	pu := strconv.Itoa(a.quantity)
	p := strconv.Itoa(page)

	u, _ := url.Parse("http://www.ask.com/web")
	u.RawQuery = url.Values{"q": {a.domain}, "pu": {pu}, "page": {p}}.Encode()

	return u.String()
}

func AskSearch(domain string, subdomains chan *Subdomain) Searcher {
	a := new(searchEngine)

	a.name = "Ask Search"
	a.domain = domain
	// ask.com appears to be hardcoded at 10 results per page
	a.quantity = 10
	a.limit = 200
	a.subdomains = subdomains
	a.callback = askURLByPageNum
	return a
}

func bingURLByPageNum(b searchEngine, page int) string {
	count := strconv.Itoa(b.quantity)
	first := strconv.Itoa((page * b.quantity) + 1)

	u, _ := url.Parse("http://www.bing.com/search")
	u.RawQuery = url.Values{"q": {"domain:" + b.domain},
		"count": {count}, "first": {first}, "FORM": {"PORE"}}.Encode()

	return u.String()
}

func BingSearch(domain string, subdomains chan *Subdomain) Searcher {
	b := new(searchEngine)

	b.name = "Bing Search"
	b.domain = domain
	b.quantity = 20
	b.limit = 400
	b.subdomains = subdomains
	b.callback = bingURLByPageNum
	return b
}

func censysURLByPageNum(c searchEngine, page int) string {
	format := "https://www.censys.io/domain/%s/table"

	return fmt.Sprintf(format, c.domain)
}

func CensysSearch(domain string, subdomains chan *Subdomain) Searcher {
	c := new(searchEngine)

	c.name = "Censys Search"
	c.domain = domain
	c.quantity = 1
	c.limit = 1
	c.subdomains = subdomains
	c.callback = censysURLByPageNum
	return c
}

func crtshURLByPageNum(c searchEngine, page int) string {
	u, _ := url.Parse("https://crt.sh/")
	u.RawQuery = url.Values{"q": {"%25" + c.domain}}.Encode()

	return u.String()
}

func CrtshSearch(domain string, subdomains chan *Subdomain) Searcher {
	c := new(searchEngine)

	c.name = "Crtsh Search"
	c.domain = domain
	c.quantity = 1
	c.limit = 1
	c.subdomains = subdomains
	c.callback = crtshURLByPageNum
	return c
}

func dogpileURLByPageNum(d searchEngine, page int) string {
	qsi := strconv.Itoa(d.quantity * page)

	u, _ := url.Parse("http://www.dogpile.com/search/web")
	u.RawQuery = url.Values{"qsi": {qsi}, "q": {"\"" + d.domain + "\""}}.Encode()

	return u.String()
}

func DogpileSearch(domain string, subdomains chan *Subdomain) Searcher {
	d := new(searchEngine)

	d.name = "Dogpile Search"
	d.domain = domain
	// Dogpile returns roughly 15 results per page
	d.quantity = 15
	d.limit = 300
	d.subdomains = subdomains
	d.callback = dogpileURLByPageNum
	return d
}

func gigablastURLByPageNum(g searchEngine, page int) string {
	s := strconv.Itoa(g.quantity * page)

	u, _ := url.Parse("http://www.gigablast.com/search")
	u.RawQuery = url.Values{"q": {g.domain}, "niceness": {"1"},
		"icc": {"1"}, "dr": {"1"}, "spell": {"0"}, "s": {s}}.Encode()

	return u.String()
}

func GigablastSearch(domain string, subdomains chan *Subdomain) Searcher {
	g := new(searchEngine)

	g.name = "Gigablast Search"
	g.domain = domain
	g.subdomains = subdomains
	// Gigablast.com appears to be hardcoded at 10 results per page
	g.quantity = 10
	g.limit = 200
	g.callback = gigablastURLByPageNum
	return g
}

func pgpURLByPageNum(p searchEngine, page int) string {
	u, _ := url.Parse("http://pgp.mit.edu/pks/lookup")
	u.RawQuery = url.Values{"search": {p.domain}, "op": {"index"}}.Encode()

	return u.String()
}

func PGPSearch(domain string, subdomains chan *Subdomain) Searcher {
	p := new(searchEngine)

	p.name = "PGP Search"
	p.domain = domain
	p.quantity = 1
	p.limit = 1
	p.subdomains = subdomains
	p.callback = pgpURLByPageNum
	return p
}

func robtexURLByPageNum(r searchEngine, page int) string {
	format := "https://www.robtex.com/dns-lookup/%s"

	return fmt.Sprintf(format, r.domain)
}

func RobtexSearch(domain string, subdomains chan *Subdomain) Searcher {
	r := new(searchEngine)

	r.name = "Robtex Search"
	r.domain = domain
	r.quantity = 1
	r.limit = 1
	r.subdomains = subdomains
	r.callback = robtexURLByPageNum
	return r
}

func yahooURLByPageNum(y searchEngine, page int) string {
	b := strconv.Itoa(y.quantity * page)
	pz := strconv.Itoa(y.quantity)

	u, _ := url.Parse("http://search.yahoo.com/search")
	u.RawQuery = url.Values{"p": {"\"" + y.domain + "\""}, "b": {b}, "pz": {pz}}.Encode()

	return u.String()
}

func YahooSearch(domain string, subdomains chan *Subdomain) Searcher {
	y := new(searchEngine)

	y.name = "Yahoo Search"
	y.domain = domain
	y.quantity = 20
	y.limit = 400
	y.subdomains = subdomains
	y.callback = yahooURLByPageNum
	return y
}
