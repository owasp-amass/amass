// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package amass

import (
	"regexp"
	"sort"
	"strings"
	"sync"

	"github.com/irfansharif/cfilter"
	"github.com/likexian/whois-go"
	"github.com/likexian/whois-parser-go"
)

var (
	badWordFilter *cfilter.CFilter
	once          sync.Once
)

func initializeFilter() {
	badWordFilter = cfilter.New()

	badWordFilter.Insert([]byte("domain administrator"))
	badWordFilter.Insert([]byte("private registration"))
	badWordFilter.Insert([]byte("registration private"))
	badWordFilter.Insert([]byte("registration"))
	badWordFilter.Insert([]byte("domain manager"))
	badWordFilter.Insert([]byte("domain name coordinator"))
	badWordFilter.Insert([]byte("techcontact"))
	badWordFilter.Insert([]byte("technical contact"))
	badWordFilter.Insert([]byte("internet"))
	badWordFilter.Insert([]byte("hostmaster"))
	badWordFilter.Insert([]byte("united states"))
	badWordFilter.Insert([]byte("information"))
	badWordFilter.Insert([]byte("security officer"))
	badWordFilter.Insert([]byte("chief information security officer"))
	badWordFilter.Insert([]byte("chief information officer"))
	badWordFilter.Insert([]byte("information officer"))
	badWordFilter.Insert([]byte("information technology services"))
	badWordFilter.Insert([]byte("domains by proxy"))
	badWordFilter.Insert([]byte("perfect privacy"))

	return
}

func getTable(page string) string {
	var begin, end int
	s := page

	for i := 0; i < 4; i++ {
		b := strings.Index(s, "<table")
		if b == -1 {
			return ""
		}
		begin += b + 6

		e := strings.Index(s[b:], "</table>")
		if e == -1 {
			return ""
		}

		end = begin + e

		s = page[end+8:]
	}

	i := strings.Index(page[begin:end], "<table")
	i = strings.Index(page[begin+i+6:end], "<table")
	return page[begin+i : end]
}

func rawReverseWhoisData(domain string) []string {
	re, err := regexp.Compile(SUBRE + "[a-zA-Z]+")
	if err != nil {
		return nil
	}

	page := GetWebPage("http://viewdns.info/reversewhois/?q=" + domain)
	if page == "" {
		return nil
	}

	table := getTable(page)
	if table == "" {
		return nil
	}

	var unique []string

	for _, name := range re.FindAllString(table, -1) {
		unique = UniqueAppend(unique, name)
	}

	return unique
}

func compare(domain string, l []string, data whois_parser.WhoisInfo) bool {
	match := false
	dlist := list(domain, data)

	if len(dlist) == 0 {
		return false
	}

	for _, v := range l {
		if listCompare(v, dlist) {
			match = true
			break
		}
	}

	return match
}

func breakout(r whois_parser.Registrant) []string {
	var list []string

	list = UniqueAppend(list, strings.Split(r.Name, ",")...)
	list = UniqueAppend(list, strings.Split(r.Organization, ",")...)
	list = UniqueAppend(list, strings.Split(r.Street, ",")...)
	list = UniqueAppend(list, strings.Split(r.StreetExt, ",")...)
	list = UniqueAppend(list, strings.Split(r.Phone, ",")...)
	list = UniqueAppend(list, strings.Split(r.Email, ",")...)

	return list
}

func listCompare(s string, list []string) bool {
	if s == "" {
		return false
	}

	match := false

	for _, l := range list {
		if l == "" {
			continue
		}

		l = strings.TrimSpace(l)
		l = strings.ToLower(l)

		if strings.Compare(s, l) == 0 {
			match = true
			break
		}
	}

	return match
}

func filterList(list []string) []string {
	var fl []string

	for _, v := range list {
		if len(v) < 10 {
			continue
		}

		if !badWordFilter.Lookup([]byte(v)) {
			fl = append(fl, v)
		}
	}

	return fl
}

func list(domain string, data whois_parser.WhoisInfo) []string {
	var first, list []string

	first = UniqueAppend(first, strings.Split(data.Registrar.NameServers, ",")...)
	first = UniqueAppend(first, breakout(data.Registrant)...)
	first = UniqueAppend(first, breakout(data.Admin)...)
	first = UniqueAppend(first, breakout(data.Tech)...)
	first = UniqueAppend(first, breakout(data.Bill)...)

	for _, v := range first {
		if !strings.Contains(domain, v) {
			list = append(list, v)
		}
	}

	return filterList(list)
}

func attemptMatch(domain, candidate string, list []string, done chan string) {
	var result string

	if candidate == domain {
		done <- result
		return
	}

	c, err := whois.Whois(candidate)
	if err != nil {
		done <- result
		return
	}

	parsed, err := whois_parser.Parser(c)
	if err == nil {
		if compare(domain, list, parsed) {
			result = candidate
		}
	}

	done <- result
	return
}

func ReverseWhois(domain string) []string {
	w, err := whois.Whois(domain)
	if err != nil {
		return nil
	}

	target, err := whois_parser.Parser(w)
	if err != nil {
		return nil
	}

	once.Do(initializeFilter)

	tlist := list(domain, target)

	domainlist := rawReverseWhoisData(domain)
	if domainlist == nil {
		return nil
	}

	var done chan string = make(chan string, 10)

	for _, d := range domainlist {
		go attemptMatch(domain, d, tlist, done)
	}

	var results []string

	for count, l := 0, len(domainlist); count < l; count++ {
		match := <-done

		if match != "" {
			results = append(results, match)
		}
	}

	sort.Strings(results)
	return results
}
