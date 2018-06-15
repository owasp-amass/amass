// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package amass

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/caffix/amass/amass/internal/utils"
)

type ASRecord struct {
	ASN            int
	Prefix         string
	CC             string
	Registry       string
	AllocationDate time.Time
	Description    string
	Netblocks      []string
}

var (
	// Cache for the infrastructure data collected from online sources
	netDataLock  sync.Mutex
	netDataCache map[int]*ASRecord
	// Domains discovered by the SubdomainToDomain method call
	domainLock  sync.Mutex
	domainCache map[string]struct{}
)

func init() {
	netDataCache = make(map[int]*ASRecord)
	domainCache = make(map[string]struct{})
}

func SubdomainToDomain(name string) string {
	domainLock.Lock()
	defer domainLock.Unlock()

	var domain string

	// Obtain all parts of the subdomain name
	labels := strings.Split(strings.TrimSpace(name), ".")
	// Check the cache for all parts of the name
	for i := len(labels); i >= 0; i-- {
		sub := strings.Join(labels[i:], ".")

		if _, ok := domainCache[sub]; ok {
			domain = sub
			break
		}
	}
	if domain != "" {
		return domain
	}
	// Check the DNS for all parts of the name
	for i := len(labels) - 2; i >= 0; i-- {
		sub := strings.Join(labels[i:], ".")

		if _, err := ResolveDNS(sub, "NS"); err == nil {
			domainCache[sub] = struct{}{}
			domain = sub
			break
		}
	}
	return domain
}

func IPRequest(addr string) (int, *net.IPNet, string) {
	netDataLock.Lock()
	defer netDataLock.Unlock()

	// Is the data already available in the cache?
	asn, cidr, desc := ipSearch(addr)
	if asn != 0 {
		return asn, cidr, desc
	}
	// Need to pull the online data
	record := fetchOnlineData(addr, 0)
	if record == nil {
		return 0, nil, ""
	}
	// Add it to the cache
	netDataCache[record.ASN] = record
	// Lets try again
	asn, cidr, desc = ipSearch(addr)
	if asn == 0 {
		return 0, nil, ""
	}
	return asn, cidr, desc
}

func ASNRequest(asn int) *ASRecord {
	netDataLock.Lock()
	defer netDataLock.Unlock()

	record, found := netDataCache[asn]
	if !found {
		record = fetchOnlineData("", asn)
		if record == nil {
			return nil
		}
		// Insert the AS record into the cache
		netDataCache[record.ASN] = record
	}
	return record
}

func CIDRRequest(cidr *net.IPNet) (int, string) {
	netDataLock.Lock()
	defer netDataLock.Unlock()

	asn, desc := cidrSearch(cidr)
	// Does the data need to be obtained?
	if asn != 0 {
		return asn, desc
	}
	// Need to pull the online data
	record := fetchOnlineData(cidr.IP.String(), 0)
	if record == nil {
		return 0, ""
	}
	// Add it to the cache
	netDataCache[record.ASN] = record
	// Lets try again
	asn, desc = cidrSearch(cidr)
	if asn == 0 {
		return 0, ""
	}
	return asn, desc
}

func cidrSearch(ipnet *net.IPNet) (int, string) {
	var a int
	var desc string
loop:
	// Check that the necessary data is already cached
	for asn, record := range netDataCache {
		for _, netblock := range record.Netblocks {
			if netblock == ipnet.String() {
				a = asn
				desc = record.Description
				break loop
			}
		}
	}
	return a, desc
}

func ipSearch(addr string) (int, *net.IPNet, string) {
	var a int
	var cidr *net.IPNet
	var desc string

	ip := net.ParseIP(addr)
loop:
	// Check that the necessary data is already cached
	for asn, record := range netDataCache {
		for _, netblock := range record.Netblocks {
			_, ipnet, err := net.ParseCIDR(netblock)
			if err != nil {
				continue
			}

			if ipnet.Contains(ip) {
				a = asn
				cidr = ipnet
				desc = record.Description
				break loop
			}
		}
	}
	return a, cidr, desc
}

func fetchOnlineData(addr string, asn int) *ASRecord {
	if addr == "" && asn == 0 {
		return nil
	}

	var cidr string
	// If the ASN was not provided, look it up
	if asn == 0 {
		asn, cidr = originLookup(addr)
		if asn == 0 {
			return nil
		}
	}
	record, ok := netDataCache[asn]
	if !ok {
		// Get the ASN record from the online source
		record = asnLookup(asn)
		if record == nil {
			return nil
		}
		// Get the netblocks associated with this ASN
		record.Netblocks = fetchOnlineNetblockData(asn)
	}
	// Just in case
	if cidr != "" {
		record.Netblocks = utils.UniqueAppend(record.Netblocks, cidr)
	}
	if len(record.Netblocks) == 0 {
		return nil
	}
	return record
}

func originLookup(addr string) (int, string) {
	var err error
	var name string
	var answers []DNSAnswer

	if ip := net.ParseIP(addr); len(ip.To4()) == net.IPv4len {
		name = utils.ReverseIP(addr) + ".origin.asn.cymru.com"
	} else if len(ip) == net.IPv6len {
		name = utils.IPv6NibbleFormat(utils.HexString(ip)) + ".origin6.asn.cymru.com"
	} else {
		return 0, ""
	}

	answers, err = ResolveDNS(name, "TXT")
	if err != nil {
		return 0, ""
	}
	// Retrieve the ASN
	fields := strings.Split(answers[0].Data, " | ")
	asn, err := strconv.Atoi(fields[0])
	if err != nil {
		return 0, ""
	}
	return asn, strings.TrimSpace(fields[1])
}

func asnLookup(asn int) *ASRecord {
	var err error
	var answers []DNSAnswer

	// Get the AS record using the ASN
	name := "AS" + strconv.Itoa(asn) + ".asn.cymru.com"

	answers, err = ResolveDNS(name, "TXT")
	if err != nil {
		return nil
	}
	// Parse the record returned
	record := parseASNInfo(answers[0].Data)
	if record == nil {
		return nil
	}
	return record
}

func fetchOnlineNetblockData(asn int) []string {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	conn, err := DialContext(ctx, "tcp", "asn.shadowserver.org:43")
	if err != nil {
		return []string{}
	}
	defer conn.Close()

	fmt.Fprintf(conn, "prefix %d\n", asn)
	reader := bufio.NewReader(conn)

	var blocks []string
	for err == nil {
		var line string

		line, err = reader.ReadString('\n')
		if len(line) > 0 {
			blocks = append(blocks, strings.TrimSpace(line))
		}
	}

	if len(blocks) == 0 {
		return []string{}
	}
	return blocks
}

func parseASNInfo(line string) *ASRecord {
	fields := strings.Split(line, " | ")

	asn, err := strconv.Atoi(fields[0])
	if err != nil {
		return nil
	}
	// Get the allocation date into the Go Time type
	t, err := time.Parse("2006-Jan-02", strings.TrimSpace(fields[3]))
	if err != nil {
		t = time.Now()
	}

	return &ASRecord{
		ASN:            asn,
		CC:             strings.TrimSpace(fields[1]),
		Registry:       strings.TrimSpace(fields[2]),
		AllocationDate: t,
		Description:    strings.TrimSpace(fields[4]),
	}
}

// LookupIPHistory - Attempts to obtain IP addresses used by a root domain name
func LookupIPHistory(domain string) []string {
	url := "http://viewdns.info/iphistory/?domain=" + domain
	// The ViewDNS IP History lookup sometimes reveals interesting results
	page := utils.GetWebPage(url, nil)
	if page == "" {
		return nil
	}
	// Look for IP addresses in the web page returned
	var unique []string

	re := regexp.MustCompile(utils.IPv4RE)
	for _, sd := range re.FindAllString(page, -1) {
		u := utils.NewUniqueElements(unique, sd)

		if len(u) > 0 {
			unique = append(unique, u...)
		}
	}
	// Each IP address could provide a netblock to investigate
	return unique
}

//--------------------------------------------------------------------------------------------------
// ReverseWhois - Returns domain names that are related to the domain provided
func ReverseWhois(domain string) []string {
	var domains []string

	page := utils.GetWebPage("http://viewdns.info/reversewhois/?q="+domain, nil)
	if page == "" {
		return []string{}
	}
	// Pull the table we need from the page content
	table := getViewDNSTable(page)
	// Get the list of domain names discovered through
	// the reverse DNS service
	re := regexp.MustCompile("<tr><td>([a-zA-Z0-9]{1}[a-zA-Z0-9-]{0,61}[a-zA-Z0-9]{1}[.]{1}[a-zA-Z0-9-]+)</td><td>")
	subs := re.FindAllStringSubmatch(table, -1)
	for _, match := range subs {
		sub := match[1]
		if sub == "" {
			continue
		}
		domains = append(domains, strings.TrimSpace(sub))
	}
	sort.Strings(domains)
	return domains
}

func getViewDNSTable(page string) string {
	var begin, end int

	s := page
	for i := 0; i < 4; i++ {
		b := strings.Index(s, "<table")
		if b == -1 {
			return ""
		}
		begin += b + 6

		if e := strings.Index(s[b:], "</table>"); e == -1 {
			return ""
		} else {
			end = begin + e
		}

		s = page[end+8:]
	}
	i := strings.Index(page[begin:end], "<table")
	i = strings.Index(page[begin+i+6:end], "<table")
	return page[begin+i : end]
}
