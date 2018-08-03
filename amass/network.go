// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package amass

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"net"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/OWASP/Amass/amass/core"
	"github.com/OWASP/Amass/amass/utils"
	"github.com/OWASP/Amass/amass/dnssrv"
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

		if _, err := dnssrv.Resolve(sub, "NS"); err == nil {
			domainCache[sub] = struct{}{}
			domain = sub
			break
		}
	}
	return domain
}

func IPRequest(addr string) (int, *net.IPNet, string, error) {
	netDataLock.Lock()
	defer netDataLock.Unlock()

	// Is the data already available in the cache?
	asn, cidr, desc := ipSearch(addr)
	if asn != 0 {
		return asn, cidr, desc, nil
	}
	// Need to pull the online data
	record, err := fetchOnlineData(addr, 0)
	if err != nil {
		return 0, nil, "", err
	}
	// Add it to the cache
	netDataCache[record.ASN] = record
	// Lets try again
	asn, cidr, desc = ipSearch(addr)
	if asn == 0 {
		return 0, nil, "", fmt.Errorf("IPRequest failed to find data for %s after an online search", addr)
	}
	return asn, cidr, desc, nil
}

func ASNRequest(asn int) (*ASRecord, error) {
	netDataLock.Lock()
	defer netDataLock.Unlock()

	var err error

	record, found := netDataCache[asn]
	if !found {
		record, err = fetchOnlineData("", asn)
		if err != nil {
			return nil, err
		}
		// Insert the AS record into the cache
		netDataCache[record.ASN] = record
	}
	return record, nil
}

func CIDRRequest(cidr *net.IPNet) (int, string, error) {
	netDataLock.Lock()
	defer netDataLock.Unlock()

	asn, desc := cidrSearch(cidr)
	// Does the data need to be obtained?
	if asn != 0 {
		return asn, desc, nil
	}
	// Need to pull the online data
	record, err := fetchOnlineData(cidr.IP.String(), 0)
	if err != nil {
		return 0, "", err
	}
	// Add it to the cache
	netDataCache[record.ASN] = record
	// Lets try again
	asn, desc = cidrSearch(cidr)
	if asn == 0 {
		return 0, "", fmt.Errorf("CIDRRequest failed to find data for %s after an online search", cidr)
	}
	return asn, desc, nil
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

func compareCIDRSizes(first, second *net.IPNet) int {
	var result int = 0

	s1, _ := first.Mask.Size()
	s2, _ := second.Mask.Size()
	if s1 > s2 {
		result = 1
	} else if s2 > s1 {
		result = -1
	}
	return result
}

func ipSearch(addr string) (int, *net.IPNet, string) {
	var a int
	var cidr *net.IPNet
	var desc string

	ip := net.ParseIP(addr)
	// Check that the necessary data is already cached
	for asn, record := range netDataCache {
		for _, netblock := range record.Netblocks {
			_, ipnet, err := net.ParseCIDR(netblock)
			if err != nil {
				continue
			}

			if ipnet.Contains(ip) {
				// Select the smallest CIDR
				if cidr != nil && compareCIDRSizes(cidr, ipnet) == 1 {
					continue
				}
				a = asn
				cidr = ipnet
				desc = record.Description
			}
		}
	}
	return a, cidr, desc
}

func fetchOnlineData(addr string, asn int) (*ASRecord, error) {
	if addr == "" && asn == 0 {
		return nil, fmt.Errorf("fetchOnlineData params are insufficient: addr: %s asn: %d", addr, asn)
	}

	var err error
	var cidr string
	// If the ASN was not provided, look it up
	if asn == 0 {
		asn, cidr, err = originLookup(addr)
		if err != nil {
			return nil, err
		}
	}
	record, ok := netDataCache[asn]
	if !ok {
		// Get the ASN record from the online source
		record, err = asnLookup(asn)
		if err != nil {
			return nil, err
		}
		// Get the netblocks associated with this ASN
		record.Netblocks, err = fetchOnlineNetblockData(asn)
		if err != nil {
			return nil, err
		}
	}
	if cidr != "" {
		record.Netblocks = utils.UniqueAppend(record.Netblocks, cidr)
	}
	if len(record.Netblocks) == 0 {
		return nil, fmt.Errorf("fetchOnlineData failed to obtain netblocks for ASN: %d", asn)
	}
	return record, nil
}

func originLookup(addr string) (int, string, error) {
	var err error
	var name string
	var answers []core.DNSAnswer

	if ip := net.ParseIP(addr); len(ip.To4()) == net.IPv4len {
		name = utils.ReverseIP(addr) + ".origin.asn.cymru.com"
	} else if len(ip) == net.IPv6len {
		name = utils.IPv6NibbleFormat(utils.HexString(ip)) + ".origin6.asn.cymru.com"
	} else {
		return 0, "", fmt.Errorf("originLookup param is insufficient: addr: %s", ip)
	}

	answers, err = dnssrv.Resolve(name, "TXT")
	if err != nil {
		return 0, "", fmt.Errorf("originLookup: DNS TXT record query error: %s: %v", name, err)
	}
	// Retrieve the ASN
	fields := strings.Split(answers[0].Data, " | ")
	asn, err := strconv.Atoi(fields[0])
	if err != nil {
		return 0, "", fmt.Errorf("originLookup: Failed to extract the ASN: %s: %v", fields[0], err)
	}
	return asn, strings.TrimSpace(fields[1]), nil
}

func asnLookup(asn int) (*ASRecord, error) {
	var err error
	var answers []core.DNSAnswer

	// Get the AS record using the ASN
	name := "AS" + strconv.Itoa(asn) + ".asn.cymru.com"

	answers, err = dnssrv.Resolve(name, "TXT")
	if err != nil {
		return nil, fmt.Errorf("asnLookup: DNS TXT record query error: %s: %v", name, err)
	}
	// Parse the record returned
	record := parseASNInfo(answers[0].Data)
	if record == nil {
		return nil, fmt.Errorf("asnLookup: Failed to parse data: %s", answers[0].Data)
	}
	return record, nil
}

func fetchOnlineNetblockData(asn int) ([]string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	addr := "asn.shadowserver.org:43"
	conn, err := dnssrv.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("fetchOnlineNetblockData error: %s: %v", addr, err)
	}
	defer conn.Close()

	fmt.Fprintf(conn, "prefix %d\n", asn)
	scanner := bufio.NewScanner(conn)

	var blocks []string
	for scanner.Scan() {
		line := scanner.Text()

		if err := scanner.Err(); err == nil {
			blocks = append(blocks, strings.TrimSpace(line))
		}
	}

	if len(blocks) == 0 {
		return nil, errors.New("fetchOnlineNetblockData error: No netblocks acquired")
	}
	return blocks, nil
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
func LookupIPHistory(domain string) ([]string, error) {
	var unique []string

	url := "http://viewdns.info/iphistory/?domain=" + domain
	// The ViewDNS IP History lookup sometimes reveals interesting results
	page, err := utils.GetWebPage(url, nil)
	if err != nil {
		return unique, err
	}

	// Look for IP addresses in the web page returned
	re := regexp.MustCompile(utils.IPv4RE)
	for _, sd := range re.FindAllString(page, -1) {
		u := utils.NewUniqueElements(unique, sd)

		if len(u) > 0 {
			unique = append(unique, u...)
		}
	}
	// Each IP address could provide a netblock to investigate
	return unique, nil
}

//--------------------------------------------------------------------------------------------------
// ReverseWhois - Returns domain names that are related to the domain provided
func ReverseWhois(domain string) ([]string, error) {
	var domains []string

	page, err := utils.GetWebPage("http://viewdns.info/reversewhois/?q="+domain, nil)
	if err != nil {
		return domains, err
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
	return domains, nil
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
