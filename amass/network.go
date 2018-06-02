// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package amass

import (
	"bufio"
	"context"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	// An IPv4 regular expression
	IPv4RE = "((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)[.]){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)"
	// This regular expression + the base domain will match on all names and subdomains
	SUBRE = "(([a-zA-Z0-9]{1}|[a-zA-Z0-9]{1}[a-zA-Z0-9-]{0,61}[a-zA-Z0-9]{1})[.]{1})+"

	USER_AGENT  = "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/65.0.3325.181 Safari/537.36"
	ACCEPT      = "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8"
	ACCEPT_LANG = "en-US,en;q=0.8"
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
	// Caches the infrastructure data collected from online sources
	netDataLock  sync.Mutex
	netDataCache map[int]*ASRecord
)

func init() {
	netDataCache = make(map[int]*ASRecord)
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
		record.Netblocks = UniqueAppend(record.Netblocks, cidr)
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
		name = ReverseIP(addr) + ".origin.asn.cymru.com"
	} else if len(ip) == net.IPv6len {
		name = IPv6NibbleFormat(hexString(ip)) + ".origin6.asn.cymru.com"
	} else {
		return 0, ""
	}
	// Attempt multiple times since this is UDP
	for i := 0; i < 10; i++ {
		answers, err = ResolveDNS(name, "TXT")
		if err == nil {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	// Did we receive the DNS answer?
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
	// Attempt multiple times since this is UDP
	for i := 0; i < 10; i++ {
		answers, err = ResolveDNS(name, "TXT")
		if err == nil {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	// Did we receive the DNS answer?
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

func DNSDialContext(ctx context.Context, network, address string) (net.Conn, error) {
	d := &net.Dialer{}

	return d.DialContext(ctx, network, NextResolverAddress())
}

func DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	d := &net.Dialer{
		// Override the Go default DNS resolver to prevent leakage
		Resolver: &net.Resolver{
			PreferGo: true,
			Dial:     DNSDialContext,
		},
	}
	return d.DialContext(ctx, network, address)
}

type dialCtx func(ctx context.Context, network, addr string) (net.Conn, error)

func GetWebPageWithDialContext(dc dialCtx, u string, hvals map[string]string) string {
	client := &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			DialContext:           dc,
			MaxIdleConns:          200,
			IdleConnTimeout:       90 * time.Second,
			TLSHandshakeTimeout:   10 * time.Second,
			ExpectContinueTimeout: 5 * time.Second,
		},
	}

	req, err := http.NewRequest("GET", u, nil)
	if err != nil {
		return ""
	}

	req.Header.Add("User-Agent", USER_AGENT)
	req.Header.Add("Accept", ACCEPT)
	req.Header.Add("Accept-Language", ACCEPT_LANG)
	if hvals != nil {
		for k, v := range hvals {
			req.Header.Add(k, v)
		}
	}

	resp, err := client.Do(req)
	if err != nil {
		return ""
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return ""
	}

	in, err := ioutil.ReadAll(resp.Body)
	resp.Body.Close()
	return string(in)
}

// LookupIPHistory - Attempts to obtain IP addresses used by a root domain name
func LookupIPHistory(domain string) []string {
	url := "http://viewdns.info/iphistory/?domain=" + domain
	// The ViewDNS IP History lookup sometimes reveals interesting results
	page := GetWebPageWithDialContext(DialContext, url, nil)
	if page == "" {
		return nil
	}
	// Look for IP addresses in the web page returned
	var unique []string

	re := regexp.MustCompile(IPv4RE)
	for _, sd := range re.FindAllString(page, -1) {
		u := NewUniqueElements(unique, sd)

		if len(u) > 0 {
			unique = append(unique, u...)
		}
	}
	// Each IP address could provide a netblock to investigate
	return unique
}

func RangeHosts(start, end net.IP) []net.IP {
	var ips []net.IP

	stop := net.ParseIP(end.String())
	addrInc(stop)
	for ip := net.ParseIP(start.String()); !ip.Equal(stop); addrInc(ip) {
		addr := net.ParseIP(ip.String())

		ips = append(ips, addr)
	}
	return ips
}

// Obtained/modified the next two functions from the following:
// https://gist.github.com/kotakanbe/d3059af990252ba89a82
func NetHosts(cidr *net.IPNet) []net.IP {
	var ips []net.IP

	for ip := cidr.IP.Mask(cidr.Mask); cidr.Contains(ip); addrInc(ip) {
		addr := net.ParseIP(ip.String())

		ips = append(ips, addr)
	}
	// Remove network address and broadcast address
	return ips[1 : len(ips)-1]
}

func addrInc(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

func addrDec(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		if ip[j] > 0 {
			ip[j]--
			break
		}
		ip[j]--
	}
}

// getCIDRSubset - Returns a subset of the hosts slice with num elements around the addr element
func CIDRSubset(cidr *net.IPNet, addr string, num int) []net.IP {
	first := net.ParseIP(addr)

	if !cidr.Contains(first) {
		return []net.IP{first}
	}

	offset := num / 2
	// Get the first address
	for i := 0; i < offset; i++ {
		addrDec(first)
		// Check that it is still within the CIDR
		if !cidr.Contains(first) {
			addrInc(first)
			break
		}
	}
	// Get the last address
	last := net.ParseIP(addr)
	for i := 0; i < offset; i++ {
		addrInc(last)
		// Check that it is still within the CIDR
		if !cidr.Contains(last) {
			addrDec(last)
			break
		}
	}
	// Check that the addresses are not the same
	if first.Equal(last) {
		return []net.IP{first}
	}
	// Return the IP addresses within the range
	return RangeHosts(first, last)
}

func ReverseIP(ip string) string {
	var reversed []string

	parts := strings.Split(ip, ".")
	li := len(parts) - 1

	for i := li; i >= 0; i-- {
		reversed = append(reversed, parts[i])
	}

	return strings.Join(reversed, ".")
}

func IPv6NibbleFormat(ip string) string {
	var reversed []string

	parts := strings.Split(ip, "")
	li := len(parts) - 1

	for i := li; i >= 0; i-- {
		reversed = append(reversed, parts[i])
	}

	return strings.Join(reversed, ".")
}

func SubdomainRegex(domain string) *regexp.Regexp {
	// Change all the periods into literal periods for the regex
	d := strings.Replace(domain, ".", "[.]", -1)

	return regexp.MustCompile(SUBRE + d)
}

func AnySubdomainRegex() *regexp.Regexp {
	return regexp.MustCompile(SUBRE + "[a-zA-Z0-9-]{0,61}[.][a-zA-Z]")
}

func hexString(b []byte) string {
	hexDigit := "0123456789abcdef"
	s := make([]byte, len(b)*2)
	for i, tn := range b {
		s[i*2], s[i*2+1] = hexDigit[tn>>4], hexDigit[tn&0xf]
	}
	return string(s)
}

func trim252F(name string) string {
	s := strings.ToLower(name)

	re, err := regexp.Compile("^((252f)|(2f)|(3d))+")
	if err != nil {
		return s
	}

	i := re.FindStringIndex(s)
	if i != nil {
		return s[i[1]:]
	}
	return s
}

//--------------------------------------------------------------------------------------------------
// ReverseWhois - Returns domain names that are related to the domain provided
func ReverseWhois(domain string) []string {
	var domains []string

	page := GetWebPageWithDialContext(DialContext,
		"http://viewdns.info/reversewhois/?q="+domain, nil)
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
