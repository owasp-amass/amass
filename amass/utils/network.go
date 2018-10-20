// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package utils

import (
	"errors"
	"io/ioutil"
	"net"
	"net/http"
	"strings"
	"time"
)

const (
	// UserAgent is the default user agent used by Amass during HTTP requests.
	UserAgent = "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/65.0.3325.181 Safari/537.36"

	// Accept is the default HTTP Accept header value used by Amass.
	Accept = "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8"

	// AcceptLang is the default HTTP Accept-Language header value used by Amass.
	AcceptLang = "en-US,en;q=0.8"
)

// GetWebPage returns a string containing the entire web page indicated
// by the url parameter when successful. Header values can optionally be
// provided using the hvals parameter.
func GetWebPage(url string, hvals map[string]string) (string, error) {
	d := net.Dialer{}
	client := &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			DialContext:           d.DialContext,
			MaxIdleConns:          200,
			IdleConnTimeout:       90 * time.Second,
			TLSHandshakeTimeout:   10 * time.Second,
			ExpectContinueTimeout: 5 * time.Second,
		},
	}

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return "", err
	}

	req.Header.Add("User-Agent", UserAgent)
	req.Header.Add("Accept", Accept)
	req.Header.Add("Accept-Language", AcceptLang)
	if hvals != nil {
		for k, v := range hvals {
			req.Header.Add(k, v)
		}
	}

	resp, err := client.Do(req)
	if err != nil {
		return "", err
	} else if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", errors.New(resp.Status)
	}

	in, err := ioutil.ReadAll(resp.Body)
	resp.Body.Close()
	return string(in), nil
}

// NetHosts returns a slice containing all the IP addresses within
// the CIDR provided by the parameter. This implementation was
// obtained/modified from the following:
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

// RangeHosts returns all the IP addresses (inclusive) between
// the start and stop addresses provided by the parameters.
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

// CIDRSubset returns a subset of the IP addresses contained within
// the cidr parameter with num elements around the addr element.
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

// ReverseIP returns an IP address that is the ip parameter with the numbers reversed.
func ReverseIP(ip string) string {
	var reversed []string

	parts := strings.Split(ip, ".")
	li := len(parts) - 1

	for i := li; i >= 0; i-- {
		reversed = append(reversed, parts[i])
	}

	return strings.Join(reversed, ".")
}

// IPv6NibbleFormat expects an IPv6 address in the ip parameter and
// returns the address in nibble format.
func IPv6NibbleFormat(ip string) string {
	var reversed []string

	parts := strings.Split(ip, "")
	li := len(parts) - 1

	for i := li; i >= 0; i-- {
		reversed = append(reversed, parts[i])
	}

	return strings.Join(reversed, ".")
}

// HexString returns a string that is the hex representation of the byte slice parameter.
func HexString(b []byte) string {
	hexDigit := "0123456789abcdef"
	s := make([]byte, len(b)*2)
	for i, tn := range b {
		s[i*2], s[i*2+1] = hexDigit[tn>>4], hexDigit[tn&0xf]
	}
	return string(s)
}
