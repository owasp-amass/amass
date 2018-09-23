// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package utils

import (
	"context"
	"errors"
	"io/ioutil"
	"net"
	"net/http"
	"strings"
	"time"
)

const (
	USER_AGENT  = "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/65.0.3325.181 Safari/537.36"
	ACCEPT      = "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8"
	ACCEPT_LANG = "en-US,en;q=0.8"
)

type DialCtx func(ctx context.Context, network, addr string) (net.Conn, error)

var (
	DialContext DialCtx
)

func init() {
	d := &net.Dialer{}

	DialContext = d.DialContext
}

func SetDialContext(dc DialCtx) {
	DialContext = dc
}

func GetWebPage(url string, hvals map[string]string) (string, error) {
	client := &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			DialContext:           DialContext,
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
		return "", err
	} else if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", errors.New(resp.Status)
	}

	in, err := ioutil.ReadAll(resp.Body)
	resp.Body.Close()
	return string(in), nil
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

func HexString(b []byte) string {
	hexDigit := "0123456789abcdef"
	s := make([]byte, len(b)*2)
	for i, tn := range b {
		s[i*2], s[i*2+1] = hexDigit[tn>>4], hexDigit[tn&0xf]
	}
	return string(s)
}
