// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package dns

import (
	"encoding/hex"
	"net"
	"regexp"
	"strings"
)

// SUBRE is a regular expression that will match on all subdomains once the domain is appended.
const SUBRE = "(([a-zA-Z0-9]{1}|[_a-zA-Z0-9]{1}[_a-zA-Z0-9-]{0,61}[a-zA-Z0-9]{1})[.]{1})+"

// SubdomainRegex returns a Regexp object initialized to match
// subdomain names that end with the domain provided by the parameter.
func SubdomainRegex(domain string) *regexp.Regexp {
	// Change all the periods into literal periods for the regex
	d := strings.Replace(domain, ".", "[.]", -1)

	return regexp.MustCompile(SUBRE + d)
}

// AnySubdomainRegex returns a Regexp object initialized to match any DNS subdomain name.
func AnySubdomainRegex() *regexp.Regexp {
	return regexp.MustCompile(SUBRE + "[a-zA-Z]{2,61}")
}

// CopyString return a new string variable with the same value as the parameter.
func CopyString(src string) string {
	str := make([]byte, len(src))

	copy(str, src)
	return string(str)
}

// RemoveAsteriskLabel returns the provided DNS name with all asterisk labels removed.
func RemoveAsteriskLabel(s string) string {
	startIndex := strings.LastIndex(s, "*.")

	if startIndex == -1 {
		return s
	}

	return s[startIndex+2:]
}

// ReverseString returns the characters of the argument string in reverse order.
func ReverseString(s string) string {
	chrs := []rune(s)
	end := len(chrs) / 2

	for i, j := 0, len(chrs)-1; i < end; i, j = i+1, j-1 {
		chrs[i], chrs[j] = chrs[j], chrs[i]
	}

	return string(chrs)
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

	ip = strings.ReplaceAll(expandIPv6Addr(ip), ":", "")
	parts := strings.Split(ip, "")
	li := len(parts) - 1

	for i := li; i >= 0; i-- {
		reversed = append(reversed, parts[i])
	}

	return strings.Join(reversed, ".")
}

func expandIPv6Addr(addr string) string {
	ip := net.ParseIP(addr)

	dst := make([]byte, hex.EncodedLen(len(ip)))
	hex.Encode(dst, ip)

	return string(dst[0:4]) + ":" +
		string(dst[4:8]) + ":" +
		string(dst[8:12]) + ":" +
		string(dst[12:16]) + ":" +
		string(dst[16:20]) + ":" +
		string(dst[20:24]) + ":" +
		string(dst[24:28]) + ":" +
		string(dst[28:])
}
