// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package net

import (
	"bytes"
	"math/big"
	"net"
	"strconv"
	"strings"
)

// IPv4RE is a regular expression that will match an IPv4 address.
const IPv4RE = "((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)[.]){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)"

// ReservedCIDRs includes all the networks that are reserved for special use.
var ReservedCIDRs = []string{
	"192.168.0.0/16",
	"172.16.0.0/12",
	"10.0.0.0/8",
	"127.0.0.0/8",
	"224.0.0.0/4",
	"240.0.0.0/4",
	"100.64.0.0/10",
	"198.18.0.0/15",
	"169.254.0.0/16",
	"192.88.99.0/24",
	"192.0.0.0/24",
	"192.0.2.0/24",
	"192.94.77.0/24",
	"192.94.78.0/24",
	"192.52.193.0/24",
	"192.12.109.0/24",
	"192.31.196.0/24",
	"192.0.0.0/29",
}

// IsIPv4 returns true when the provided net.IP address is an IPv4 address.
func IsIPv4(ip net.IP) bool {
	return strings.Count(ip.String(), ":") < 2
}

// IsIPv6 returns true when the provided net.IP address is an IPv6 address.
func IsIPv6(ip net.IP) bool {
	return strings.Count(ip.String(), ":") >= 2
}

// FirstLast return the first and last IP address of the provided CIDR/netblock.
func FirstLast(cidr *net.IPNet) (net.IP, net.IP) {
	firstIP := cidr.IP
	prefixLen, bits := cidr.Mask.Size()

	if prefixLen == bits {
		lastIP := make([]byte, len(firstIP))
		copy(lastIP, firstIP)
		return firstIP, lastIP
	}

	firstIPInt, bits := ipToInt(firstIP)
	hostLen := uint(bits) - uint(prefixLen)
	lastIPInt := big.NewInt(1)

	lastIPInt.Lsh(lastIPInt, hostLen)
	lastIPInt.Sub(lastIPInt, big.NewInt(1))
	lastIPInt.Or(lastIPInt, firstIPInt)

	return firstIP, intToIP(lastIPInt, bits)
}

// Range2CIDR turns an IP range into a CIDR.
func Range2CIDR(first, last net.IP) *net.IPNet {
	startip, m := ipToInt(first)
	endip, _ := ipToInt(last)
	newip := big.NewInt(1)
	mask := big.NewInt(1)
	one := big.NewInt(1)

	if startip.Cmp(endip) == 1 {
		return nil
	}

	max := uint(m)
	var bits uint = 1
	newip.Set(startip)
	tmp := new(big.Int)
	for bits < max {
		tmp.Rsh(startip, bits)
		tmp.Lsh(tmp, bits)

		newip.Or(startip, mask)
		if newip.Cmp(endip) == 1 || tmp.Cmp(startip) != 0 {
			bits--
			mask.Rsh(mask, 1)
			break
		}

		bits++
		tmp.Lsh(mask, 1)
		mask.Add(tmp, one)
	}

	cidrstr := first.String() + "/" + strconv.Itoa(int(max-bits))
	_, ipnet, _ := net.ParseCIDR(cidrstr)

	return ipnet
}

// AllHosts returns a slice containing all the IP addresses within
// the CIDR provided by the parameter. This implementation was
// obtained/modified from the following:
// https://gist.github.com/kotakanbe/d3059af990252ba89a82
func AllHosts(cidr *net.IPNet) []net.IP {
	var ips []net.IP

	for ip := cidr.IP.Mask(cidr.Mask); cidr.Contains(ip); IPInc(ip) {
		addr := net.ParseIP(ip.String())

		ips = append(ips, addr)
	}

	if len(ips) > 2 {
		// Remove network address and broadcast address
		ips = ips[1 : len(ips)-1]
	}
	return ips
}

// RangeHosts returns all the IP addresses (inclusive) between
// the start and stop addresses provided by the parameters.
func RangeHosts(start, end net.IP) []net.IP {
	var ips []net.IP

	if start == nil || end == nil {
		return ips
	}

	start16 := start.To16()
	end16 := end.To16()
	// Check that the end address is higher than the start address
	if r := bytes.Compare(end16, start16); r < 0 {
		return ips
	} else if r == 0 {
		return []net.IP{start}
	}

	stop := net.ParseIP(end.String())
	IPInc(stop)

	for ip := net.ParseIP(start.String()); !ip.Equal(stop); IPInc(ip) {
		if addr := net.ParseIP(ip.String()); addr != nil {
			ips = append(ips, addr)
		}
	}

	return ips
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
		IPDec(first)
		// Check that it is still within the CIDR
		if !cidr.Contains(first) {
			IPInc(first)
			break
		}
	}
	// Get the last address
	last := net.ParseIP(addr)
	for i := 0; i < offset; i++ {
		IPInc(last)
		// Check that it is still within the CIDR
		if !cidr.Contains(last) {
			IPDec(last)
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

// IPInc increments the IP address provided.
func IPInc(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

// IPDec decrements the IP address provided.
func IPDec(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		if ip[j] > 0 {
			ip[j]--
			break
		}
		ip[j]--
	}
}

func ipToInt(ip net.IP) (*big.Int, int) {
	val := big.NewInt(1)

	val.SetBytes([]byte(ip))
	if IsIPv4(ip) {
		return val, 32
	} else if IsIPv6(ip) {
		return val, 128
	}

	return val, 0
}

func intToIP(ipInt *big.Int, bits int) net.IP {
	ipBytes := ipInt.Bytes()
	ret := make([]byte, bits/8)

	// Pack our IP bytes into the end of the return array,
	// since big.Int.Bytes() removes front zero padding
	for i := 1; i <= len(ipBytes); i++ {
		ret[len(ret)-i] = ipBytes[len(ipBytes)-i]
	}

	return net.IP(ret)
}
