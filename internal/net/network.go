// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package net

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
)

// Maximum number of connections allowed by each process.
const MaxNetworkConns = 500

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

// The reserved network address ranges
var reservedAddrRanges []*net.IPNet

type Semaphore chan struct{}

func init() {
	for _, cidr := range ReservedCIDRs {
		if _, ipnet, err := net.ParseCIDR(cidr); err == nil {
			reservedAddrRanges = append(reservedAddrRanges, ipnet)
		}
	}
}

func NewSemaphore(cap int) Semaphore {
	sem := make(Semaphore, cap)

	for range cap {
		sem <- struct{}{}
	}

	return sem
}

func (r Semaphore) Acquire() {
	<-r
}

func (r Semaphore) Release() {
	select {
	case r <- struct{}{}:
	default:
	}
}

type DialContext func(ctx context.Context, network, addr string) (net.Conn, error)

// NewDialContext returns a dial function that sends from the local
// addresses for its context (see LocalAddrsFrom): an IPv4 destination from
// the IPv4 address and an IPv6 destination from the IPv6 address. When the
// context's interface lacks an address of a destination's IP version, that
// destination is not reached at all, rather than through another interface.
func NewDialContext(timeout time.Duration) DialContext {
	return func(ctx context.Context, network, address string) (net.Conn, error) {
		d := net.Dialer{
			Timeout:   timeout,
			KeepAlive: 30 * time.Second,
		}

		local := LocalAddrsFrom(ctx)
		if local.IsZero() {
			return d.DialContext(ctx, network, address)
		}
		return dialFrom(ctx, d, local, network, address)
	}
}

// dialFrom dials address from the local address of each destination's IP
// version, trying the destination's addresses in the order the resolver
// returns them.
func dialFrom(ctx context.Context, d net.Dialer, local LocalAddrs, network, address string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}

	var dsts []netip.Addr
	if ip, err := netip.ParseAddr(host); err == nil {
		dsts = []netip.Addr{ip.Unmap()}
	} else if dsts, err = net.DefaultResolver.LookupNetIP(ctx, "ip", host); err != nil {
		return nil, err
	}

	var errs []error
	for _, dst := range dsts {
		dst = dst.Unmap()
		la, ok := local.For(dst)
		if !ok {
			errs = append(errs, fmt.Errorf("%s: the local interface has no IPv%d address", dst, ipVersion(dst)))
			continue
		}

		ap := netip.AddrPortFrom(la, 0) // port 0 lets the kernel choose the source port
		if strings.HasPrefix(network, "udp") {
			d.LocalAddr = net.UDPAddrFromAddrPort(ap)
		} else {
			d.LocalAddr = net.TCPAddrFromAddrPort(ap)
		}

		c, err := d.DialContext(ctx, network, net.JoinHostPort(dst.String(), port))
		if err == nil {
			return c, nil
		}
		errs = append(errs, err)
		if ctx.Err() != nil {
			break
		}
	}

	if len(errs) == 0 {
		return nil, fmt.Errorf("no address found for %s", host)
	}
	return nil, errors.Join(errs...)
}

func ipVersion(ip netip.Addr) int {
	if ip.Is4() {
		return 4
	}
	return 6
}

// LocalAddrs are the local addresses traffic leaves from, one per IP
// version, both from the same network interface. The zero LocalAddrs leaves
// the choice to the system; otherwise a destination whose IP version has no
// address is not reached.
type LocalAddrs struct {
	V4 netip.Addr
	V6 netip.Addr
}

// IsZero reports whether the addresses leave the choice to the system.
func (l LocalAddrs) IsZero() bool {
	return !l.V4.IsValid() && !l.V6.IsValid()
}

// For returns the local address for a destination's IP version.
func (l LocalAddrs) For(dst netip.Addr) (netip.Addr, bool) {
	la := l.V6
	if dst.Unmap().Is4() {
		la = l.V4
	}
	return la, la.IsValid()
}

// List returns the valid addresses, IPv4 first.
func (l LocalAddrs) List() []netip.Addr {
	var out []netip.Addr
	for _, a := range []netip.Addr{l.V4, l.V6} {
		if a.IsValid() {
			out = append(out, a)
		}
	}
	return out
}

func (l LocalAddrs) String() string {
	parts := make([]string, 0, 2)
	for _, a := range l.List() {
		parts = append(parts, a.String())
	}
	if len(parts) == 0 {
		return "any local address"
	}
	return strings.Join(parts, " and ")
}

// engineAddrs are the local addresses the engine's traffic leaves from when
// a context names none.
var engineAddrs atomic.Pointer[LocalAddrs]

// SetLocalAddrs sets the local addresses the engine's traffic leaves from
// when a context names none. The zero LocalAddrs leaves the choice to the
// system.
func SetLocalAddrs(l LocalAddrs) {
	engineAddrs.Store(&l)
}

type localAddrsKey struct{}

// WithLocalAddrs returns a copy of ctx that names the local addresses for
// the traffic made with it. The zero LocalAddrs returns ctx itself.
func WithLocalAddrs(ctx context.Context, l LocalAddrs) context.Context {
	if l.IsZero() {
		return ctx
	}
	return context.WithValue(ctx, localAddrsKey{}, l)
}

// LocalAddrsFrom returns the local addresses for the traffic made with ctx:
// the ones ctx names, else the engine's, else the zero LocalAddrs, which
// leaves the choice to the system.
func LocalAddrsFrom(ctx context.Context) LocalAddrs {
	if ctx != nil {
		if l, ok := ctx.Value(localAddrsKey{}).(LocalAddrs); ok && !l.IsZero() {
			return l
		}
	}
	if l := engineAddrs.Load(); l != nil {
		return *l
	}
	return LocalAddrs{}
}

// InterfaceAddrs returns the local addresses for the network interface that
// spec names: an interface name, such as eth0, or one of the host's own IP
// addresses. For a name, they are the interface's first global unicast IPv4
// and IPv6 addresses; for an address, that address alone. An empty spec
// returns the zero LocalAddrs, which leaves the choice to the system.
func InterfaceAddrs(spec string) (LocalAddrs, error) {
	spec = strings.TrimSpace(spec)
	if spec == "" {
		return LocalAddrs{}, nil
	}

	if ip, err := netip.ParseAddr(spec); err == nil {
		addrs, err := net.InterfaceAddrs()
		if err != nil {
			return LocalAddrs{}, err
		}

		ip = ip.Unmap()
		for _, a := range addrs {
			if local, ok := interfaceIP(a); ok && local == ip.WithZone("") {
				if ip.Is4() {
					return LocalAddrs{V4: ip}, nil
				}
				return LocalAddrs{V6: ip}, nil
			}
		}
		return LocalAddrs{}, fmt.Errorf("the address %s is not on a network interface of this host", spec)
	}

	ifc, err := net.InterfaceByName(spec)
	if err != nil {
		return LocalAddrs{}, fmt.Errorf("the network interface %q: %w", spec, err)
	}

	addrs, err := ifc.Addrs()
	if err != nil {
		return LocalAddrs{}, fmt.Errorf("the network interface %q: %w", spec, err)
	}

	var l LocalAddrs
	for _, a := range addrs {
		ip, ok := interfaceIP(a)
		if !ok || !ip.IsGlobalUnicast() {
			continue
		}
		if ip.Is4() && !l.V4.IsValid() {
			l.V4 = ip
		} else if ip.Is6() && !l.V6.IsValid() {
			l.V6 = ip
		}
	}

	if l.IsZero() {
		return LocalAddrs{}, fmt.Errorf("the network interface %q has no global unicast address", spec)
	}
	return l, nil
}

// interfaceIP returns the IP address of an interface address.
func interfaceIP(a net.Addr) (netip.Addr, bool) {
	var ip net.IP
	switch v := a.(type) {
	case *net.IPNet:
		ip = v.IP
	case *net.IPAddr:
		ip = v.IP
	default:
		return netip.Addr{}, false
	}

	addr, ok := IPToAddr(ip)
	return addr.Unmap(), ok
}

// IsIPv4 returns true when the provided net.IP address is an IPv4 address.
func IsIPv4(ip net.IP) bool {
	return strings.Count(ip.String(), ":") < 2
}

// IsIPv6 returns true when the provided net.IP address is an IPv6 address.
func IsIPv6(ip net.IP) bool {
	return strings.Count(ip.String(), ":") >= 2
}

// IPToAddr converts a net.IP to netip.Addr, handling both IPv4 and IPv6.
// Returns an error if the IP is invalid.
func IPToAddr(ip net.IP) (netip.Addr, bool) {
	if v4 := ip.To4(); v4 != nil {
		return netip.AddrFromSlice(v4)
	}
	if v16 := ip.To16(); v16 != nil {
		return netip.AddrFromSlice(v16)
	}
	return netip.Addr{}, false
}

// IsReservedAddress checks if the addr parameter is within one of the address ranges in the ReservedCIDRs slice.
func IsReservedAddress(addr string) (bool, string) {
	ip := net.ParseIP(addr)
	if ip == nil {
		return false, ""
	}

	var cidr string
	for _, block := range reservedAddrRanges {
		if block.Contains(ip) {
			cidr = block.String()
			break
		}
	}

	if cidr != "" {
		return true, cidr
	}
	return false, ""
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
