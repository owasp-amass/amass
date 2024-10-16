// Copyright © by Jeff Foley 2017-2024. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package support

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/caffix/queue"
	"github.com/caffix/stringset"
	"github.com/owasp-amass/amass/v4/config"
	et "github.com/owasp-amass/amass/v4/engine/types"
	amassnet "github.com/owasp-amass/amass/v4/utils/net"
	"github.com/owasp-amass/amass/v4/utils/net/dns"
	dbt "github.com/owasp-amass/asset-db/types"
	oam "github.com/owasp-amass/open-asset-model"
	"github.com/owasp-amass/open-asset-model/domain"
	oamnet "github.com/owasp-amass/open-asset-model/network"
	"github.com/owasp-amass/open-asset-model/url"
	"github.com/owasp-amass/resolve"
	xurls "mvdan.cc/xurls/v2"
)

type SweepCallback func(d *et.Event, addr *oamnet.IPAddress, src *dbt.Asset)

const MaxHandlerInstances int = 100

var done chan struct{}
var subre, urlre *regexp.Regexp

func init() {
	done = make(chan struct{})
	rate := resolve.NewRateTracker()
	trusted, _ = trustedResolvers()
	trusted.SetRateTracker(rate)

	dbQueue = queue.NewQueue()
	go processDBCallbacks()

	urlre = xurls.Relaxed()
	subre = regexp.MustCompile(dns.AnySubdomainRegexString())

	postalHost = os.Getenv("POSTAL_SERVER_HOST")
	postalPort = os.Getenv("POSTAL_SERVER_PORT")
}

func ScrapeSubdomainNames(s string) []string {
	set := stringset.New()
	defer set.Close()

	for _, sub := range subre.FindAllString(s, -1) {
		if sub != "" {
			set.Insert(sub)
		}
	}

	return set.Slice()
}

func ExtractURLFromString(s string) *url.URL {
	if u := urlre.FindString(s); u != "" {
		if !strings.HasPrefix(u, "http") && !strings.HasPrefix(u, "https") {
			u = "http://" + u
		}
		return RawURLToOAM(u)
	}
	return nil
}

func ExtractURLsFromString(s string) []*url.URL {
	var results []*url.URL

	matches := urlre.FindAllString(s, -1)
	if matches == nil {
		return results
	}

	for _, match := range matches {
		if match != "" {
			if !strings.HasPrefix(match, "http") && !strings.HasPrefix(match, "https") {
				match = "http://" + match
			}
			if u := RawURLToOAM(match); u != nil {
				results = append(results, u)
			}
		}
	}
	return results
}

func Shutdown() {
	close(done)
}

func TTLStartTime(c *config.Config, from, to, plugin string) (time.Time, error) {
	now := time.Now()

	if matches, err := c.CheckTransformations(from, to, plugin); err == nil && matches != nil {
		if ttl := matches.TTL(plugin); ttl >= 0 {
			return now.Add(time.Duration(-ttl) * time.Minute), nil
		}
		if ttl := matches.TTL(to); ttl >= 0 {
			return now.Add(time.Duration(-ttl) * time.Minute), nil
		}
	}

	return time.Time{}, fmt.Errorf("failed to obtain the TTL for transformation %s->%s", from, to)
}

func GetAPI(name string, e *et.Event) (string, error) {
	// TODO: Add support for multiple API keys
	dsc := e.Session.Config().GetDataSourceConfig(name)
	if dsc == nil || len(dsc.Creds) == 0 {
		return "", errors.New("no API key found")
	}

	for _, cred := range dsc.Creds {
		if cred != nil && cred.Apikey != "" {
			return cred.Apikey, nil
		}
	}

	return "", errors.New("no API key found")
}

func IPToNetblockWithAttempts(session et.Session, ip *oamnet.IPAddress, num int, d time.Duration) (*oamnet.Netblock, error) {
	var err error
	var nb *oamnet.Netblock

	for i := 0; i < num; i++ {
		nb, err = IPToNetblock(session, ip)
		if err == nil {
			break
		}
		time.Sleep(d)
	}

	return nb, err
}

func IPToNetblock(session et.Session, ip *oamnet.IPAddress) (*oamnet.Netblock, error) {
	var size int
	var found *oamnet.Netblock

	if assets, hit := session.Cache().GetAssetsByType(oam.Netblock); hit && len(assets) > 0 {
		for _, a := range assets {
			if nb, ok := a.Asset.(*oamnet.Netblock); ok && nb.CIDR.Contains(ip.Address) {
				if s := nb.CIDR.Masked().Bits(); s > size {
					size = s
					found = nb
				}
			}
		}
	}

	if found == nil {
		return nil, errors.New("no netblock match in the cache")
	}
	return found, nil
}

func IPAddressSweep(e *et.Event, addr *oamnet.IPAddress, src *dbt.Asset, size int, callback SweepCallback) {
	// do not work on an IP address that been processed previously
	_, hit := e.Session.Cache().GetAsset(addr)
	if hit {
		return
	}

	n, err := IPToNetblockWithAttempts(e.Session, addr, 60, time.Second)
	if err != nil {
		return
	}

	addrstr := addr.Address.String()
	_, cidr, err := net.ParseCIDR(n.CIDR.String())
	if err != nil || cidr == nil {
		a := net.ParseIP(addrstr)
		mask := net.CIDRMask(18, 32)
		if amassnet.IsIPv6(a) {
			mask = net.CIDRMask(64, 128)
		}

		cidr = &net.IPNet{
			IP:   a.Mask(mask),
			Mask: mask,
		}
	}

	for _, ip := range amassnet.CIDRSubset(cidr, addrstr, size) {
		a := oamnet.IPAddress{
			Type:    "IPv4",
			Address: netip.MustParseAddr(ip.String()),
		}
		if a.Address.Is6() {
			a.Type = "IPv6"
		}
		callback(e, &a, src)
	}
}

func IsCNAME(session et.Session, name *domain.FQDN) (*domain.FQDN, bool) {
	fqdn, hit := session.Cache().GetAsset(name)
	if !hit || fqdn == nil {
		return nil, false
	}

	if relations, hit := session.Cache().GetRelations(&dbt.Relation{
		Type:      "cname_record",
		FromAsset: fqdn,
	}); hit && len(relations) > 0 {
		if cname, ok := relations[0].ToAsset.Asset.(*domain.FQDN); ok {
			return cname, true
		}
	}
	return nil, false
}

func NameIPAddresses(session et.Session, name *domain.FQDN) []*oamnet.IPAddress {
	fqdn, hit := session.Cache().GetAsset(name)
	if !hit || fqdn == nil {
		return nil
	}

	var results []*oamnet.IPAddress
	if relations, hit := session.Cache().GetRelations(&dbt.Relation{
		Type:      "a_record",
		FromAsset: fqdn,
	}); hit && len(relations) > 0 {
		for _, r := range relations {
			if ip, ok := r.ToAsset.Asset.(*oamnet.IPAddress); ok {
				results = append(results, ip)
			}
		}
	}

	if relations, hit := session.Cache().GetRelations(&dbt.Relation{
		Type:      "aaaa_record",
		FromAsset: fqdn,
	}); hit && len(relations) > 0 {
		for _, r := range relations {
			if ip, ok := r.ToAsset.Asset.(*oamnet.IPAddress); ok {
				results = append(results, ip)
			}
		}
	}

	if len(results) > 0 {
		return results
	}
	return nil
}

func NameResolved(session et.Session, name *domain.FQDN) bool {
	if _, found := IsCNAME(session, name); found {
		return true
	}
	if ips := NameIPAddresses(session, name); len(ips) > 0 {
		return true
	}
	return false
}
