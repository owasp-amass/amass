// Copyright © by Jeff Foley 2017-2025. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package support

import (
	"context"
	"errors"
	"runtime"
	"strings"
	"time"

	"github.com/miekg/dns"
	"github.com/owasp-amass/resolve/conn"
	"github.com/owasp-amass/resolve/pool"
	"github.com/owasp-amass/resolve/selectors"
	"github.com/owasp-amass/resolve/servers"
	"github.com/owasp-amass/resolve/utils"
	"github.com/owasp-amass/resolve/wildcards"
	"golang.org/x/net/publicsuffix"
)

type baseline struct {
	address string
	qps     int
}

// baselineResolvers is a list of trusted public DNS resolvers.
var baselineResolvers = []baseline{
	{"8.8.8.8", 5},         // Google Primary
	{"8.8.4.4", 5},         // Google Secondary
	{"95.85.95.85", 2},     // Gcore DNS Primary
	{"2.56.220.2", 2},      // Gcore DNS Secondary
	{"76.76.2.0", 2},       // ControlD Primary
	{"76.76.10.0", 2},      // ControlD Secondary
	{"9.9.9.9", 2},         // Quad9 Primary
	{"149.112.112.112", 2}, // Quad9 Secondary
	{"208.67.222.222", 2},  // Cisco OpenDNS Home Primary
	{"208.67.220.220", 2},  // Cisco OpenDNS Home Secondary
	{"1.1.1.1", 3},         // Cloudflare Primary
	{"1.0.0.1", 3},         // Cloudflare Secondary
	{"185.228.168.9", 1},   // CleanBrowsing Primary
	{"185.228.169.9", 1},   // CleanBrowsing Secondary
	{"76.76.19.19", 1},     // Alternate DNS Primary
	{"76.223.122.150", 1},  // Alternate DNS Secondary
	{"94.140.14.14", 1},    // AdGuard DNS Primary
	{"94.140.15.15", 1},    // AdGuard DNS Secondary
	{"176.103.130.130", 1}, // AdGuard
	{"176.103.130.131", 1}, // AdGuard
	{"8.26.56.26", 1},      // Comodo Secure DNS Primary
	{"8.20.247.20", 1},     // Comodo Secure DNS Secondary
	{"205.171.3.65", 1},    // CenturyLink Level3 Primary
	{"205.171.2.65", 1},    // CenturyLink Level3 Secondary
	{"64.6.64.6", 1},       // Verisign DNS Primary
	{"64.6.65.6", 1},       // Verisign DNS Secondary
	{"209.244.0.3", 1},     // CenturyLink Level3
	{"209.244.0.4", 1},     // CenturyLink Level3
	{"149.112.121.10", 1},  // CIRA Canadian Shield Primary
	{"149.112.122.10", 1},  // CIRA Canadian Shield Secondary
	{"138.197.140.189", 1}, // OpenNIC Primary
	{"162.243.19.47", 1},   // OpenNIC Secondary
	{"216.87.84.211", 1},   // OpenNIC
	{"23.90.4.6", 1},       // OpenNIC
	{"216.146.35.35", 1},   // Oracle Dyn Primary
	{"216.146.36.36", 1},   // Oracle Dyn Secondary
	{"91.239.100.100", 1},  // UncensoredDNS Primary
	{"89.233.43.71", 1},    // UncensoredDNS Secondary
	{"77.88.8.8", 1},       // Yandex.DNS Primary
	{"77.88.8.1", 1},       // Yandex.DNS Secondary
	{"74.82.42.42", 1},     // Hurricane Electric Primary
	{"94.130.180.225", 1},  // DNS for Family Primary
	{"78.47.64.161", 1},    // DNS for Family Secondary
	{"80.80.80.80", 1},     // Freenom World Primary
	{"80.80.81.81", 1},     // Freenom World Secondary
	{"84.200.69.80", 1},    // DNS.WATCH Primary
	{"84.200.70.40", 1},    // DNS.WATCH Secondary
	{"156.154.70.5", 1},    // Neustar Primary
	{"156.157.71.5", 1},    // Neustar Secondary
	{"81.218.119.11", 1},   // GreenTeamDNS Primary
	{"209.88.198.133", 1},  // GreenTeamDNS Secondary
	{"37.235.1.177", 1},    // FreeDNS
	{"38.132.106.139", 1},  // CyberGhost
}

var trusted *pool.Pool

var detector *wildcards.Detector

func PerformQuery(name string, qtype uint16) ([]dns.RR, error) {
	msg := utils.QueryMsg(name, qtype)
	if qtype == dns.TypePTR {
		msg = utils.ReverseMsg(name)
	}

	resp, err := dnsQuery(msg, trusted, 10)
	if err == nil && resp != nil {
		if wildcardDetected(resp, detector) {
			return nil, errors.New("wildcard detected")
		}
		if len(resp.Answer) > 0 {
			if rr := utils.AnswersByType(resp, qtype); len(rr) > 0 {
				return rr, nil
			}
		}
	}
	return nil, err
}

func wildcardDetected(resp *dns.Msg, r *wildcards.Detector) bool {
	name := strings.ToLower(utils.RemoveLastDot(resp.Question[0].Name))

	if dom, err := publicsuffix.EffectiveTLDPlusOne(name); err == nil && dom != "" {
		return r.WildcardDetected(context.TODO(), resp, dom)
	}
	return false
}

func dnsQuery(msg *dns.Msg, r *pool.Pool, attempts int) (*dns.Msg, error) {
	for num := 0; num < attempts; num++ {
		resp, err := r.Exchange(context.TODO(), msg)
		if err != nil {
			continue
		}
		if resp.Rcode == dns.RcodeNameError {
			return nil, errors.New("name does not exist")
		}
		if resp.Rcode == dns.RcodeSuccess {
			if len(resp.Answer) == 0 {
				return nil, errors.New("no record of this type")
			}
			return resp, nil
		}
	}
	return nil, nil
}

func trustedResolvers() *pool.Pool {
	timeout := 5 * time.Second
	cpus := runtime.NumCPU()
	// wildcard detector
	serv := servers.NewNameserver("8.8.8.8", timeout)
	wconns := conn.New(cpus, selectors.NewSingle(serv))
	detector = wildcards.NewDetector(serv, wconns, nil)
	// the server pool
	sel := selectors.NewAuthoritative(timeout, servers.NewNameserver)
	conns := conn.New(cpus, sel)
	return pool.New(0, sel, conns, nil)
}
