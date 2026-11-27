// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package bgptools

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
	"github.com/owasp-amass/amass/v5/engine/plugins/support"
	et "github.com/owasp-amass/amass/v5/engine/types"
	amassnet "github.com/owasp-amass/amass/v5/internal/net"
	oam "github.com/owasp-amass/open-asset-model"
	"golang.org/x/time/rate"
)

type bgpTools struct {
	name     string
	addrLock sync.Mutex
	addr     string
	retry    time.Time
	port     int
	log      *slog.Logger
	autsys   *autsys
	netblock *netblock
	rlimit   *rate.Limiter
	source   *et.Source
}

func NewBGPTools() et.Plugin {
	limit := rate.Every(time.Second)

	return &bgpTools{
		name:   "BGP.Tools",
		port:   43,
		rlimit: rate.NewLimiter(limit, 1),
		source: &et.Source{
			Name:       "BGP.Tools",
			Confidence: 100,
		},
	}
}

func (bt *bgpTools) Name() string {
	return bt.name
}

func (bt *bgpTools) Start(r et.Registry) error {
	bt.log = r.Log().WithGroup("plugin").With("name", bt.name)

	// bgp.tools is found when it is first asked, so the engine starts even
	// when the name cannot be resolved yet
	bt.netblock = &netblock{
		name:   bt.name + "-IP-Handler",
		plugin: bt,
	}
	if err := r.RegisterHandler(&et.Handler{
		Plugin:       bt,
		Name:         bt.netblock.name,
		Position:     2,
		Exclusive:    true,
		MaxInstances: support.MinHandlerInstances,
		Transforms:   []string{string(oam.Netblock)},
		EventType:    oam.IPAddress,
		Callback:     bt.netblock.check,
	}); err != nil {
		return err
	}

	bt.autsys = &autsys{
		name:   bt.name + "-Netblock-Handler",
		plugin: bt,
	}
	if err := r.RegisterHandler(&et.Handler{
		Plugin:       bt,
		Name:         bt.autsys.name,
		Position:     2,
		Exclusive:    true,
		MaxInstances: support.MinHandlerInstances,
		Transforms:   []string{string(oam.AutonomousSystem)},
		EventType:    oam.Netblock,
		Callback:     bt.autsys.check,
	}); err != nil {
		return err
	}

	bt.log.Info("Plugin started")
	return nil
}

func (bt *bgpTools) Stop() {
	bt.log.Info("Plugin stopped")
}

type bgpToolsRecord struct {
	ASN           int
	IP            netip.Addr
	Prefix        netip.Prefix
	CC            string
	Registry      string
	AllocatedDate time.Time
	ASName        string
}

// serverAddr returns bgp.tools' address, looking it up the first time and
// again at most once a minute after a lookup fails.
func (bt *bgpTools) serverAddr(ctx context.Context) (string, error) {
	bt.addrLock.Lock()
	defer bt.addrLock.Unlock()

	if bt.addr != "" {
		return bt.addr, nil
	}
	if time.Now().Before(bt.retry) {
		return "", errors.New("the BGPTools IP address is not known yet")
	}

	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	if rr, err := support.PerformQuery(ctx, "bgp.tools", dns.TypeA); err == nil {
		for _, record := range rr {
			if a, ok := record.(*dns.A); ok {
				bt.addr = strings.TrimSpace(a.A.String())
				return bt.addr, nil
			}
		}
	}

	bt.retry = time.Now().Add(time.Minute)
	return "", errors.New("failed to obtain the BGPTools IP address")
}

func (bt *bgpTools) whois(ctx context.Context, ipstr string) (*bgpToolsRecord, error) {
	host, err := bt.serverAddr(ctx)
	if err != nil {
		return nil, err
	}

	_ = support.WaitLimit(ctx, bt.rlimit)
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	data, err := amassnet.WhoisQuery(ctx, net.JoinHostPort(host, strconv.Itoa(bt.port)),
		fmt.Sprintf("begin\n%s\nend", ipstr), 3*time.Second, 0)
	if err != nil {
		return nil, err
	}
	return parseRecord(data)
}

// parseRecord reads the first line of a bgp.tools WHOIS answer that starts
// with an AS number: AS | IP | prefix | country | registry | allocated |
// AS name. The AS number, address and prefix are required; the other
// fields are kept when they can be read.
func parseRecord(data string) (*bgpToolsRecord, error) {
	for _, line := range strings.Split(data, "\n") {
		fields := strings.Split(line, "|")
		if len(fields) < 7 {
			continue
		}
		for i := range fields {
			fields[i] = strings.TrimSpace(fields[i])
		}

		asn, err := strconv.Atoi(fields[0])
		if err != nil {
			continue
		}
		ip, err := netip.ParseAddr(fields[1])
		if err != nil {
			return nil, err
		}
		prefix, err := netip.ParsePrefix(fields[2])
		if err != nil {
			return nil, err
		}

		r := &bgpToolsRecord{ASN: asn, IP: ip, Prefix: prefix, CC: fields[3], Registry: fields[4],
			ASName: strings.Join(fields[6:], "|")}
		if t, err := time.Parse("2006-01-02", fields[5]); err == nil {
			r.AllocatedDate = t
		}
		return r, nil
	}

	return nil, errors.New("received insufficient data from the WHOIS server")
}
