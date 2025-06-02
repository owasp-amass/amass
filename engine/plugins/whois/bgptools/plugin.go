// Copyright © by Jeff Foley 2017-2025. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package bgptools

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
	"github.com/owasp-amass/amass/v4/engine/plugins/support"
	et "github.com/owasp-amass/amass/v4/engine/types"
	amassnet "github.com/owasp-amass/amass/v4/internal/net"
	oam "github.com/owasp-amass/open-asset-model"
	"golang.org/x/time/rate"
)

type bgpTools struct {
	sync.Mutex
	name     string
	addr     string
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

	rr, err := support.PerformQuery("bgp.tools", dns.TypeA)
	if err != nil {
		return fmt.Errorf("failed to obtain the BGPTools IP address: %v", err)
	} else if len(rr) == 0 {
		return errors.New("failed to obtain the BGPTools IP address")
	}

	for _, record := range rr {
		if record.Header().Rrtype == dns.TypeA {
			bt.addr = strings.TrimSpace((record.(*dns.A)).A.String())
			break
		}
	}
	if bt.addr == "" {
		return errors.New("failed to obtain the BGPTools IP address")
	}

	bt.netblock = &netblock{
		name:   bt.name + "-IP-Handler",
		plugin: bt,
	}
	if err := r.RegisterHandler(&et.Handler{
		Plugin:     bt,
		Name:       bt.netblock.name,
		Priority:   1,
		Transforms: []string{string(oam.Netblock)},
		EventType:  oam.IPAddress,
		Callback:   bt.netblock.check,
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
		Priority:     1,
		MaxInstances: 10,
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

func (bt *bgpTools) whois(ipstr string) (*bgpToolsRecord, error) {
	addr := net.JoinHostPort(bt.addr, strconv.Itoa(bt.port))

	_ = bt.rlimit.Wait(context.TODO())
	conn, err := amassnet.DialContext(context.TODO(), "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("failed to establish a connection with the WHOIS server: %v", err)
	}
	defer func() { _ = conn.Close() }()

	n, err := io.WriteString(conn, fmt.Sprintf("begin\n%s\nend", ipstr))
	if err != nil || n == 0 {
		return nil, fmt.Errorf("failed to send the request to the WHOIS server: %v", err)
	}

	data, err := io.ReadAll(conn)
	if err != nil {
		return nil, fmt.Errorf("error reading the response from the WHOIS server: %v", err)
	}

	record := strings.Split(string(data), "|")
	// Ensure the record contains the necessary details (AutonomousSystem and Netblock)
	if len(record) < 7 {
		return nil, errors.New("received insufficient data from the WHOIS server")
	}

	var r bgpToolsRecord
	for i, f := range record {
		field := strings.TrimSpace(f)

		switch i {
		case 0:
			num, err := strconv.Atoi(field)
			if err != nil {
				return nil, err
			}
			r.ASN = num
		case 1:
			ip, err := netip.ParseAddr(field)
			if err != nil {
				return nil, err
			}
			r.IP = ip
		case 2:
			prefix, err := netip.ParsePrefix(field)
			if err != nil {
				return nil, err
			}
			r.Prefix = prefix
		case 3:
			r.CC = field
		case 4:
			r.Registry = field
		case 5:
			t, err := time.Parse("2006-01-02", field)
			if err != nil {
				return nil, err
			}
			r.AllocatedDate = t
		case 6:
			r.ASName = field
		}
	}
	return &r, nil
}
