// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package amass

import (
	"net"
	"os"
	"sync"
	"time"

	"github.com/OWASP/Amass/amass/utils"
	"github.com/OWASP/Amass/amass/utils/dns"
	"github.com/OWASP/Amass/amass/utils/viz"
	evbus "github.com/asaskevich/EventBus"
)

const (
	Version string = "v2.4.2"
	Author  string = "Jeff Foley (@jeff_foley)"
	// Tags used to mark the data source with the Subdomain struct
	ALT     = "alt"
	ARCHIVE = "archive"
	API     = "api"
	BRUTE   = "brute"
	CERT    = "cert"
	SCRAPE  = "scrape"

	// Topics used in the EventBus
	DNSQUERY = "amass:dnsquery"
	RESOLVED = "amass:resolved"
	OUTPUT   = "amass:output"

	// Node types used in the Maltego local transform
	TypeNorm int = iota
	TypeNS
	TypeMX
	TypeWeb
)

type AmassAddressInfo struct {
	Address     net.IP
	Netblock    *net.IPNet
	ASN         int
	Description string
}

type AmassOutput struct {
	Name      string
	Domain    string
	Addresses []AmassAddressInfo
	Tag       string
	Source    string
	Type      int
}

func StartEnumeration(config *AmassConfig) error {
	var services []AmassService
	var filterMutex sync.Mutex
	filter := make(map[string]struct{})

	if err := CheckConfig(config); err != nil {
		return err
	}
	utils.SetDialContext(dns.DialContext)

	bus := evbus.New()
	bus.SubscribeAsync(OUTPUT, func(out *AmassOutput) {
		filterMutex.Lock()
		defer filterMutex.Unlock()

		if _, found := filter[out.Name]; !found {
			filter[out.Name] = struct{}{}
			config.Output <- out
		}
	}, false)

	services = append(services, NewSourcesService(config, bus))
	if !config.NoDNS {
		services = append(services,
			NewDNSService(config, bus),
			NewDataManagerService(config, bus),
			NewAlterationService(config, bus),
			NewBruteForceService(config, bus),
		)
	}

	for _, service := range services {
		if err := service.Start(); err != nil {
			return err
		}
	}

	// We periodically check if all the services have finished
	t := time.NewTicker(1 * time.Second)
	defer t.Stop()
	for range t.C {
		done := true

		for _, service := range services {
			if service.IsActive() {
				done = false
				break
			}
		}

		if done {
			break
		}
	}
	// Stop all the services
	for _, service := range services {
		service.Stop()
	}
	close(config.Output)
	return nil
}

func WriteVisjsFile(path string, config *AmassConfig) {
	if path == "" {
		return
	}

	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE, 0644)
	if err != nil {
		return
	}
	defer f.Close()

	nodes, edges := config.Graph.VizData()
	viz.WriteVisjsData(nodes, edges, f)
	f.Sync()
}

func WriteGraphistryFile(path string, config *AmassConfig) {
	if path == "" {
		return
	}

	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE, 0644)
	if err != nil {
		return
	}
	defer f.Close()

	nodes, edges := config.Graph.VizData()
	viz.WriteGraphistryData(nodes, edges, f)
	f.Sync()
}

func WriteGEXFFile(path string, config *AmassConfig) {
	if path == "" {
		return
	}

	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE, 0644)
	if err != nil {
		return
	}
	defer f.Close()

	nodes, edges := config.Graph.VizData()
	viz.WriteGEXFData(nodes, edges, f)
	f.Sync()
}

func WriteD3File(path string, config *AmassConfig) {
	if path == "" {
		return
	}

	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE, 0644)
	if err != nil {
		return
	}
	defer f.Close()

	nodes, edges := config.Graph.VizData()
	viz.WriteD3Data(nodes, edges, f)
	f.Sync()
}

func ObtainAdditionalDomains(config *AmassConfig) {
	ips := allIPsInConfig(config)

	if len(ips) > 0 {
		pullAllCertificates(ips, config)
	}

	if config.Whois {
		domains := config.Domains()
		for _, domain := range domains {
			more, err := ReverseWhois(domain)
			if err != nil {
				config.Log.Printf("ReverseWhois error: %v", err)
				continue
			}

			for _, domain := range more {
				config.AddDomain(domain)
			}
		}
	}
}

func allIPsInConfig(config *AmassConfig) []net.IP {
	var ips []net.IP

	ips = append(ips, config.IPs...)

	for _, cidr := range config.CIDRs {
		ips = append(ips, utils.NetHosts(cidr)...)
	}

	for _, asn := range config.ASNs {
		record, err := ASNRequest(asn)
		if err != nil {
			config.Log.Printf("%v", err)
			continue
		}

		for _, cidr := range record.Netblocks {
			_, ipnet, err := net.ParseCIDR(cidr)
			if err != nil {
				continue
			}

			ips = append(ips, utils.NetHosts(ipnet)...)
		}
	}
	return ips
}

func pullAllCertificates(ips []net.IP, config *AmassConfig) {
	var running int
	done := make(chan struct{}, 100)

	t := time.NewTicker(100 * time.Millisecond)
	defer t.Stop()
loop:
	for {
		select {
		case <-t.C:
			if running >= 100 || len(ips) <= 0 {
				break
			}

			running++

			addr := ips[0]
			if len(ips) == 1 {
				ips = []net.IP{}
			} else {
				ips = ips[1:]
			}

			go executeActiveCert(addr.String(), config, done)
		case <-done:
			running--
			if running == 0 && len(ips) <= 0 {
				break loop
			}
		}
	}
}

func executeActiveCert(addr string, config *AmassConfig, done chan struct{}) {
	var domains []string

	for _, r := range PullCertificateNames(addr, config.Ports) {
		domains = utils.UniqueAppend(domains, r.Domain)
	}

	for _, domain := range domains {
		config.AddDomain(domain)
	}
	done <- struct{}{}
}
