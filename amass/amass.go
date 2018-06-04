// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package amass

import (
	"net"
	"strings"
	"time"
)

const (
	Version string = "v2.0.2"
	Author  string = "Jeff Foley (@jeff_foley)"
	// Tags used to mark the data source with the Subdomain struct
	ALT     = "alt"
	BRUTE   = "brute"
	SCRAPE  = "scrape"
	ARCHIVE = "archive"

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

	if err := CheckConfig(config); err != nil {
		return err
	}

	if len(config.Resolvers) > 0 {
		SetCustomResolvers(config.Resolvers)
	}

	dnsSrv := NewDNSService(config)
	config.dns = dnsSrv

	obtainAdditionalDomains(config)

	scrapeSrv := NewScraperService(config)
	config.scrape = scrapeSrv

	dataMgrSrv := NewDataManagerService(config)
	config.data = dataMgrSrv

	archiveSrv := NewArchiveService(config)
	config.archive = archiveSrv

	altSrv := NewAlterationService(config)
	config.alt = altSrv

	bruteSrv := NewBruteForceService(config)
	config.brute = bruteSrv

	services = append(services, scrapeSrv, dnsSrv, dataMgrSrv, archiveSrv, altSrv, bruteSrv)
	for _, service := range services {
		if err := service.Start(); err != nil {
			return err
		}
	}

	// We periodically check if all the services have finished
	t := time.NewTicker(5 * time.Second)
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

func obtainAdditionalDomains(config *AmassConfig) {
	var ips []net.IP

	ips = append(ips, config.IPs...)

	for _, cidr := range config.CIDRs {
		ips = append(ips, NetHosts(cidr)...)
	}

	for _, asn := range config.ASNs {
		record := ASNRequest(asn)
		if record == nil {
			continue
		}

		for _, cidr := range record.Netblocks {
			_, ipnet, err := net.ParseCIDR(cidr)
			if err != nil {
				continue
			}

			ips = append(ips, NetHosts(ipnet)...)
		}
	}

	if len(ips) == 0 {
		return
	}

	var running int
	done := make(chan struct{}, 50)

	t := time.NewTicker(100 * time.Millisecond)
	defer t.Stop()
loop:
	for {
		select {
		case <-t.C:
			if running >= 50 || len(ips) <= 0 {
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
	PullCertificate(addr, config, true)
	done <- struct{}{}
}

// NewUniqueElements - Removes elements that have duplicates in the original or new elements
func NewUniqueElements(orig []string, add ...string) []string {
	var n []string

	for _, av := range add {
		found := false
		s := strings.ToLower(av)

		// Check the original slice for duplicates
		for _, ov := range orig {
			if s == strings.ToLower(ov) {
				found = true
				break
			}
		}
		// Check that we didn't already add it in
		if !found {
			for _, nv := range n {
				if s == nv {
					found = true
					break
				}
			}
		}
		// If no duplicates were found, add the entry in
		if !found {
			n = append(n, s)
		}
	}
	return n
}

// UniqueAppend - Behaves like the Go append, but does not add duplicate elements
func UniqueAppend(orig []string, add ...string) []string {
	return append(orig, NewUniqueElements(orig, add...)...)
}
