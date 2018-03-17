// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package amass

import (
	"crypto/tls"
	"fmt"
	"strconv"
	"strings"
	"time"
)

type ActiveCertService struct {
	BaseAmassService

	// Queue for requests
	queue []*AmassRequest

	// Ensures that the same IP is not used twice
	filter map[string]struct{}
}

func NewActiveCertService(in, out chan *AmassRequest, config *AmassConfig) *ActiveCertService {
	acs := &ActiveCertService{filter: make(map[string]struct{})}

	acs.BaseAmassService = *NewBaseAmassService("Active Certificate Service", config, acs)

	acs.input = in
	acs.output = out
	return acs
}

func (acs *ActiveCertService) OnStart() error {
	acs.BaseAmassService.OnStart()

	go acs.processRequests()
	return nil
}

func (acs *ActiveCertService) OnStop() error {
	acs.BaseAmassService.OnStop()
	return nil
}

func (acs *ActiveCertService) processRequests() {
	t := time.NewTicker(10 * time.Second)
	defer t.Stop()

	pull := time.NewTicker(1 * time.Second)
	defer pull.Stop()
loop:
	for {
		select {
		case req := <-acs.Input():
			if req.activeCertOnly {
				go acs.add(req)
			}
		case <-pull.C:
			next := acs.next()
			if next != nil {
				go acs.handleRequest(next)
			}
		case <-t.C:
			acs.SetActive(false)
		case <-acs.Quit():
			break loop
		}
	}
}

func (acs *ActiveCertService) add(req *AmassRequest) {
	acs.Lock()
	defer acs.Unlock()

	acs.queue = append(acs.queue, req)
}

func (acs *ActiveCertService) next() *AmassRequest {
	acs.Lock()
	defer acs.Unlock()

	var next *AmassRequest
	if len(acs.queue) == 1 {
		next = acs.queue[0]
		acs.queue = []*AmassRequest{}
	} else if len(acs.queue) > 1 {
		next = acs.queue[0]
		acs.queue = acs.queue[1:]
	}
	return next
}

// Returns true if the IP is a duplicate entry in the filter.
// If not, the IP is added to the filter
func (acs *ActiveCertService) duplicate(ip string) bool {
	acs.Lock()
	defer acs.Unlock()

	if _, found := acs.filter[ip]; found {
		return true
	}
	acs.filter[ip] = struct{}{}
	return false
}

func (acs *ActiveCertService) handleRequest(req *AmassRequest) {
	acs.SetActive(true)
	// Which type of request is this?
	if req.Address != "" && !acs.duplicate(req.Address) {
		acs.pullCertificate(req.Address)
	} else if req.Netblock != nil {
		ips := hosts(req.Netblock)

		for _, ip := range ips {
			acs.add(&AmassRequest{
				Address:  ip,
				Netblock: req.Netblock,
				ASN:      req.ASN,
				ISP:      req.ISP,
			})
		}
	}
}

// pullCertificate - Attempts to pull a cert from several ports on an IP
func (acs *ActiveCertService) pullCertificate(addr string) {
	var roots []string
	var requests []*AmassRequest

	// Check hosts for certificates that contain subdomain names
	for _, port := range acs.Config().Ports {
		strPort := strconv.Itoa(port)
		cfg := tls.Config{InsecureSkipVerify: true}

		conn, err := tls.Dial("tcp", addr+":"+strPort, &cfg)
		if err != nil {
			continue
		}

		certChain := conn.ConnectionState().PeerCertificates
		cert := certChain[0]

		var cn string
		for _, name := range cert.Subject.Names {
			oid := name.Type
			if len(oid) == 4 && oid[0] == 2 && oid[1] == 5 && oid[2] == 4 {
				if oid[3] == 3 {
					cn = fmt.Sprintf("%s", name.Value)
					break
				}
			}
		}
		root := removeAsteriskLabel(cn)
		roots = append(roots, root)

		var subdomains []string
		for _, name := range cert.DNSNames {
			subdomains = append(subdomains, removeAsteriskLabel(name))
		}
		subdomains = NewUniqueElements([]string{}, subdomains...)

		for _, name := range subdomains {
			requests = append(requests, &AmassRequest{
				Name:   name,
				Domain: root,
				Tag:    "cert",
				Source: "Active Cert",
			})
		}

		for _, ip := range cert.IPAddresses {
			acs.add(&AmassRequest{Address: ip.String()})
		}
	}
	// Add the new root domain names to our Config
	acs.Config().Domains = UniqueAppend(acs.Config().Domains, roots...)
	// Send all the new requests out
	for _, req := range requests {
		acs.SendOut(req)
	}
}

func removeAsteriskLabel(s string) string {
	var index int

	labels := strings.Split(s, ".")
	for i := len(labels) - 1; i >= 0; i-- {
		if strings.TrimSpace(labels[i]) == "*" {
			break
		}
		index = i
	}
	if index == len(labels)-1 {
		return ""
	}
	return strings.Join(labels[index:], ".")
}
