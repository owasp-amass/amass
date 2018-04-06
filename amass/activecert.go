// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package amass

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
)

const (
	defaultTLSConnectTimeout = 3 * time.Second
	defaultHandshakeDeadline = 10 * time.Second
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

	pull := time.NewTicker(100 * time.Millisecond)
	defer pull.Stop()
loop:
	for {
		select {
		case req := <-acs.Input():
			if req.addDomains {
				acs.add(req)
			}
		case <-pull.C:
			next := acs.next()
			if next != nil {
				acs.handleRequest(next)
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
	// Do not perform repetitive activities
	if req.Address != "" && acs.duplicate(req.Address) {
		return
	}
	// Otherwise, check which type of request it is
	if req.Address != "" {
		go acs.pullCertificate(req)
	} else if req.Netblock != nil {
		ips := NetHosts(req.Netblock)

		for _, ip := range ips {
			acs.add(&AmassRequest{
				Address:    ip,
				Netblock:   req.Netblock,
				ASN:        req.ASN,
				ISP:        req.ISP,
				addDomains: req.addDomains,
			})
		}
	}
}

func (acs *ActiveCertService) performOutput(req *AmassRequest) {
	acs.SetActive(true)
	// Check if the discovered name belongs to a root domain of interest
	for _, domain := range acs.Config().Domains() {
		// If we have a match, the request can be sent out
		if req.Domain == domain {
			acs.SendOut(req)
			break
		}
	}
}

// pullCertificate - Attempts to pull a cert from several ports on an IP
func (acs *ActiveCertService) pullCertificate(req *AmassRequest) {
	var requests []*AmassRequest

	// Check hosts for certificates that contain subdomain names
	for _, port := range acs.Config().Ports {
		acs.SetActive(true)

		cfg := &tls.Config{InsecureSkipVerify: true}
		// Set the maximum time allowed for making the connection
		ctx, cancel := context.WithTimeout(context.Background(), defaultTLSConnectTimeout)
		defer cancel()
		// Obtain the connection
		conn, err := acs.Config().DialContext(ctx, "tcp", req.Address+":"+strconv.Itoa(port))
		if err != nil {
			continue
		}
		defer conn.Close()
		c := tls.Client(conn, cfg)
		// Attempt to acquire the certificate chain
		errChan := make(chan error, 2)
		// This goroutine will break us out of the handshake
		time.AfterFunc(defaultHandshakeDeadline, func() {
			errChan <- errors.New("Handshake timeout")
		})
		// Be sure we do not wait too long in this attempt
		c.SetDeadline(time.Now().Add(defaultHandshakeDeadline))
		// The handshake is performed in the goroutine
		go func() {
			errChan <- c.Handshake()
		}()
		// The error channel returns handshake or timeout error
		if err = <-errChan; err != nil {
			continue
		}
		// Get the correct certificate in the chain
		certChain := c.ConnectionState().PeerCertificates
		cert := certChain[0]
		// Create the new requests from names found within the cert
		requests = append(requests, acs.reqFromNames(namesFromCert(cert))...)
	}
	// Attempt to add the domains to the configuration
	if acs.Config().AdditionalDomains {
		// Get all uniques root domain names from the generated requests
		var domains []string
		for _, r := range requests {
			domains = UniqueAppend(domains, r.Domain)
		}

		acs.Config().AddDomains(domains)
	}
	// Send all the new requests out
	for _, r := range requests {
		acs.performOutput(r)
	}
}

func namesFromCert(cert *x509.Certificate) []string {
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

	var subdomains []string
	// Add the subject common name to the list of subdomain names
	commonName := removeAsteriskLabel(cn)
	if commonName != "" {
		subdomains = append(subdomains, commonName)
	}
	// Add the cert DNS names to the list of subdomain names
	for _, name := range cert.DNSNames {
		n := removeAsteriskLabel(name)
		if n != "" {
			subdomains = UniqueAppend(subdomains, n)
		}
	}
	return subdomains
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

func (acs *ActiveCertService) reqFromNames(subdomains []string) []*AmassRequest {
	var requests []*AmassRequest

	// For each subdomain name, attempt to make a new AmassRequest
	for _, name := range subdomains {
		root := acs.Config().domainLookup.SubdomainToDomain(name)

		if root != "" {
			requests = append(requests, &AmassRequest{
				Name:   name,
				Domain: root,
				Tag:    "cert",
				Source: "Active Cert",
			})
		}
	}
	return requests
}
