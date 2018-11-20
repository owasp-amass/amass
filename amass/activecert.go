// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package amass

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"strconv"
	"time"

	"github.com/OWASP/Amass/amass/core"
	"github.com/OWASP/Amass/amass/utils"
	evbus "github.com/asaskevich/EventBus"
)

const (
	defaultTLSConnectTimeout = 3 * time.Second
	defaultHandshakeDeadline = 5 * time.Second
)

// ActiveCertService is the AmassService that handles all active certificate activities
// within the architecture.
type ActiveCertService struct {
	core.BaseAmassService

	Bus       evbus.Bus
	Config    *core.AmassConfig
	maxPulls  utils.Semaphore
	filter    *utils.StringFilter
	addrQueue chan string
}

// NewActiveCertService requires the enumeration configuration and event bus as parameters.
// The object returned is initialized, but has not yet been started.
func NewActiveCertService(bus evbus.Bus, config *core.AmassConfig) *ActiveCertService {
	acs := &ActiveCertService{
		Bus:       bus,
		Config:    config,
		maxPulls:  utils.NewSimpleSemaphore(25),
		filter:    utils.NewStringFilter(),
		addrQueue: make(chan string, 50),
	}

	acs.BaseAmassService = *core.NewBaseAmassService("Active Cert", acs)
	return acs
}

// OnStart implements the AmassService interface
func (acs *ActiveCertService) OnStart() error {
	acs.BaseAmassService.OnStart()

	if acs.Config.Active {
		acs.Bus.SubscribeAsync(core.ACTIVECERT, acs.queueAddress, false)
	}

	go acs.processRequests()
	return nil
}

// OnStop implements the AmassService interface
func (acs *ActiveCertService) OnStop() error {
	acs.BaseAmassService.OnStop()

	if acs.Config.Active {
		acs.Bus.Unsubscribe(core.ACTIVECERT, acs.queueAddress)
	}
	return nil
}

func (acs *ActiveCertService) queueAddress(addr string) {
	if acs.filter.Duplicate(addr) {
		return
	}

	acs.SetActive()
	acs.maxPulls.Acquire(1)
	acs.addrQueue <- addr
}

func (acs *ActiveCertService) processRequests() {
	for {
		select {
		case <-acs.PauseChan():
			<-acs.ResumeChan()
		case <-acs.Quit():
			return
		case addr := <-acs.addrQueue:
			go acs.performRequest(addr)
		}
	}
}

func (acs *ActiveCertService) performRequest(addr string) {
	defer acs.maxPulls.Release(1)

	acs.SetActive()
	for _, r := range PullCertificateNames(addr, acs.Config.Ports) {
		domain := acs.Config.WhichDomain(r.Name)

		if domain != "" && core.DataSourceNameFilter.Duplicate(r.Name) {
			r.Source = acs.String()
			acs.Bus.Publish(core.NEWNAME, r)
		}
	}
	acs.SetActive()
}

// PullCertificateNames attempts to pull a cert from one or more ports on an IP.
func PullCertificateNames(addr string, ports []int) []*core.AmassRequest {
	var requests []*core.AmassRequest

	// Check hosts for certificates that contain subdomain names
	for _, port := range ports {
		cfg := &tls.Config{InsecureSkipVerify: true}
		// Set the maximum time allowed for making the connection
		ctx, cancel := context.WithTimeout(context.Background(), defaultTLSConnectTimeout)
		defer cancel()
		// Obtain the connection
		d := net.Dialer{}
		conn, err := d.DialContext(ctx, "tcp", addr+":"+strconv.Itoa(port))
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
		requests = append(requests, reqFromNames(namesFromCert(cert))...)
	}
	return requests
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
	commonName := utils.RemoveAsteriskLabel(cn)
	if commonName != "" {
		subdomains = append(subdomains, commonName)
	}
	// Add the cert DNS names to the list of subdomain names
	for _, name := range cert.DNSNames {
		n := utils.RemoveAsteriskLabel(name)
		if n != "" {
			subdomains = utils.UniqueAppend(subdomains, n)
		}
	}
	return subdomains
}

func reqFromNames(subdomains []string) []*core.AmassRequest {
	var requests []*core.AmassRequest

	for _, name := range subdomains {
		requests = append(requests, &core.AmassRequest{
			Name:   name,
			Domain: SubdomainToDomain(name),
			Tag:    core.CERT,
		})
	}
	return requests
}
