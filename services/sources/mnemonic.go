// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package sources

import (
	"bufio"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/OWASP/Amass/config"
	eb "github.com/OWASP/Amass/eventbus"
	"github.com/OWASP/Amass/requests"
	"github.com/OWASP/Amass/resolvers"
	"github.com/OWASP/Amass/services"
	"github.com/OWASP/Amass/utils"
)

// Mnemonic is the Service that handles access to the Mnemonic data source.
type Mnemonic struct {
	services.BaseService

	SourceType string
}

// NewMnemonic returns he object initialized, but not yet started.
func NewMnemonic(cfg *config.Config, bus *eb.EventBus, pool *resolvers.ResolverPool) *Mnemonic {
	m := &Mnemonic{SourceType: requests.API}

	m.BaseService = *services.NewBaseService(m, "Mnemonic", cfg, bus, pool)
	return m
}

// OnStart implements the Service interface
func (m *Mnemonic) OnStart() error {
	m.BaseService.OnStart()

	go m.processRequests()
	return nil
}

func (m *Mnemonic) processRequests() {
	for {
		select {
		case <-m.Quit():
			return
		case dns := <-m.DNSRequestChan():
			if m.Config().IsDomainInScope(dns.Domain) {
				m.executeDNSQuery(dns.Domain)
			}
		case <-m.ASNRequestChan():
		case <-m.AddrRequestChan():
		case <-m.WhoisRequestChan():
		}
	}
}

func (m *Mnemonic) executeDNSQuery(domain string) {
	m.SetActive()
	url := m.getDNSURL(domain)
	page, err := utils.RequestWebPage(url, nil, nil, "", "")
	if err != nil {
		m.Bus().Publish(requests.LogTopic, fmt.Sprintf("%s: %s: %v", m.String(), url, err))
		return
	}

	var ips []string
	var names []string
	scanner := bufio.NewScanner(strings.NewReader(page))
	for scanner.Scan() {
		// Get the next line of JSON
		line := scanner.Text()
		if line == "" {
			continue
		}

		var j struct {
			Query  string `json:"query"`
			Answer string `json:"answer"`
			Type   string `json:"rrtype"`
		}
		if err := json.Unmarshal([]byte(line), &j); err != nil {
			continue
		}

		if (j.Type == "a" || j.Type == "aaaa") && m.Config().IsDomainInScope(j.Query) {
			ips = utils.UniqueAppend(ips, j.Answer)
			names = utils.UniqueAppend(names, j.Query)
		}
	}

	for _, name := range names {
		m.Bus().Publish(requests.NewNameTopic, &requests.DNSRequest{
			Name:   name,
			Domain: domain,
			Tag:    m.SourceType,
			Source: m.String(),
		})
	}

	for _, ip := range ips {
		// Inform the Address Service of this finding
		m.Bus().Publish(requests.NewAddrTopic, &requests.AddrRequest{
			Address: ip,
			Domain:  domain,
			Tag:     m.SourceType,
			Source:  m.String(),
		})
	}
}

func (m *Mnemonic) getDNSURL(domain string) string {
	format := "https://api.mnemonic.no/pdns/v3/%s"

	return fmt.Sprintf(format, domain)
}
