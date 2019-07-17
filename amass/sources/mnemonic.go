// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package sources

import (
	"bufio"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/OWASP/Amass/amass/core"
	eb "github.com/OWASP/Amass/amass/eventbus"
	"github.com/OWASP/Amass/amass/utils"
)

// Mnemonic is the Service that handles access to the Mnemonic data source.
type Mnemonic struct {
	core.BaseService

	SourceType string
}

// NewMnemonic returns he object initialized, but not yet started.
func NewMnemonic(config *core.Config, bus *eb.EventBus) *Mnemonic {
	m := &Mnemonic{SourceType: core.API}

	m.BaseService = *core.NewBaseService(m, "Mnemonic", config, bus)
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
		m.Config().Log.Printf("%s: %s: %v", m.String(), url, err)
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
		m.Bus().Publish(core.NewNameTopic, &core.DNSRequest{
			Name:   name,
			Domain: domain,
			Tag:    m.SourceType,
			Source: m.String(),
		})
	}

	for _, ip := range ips {
		// Inform the Address Service of this finding
		m.Bus().Publish(core.NewAddrTopic, &core.AddrRequest{
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
