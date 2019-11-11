// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package services

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/OWASP/Amass/v3/config"
	"github.com/OWASP/Amass/v3/eventbus"
	"github.com/OWASP/Amass/v3/net/http"
	"github.com/OWASP/Amass/v3/requests"
	"github.com/OWASP/Amass/v3/stringset"
)

// Mnemonic is the Service that handles access to the Mnemonic data source.
type Mnemonic struct {
	BaseService

	SourceType string
}

// NewMnemonic returns he object initialized, but not yet started.
func NewMnemonic(sys System) *Mnemonic {
	m := &Mnemonic{SourceType: requests.API}

	m.BaseService = *NewBaseService(m, "Mnemonic", sys)
	return m
}

// Type implements the Service interface.
func (m *Mnemonic) Type() string {
	return m.SourceType
}

// OnStart implements the Service interface.
func (m *Mnemonic) OnStart() error {
	m.BaseService.OnStart()

	m.SetRateLimit(time.Second)
	return nil
}

// OnDNSRequest implements the Service interface.
func (m *Mnemonic) OnDNSRequest(ctx context.Context, req *requests.DNSRequest) {
	cfg := ctx.Value(requests.ContextConfig).(*config.Config)
	bus := ctx.Value(requests.ContextEventBus).(*eventbus.EventBus)
	if cfg == nil || bus == nil {
		return
	}

	if req.Name == "" || req.Domain == "" {
		return
	}

	if !cfg.IsDomainInScope(req.Name) {
		return
	}

	m.CheckRateLimit()
	bus.Publish(requests.SetActiveTopic, m.String())
	bus.Publish(requests.LogTopic, fmt.Sprintf("Querying %s for %s subdomains", m.String(), req.Domain))

	url := m.getDNSURL(req.Domain)
	page, err := http.RequestWebPage(url, nil, nil, "", "")
	if err != nil {
		bus.Publish(requests.LogTopic, fmt.Sprintf("%s: %s: %v", m.String(), url, err))
		return
	}

	ips := stringset.New()
	names := stringset.New()
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

		if (j.Type == "a" || j.Type == "aaaa") && cfg.IsDomainInScope(j.Query) {
			ips.Insert(j.Answer)
			names.Insert(j.Query)
		}
	}

	for name := range names {
		bus.Publish(requests.NewNameTopic, &requests.DNSRequest{
			Name:   name,
			Domain: req.Domain,
			Tag:    m.SourceType,
			Source: m.String(),
		})
	}

	for ip := range ips {
		// Inform the Address Service of this finding
		bus.Publish(requests.NewAddrTopic, &requests.AddrRequest{
			Address: ip,
			Domain:  req.Domain,
			Tag:     m.SourceType,
			Source:  m.String(),
		})
	}
}

func (m *Mnemonic) getDNSURL(domain string) string {
	format := "https://api.mnemonic.no/pdns/v3/%s"

	return fmt.Sprintf(format, domain)
}
