// Copyright © by Jeff Foley 2017-2022. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package datasrcs

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/OWASP/Amass/v3/config"
	"github.com/OWASP/Amass/v3/net/http"
	"github.com/OWASP/Amass/v3/requests"
	"github.com/OWASP/Amass/v3/systems"
	"github.com/caffix/service"
	"github.com/caffix/stringset"
)

// DNSDB is the Service that handles access to the DNSDB data source.
type DNSDB struct {
	service.BaseService

	SourceType string
	sys        systems.System
	creds      *config.Credentials
}

// NewDNSDB returns he object initialized, but not yet started.
func NewDNSDB(sys systems.System) *DNSDB {
	d := &DNSDB{
		SourceType: requests.API,
		sys:        sys,
	}

	go d.requests()
	d.BaseService = *service.NewBaseService(d, "DNSDB")
	return d
}

// Description implements the Service interface.
func (d *DNSDB) Description() string {
	return d.SourceType
}

// OnStart implements the Service interface.
func (d *DNSDB) OnStart() error {
	d.creds = d.sys.Config().GetDataSourceConfig(d.String()).GetCredentials()

	if d.creds == nil || d.creds.Key == "" {
		d.sys.Config().Log.Printf("%s: API key data was not provided", d.String())
	}

	d.SetRateLimit(1)
	return d.checkConfig()
}

func (d *DNSDB) checkConfig() error {
	creds := d.sys.Config().GetDataSourceConfig(d.String()).GetCredentials()

	if creds == nil || creds.Key == "" {
		estr := fmt.Sprintf("%s: check callback failed for the configuration", d.String())
		d.sys.Config().Log.Print(estr)
		return errors.New(estr)
	}

	return nil
}

func (d *DNSDB) requests() {
	for {
		select {
		case <-d.Done():
			return
		case in := <-d.Input():
			switch req := in.(type) {
			case *requests.DNSRequest:
				d.CheckRateLimit()
				d.dnsRequest(context.TODO(), req)
			}
		}
	}
}

func (d *DNSDB) dnsRequest(ctx context.Context, req *requests.DNSRequest) {
	if !d.sys.Config().IsDomainInScope(req.Domain) {
		return
	}

	if d.creds == nil || d.creds.Key == "" {
		return
	}

	numRateLimitChecks(d, 120)
	d.sys.Config().Log.Printf("Querying %s for %s subdomains", d.String(), req.Domain)

	headers := map[string]string{
		"X-API-Key":    d.creds.Key,
		"Accept":       "application/json",
		"Content-Type": "application/json",
	}

	url := d.getURL(req.Domain)
	page, err := http.RequestWebPage(ctx, url, nil, headers, nil)
	if err != nil {
		d.sys.Config().Log.Printf("%s: %s: %v", d.String(), url, err)
		return
	}

	for _, name := range d.parse(ctx, page, req.Domain) {
		genNewNameEvent(ctx, d.sys, d, name)
	}
}

func (d *DNSDB) getURL(domain string) string {
	return fmt.Sprintf("https://api.dnsdb.info/lookup/rrset/name/*.%s?limit=10000000", domain)
}

func (d *DNSDB) parse(ctx context.Context, page, domain string) []string {
	re := d.sys.Config().DomainRegex(domain)
	if re == nil {
		return []string{}
	}

	unique := stringset.New()
	defer unique.Close()

	scanner := bufio.NewScanner(strings.NewReader(page))
	for scanner.Scan() {
		// Get the next line of JSON
		line := scanner.Text()
		if line == "" {
			continue
		}

		var j struct {
			Name string `json:"rrname"`
		}
		err := json.Unmarshal([]byte(line), &j)
		if err != nil {
			continue
		}
		if re.MatchString(j.Name) {
			unique.Insert(j.Name)
		}
	}
	return unique.Slice()
}
