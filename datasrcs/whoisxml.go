// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package datasrcs

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/OWASP/Amass/v3/config"
	"github.com/OWASP/Amass/v3/eventbus"
	"github.com/OWASP/Amass/v3/net/http"
	"github.com/OWASP/Amass/v3/requests"
	"github.com/OWASP/Amass/v3/systems"
)

// WhoisXML is the Service that handles access to the WhoisXML data source.
type WhoisXML struct {
	requests.BaseService

	SourceType string
	sys        systems.System
	creds      *config.Credentials
}

// WhoisXMLResponse handles WhoisXML response json.
type WhoisXMLResponse struct {
	Found int      `json:"domainsCount"`
	List  []string `json:"domainsList"`
}

// WhoisXMLAdvanceSearchTerms are variables for the api's query with specific fields in mind.
type WhoisXMLAdvanceSearchTerms struct {
	Field string `json:"field"`
	Term  string `json:"term"`
}

// WhoisXMLAdvanceRequest handles POST request Json with specific fields.
type WhoisXMLAdvanceRequest struct {
	Search      string                       `json:"searchType"`
	Mode        string                       `json:"mode"`
	SearchTerms []WhoisXMLAdvanceSearchTerms `json:"advancedSearchTerms"`
}

// WhoisXMLBasicSearchTerms for searching by domain
type WhoisXMLBasicSearchTerms struct {
	Include []string `json:"include"`
}

// WhoisXMLBasicRequest is for using general search terms such as including domains and excluding regions.
type WhoisXMLBasicRequest struct {
	Search      string                   `json:"searchType"`
	Mode        string                   `json:"mode"`
	SearchTerms WhoisXMLBasicSearchTerms `json:"basicSearchTerms"`
}

// NewWhoisXML returns the object initialized, but not yet started.
func NewWhoisXML(sys systems.System) *WhoisXML {
	w := &WhoisXML{
		SourceType: requests.API,
		sys:        sys,
	}

	w.BaseService = *requests.NewBaseService(w, "WhoisXML")
	return w
}

// OnStart implements the Service interface.
func (w *WhoisXML) OnStart() error {
	w.BaseService.OnStart()

	w.creds = w.sys.Config().GetDataSourceConfig(w.String()).GetCredentials()
	if w.creds == nil || w.creds.Key == "" {
		w.sys.Config().Log.Printf("%s: API key data was not provided", w.String())
	}

	w.SetRateLimit(10 * time.Second)
	return nil
}

// CheckConfig implements the Service interface.
func (w *WhoisXML) CheckConfig() error {
	creds := w.sys.Config().GetDataSourceConfig(w.String()).GetCredentials()

	if creds == nil || creds.Key == "" {
		estr := fmt.Sprintf("%s: check callback failed for the configuration", w.String())
		w.sys.Config().Log.Print(estr)
		return errors.New(estr)
	}

	return nil
}

// OnWhoisRequest implements the Service interface.
func (w *WhoisXML) OnWhoisRequest(ctx context.Context, req *requests.WhoisRequest) {
	cfg := ctx.Value(requests.ContextConfig).(*config.Config)
	bus := ctx.Value(requests.ContextEventBus).(*eventbus.EventBus)
	if cfg == nil || bus == nil {
		return
	}

	if w.creds == nil || w.creds.Key == "" {
		return
	}

	if !cfg.IsDomainInScope(req.Domain) {
		return
	}
	bus.Publish(requests.LogTopic, eventbus.PriorityHigh,
		fmt.Sprintf("Querying %s for %s subdomains", w.String(), req.Domain))

	w.CheckRateLimit()
	bus.Publish(requests.SetActiveTopic, eventbus.PriorityCritical, w.String())

	u := w.getReverseWhoisURL(req.Domain)
	headers := map[string]string{"X-Authentication-Token": w.creds.Key}

	var r = WhoisXMLBasicRequest{
		Search: "historic",
		Mode:   "purchase",
	}
	r.SearchTerms.Include = append(r.SearchTerms.Include, req.Domain)
	jr, _ := json.Marshal(r)

	page, err := http.RequestWebPage(u, bytes.NewReader(jr), headers, "", "")
	if err != nil {
		bus.Publish(requests.LogTopic, eventbus.PriorityHigh, fmt.Sprintf("%s: %s: %v", w.String(), u, err))
		return
	}

	var q WhoisXMLResponse
	// Pull the table we need from the page content
	err = json.NewDecoder(strings.NewReader(page)).Decode(&q)
	if err != nil {
		bus.Publish(requests.LogTopic, eventbus.PriorityHigh,
			fmt.Sprintf("Failed to decode json in WhoisXML.\nErr:%s", err))
		return
	}

	if q.Found > 0 {
		bus.Publish(requests.NewWhoisTopic, eventbus.PriorityHigh, &requests.WhoisRequest{
			Domain:     req.Domain,
			NewDomains: q.List,
			Tag:        w.SourceType,
			Source:     w.String(),
		})
	}
}

func (w *WhoisXML) getReverseWhoisURL(domain string) string {
	return "https://reverse-whois-api.whoisxmlapi.com/api/v2"
}
