// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package services

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/OWASP/Amass/v3/config"
	"github.com/OWASP/Amass/v3/eventbus"
	"github.com/OWASP/Amass/v3/net/http"
	"github.com/OWASP/Amass/v3/requests"
)

// WhoisXML is the Service that handles access to the WhoisXML data source.
type WhoisXML struct {
	BaseService

	API        *config.APIKey
	SourceType string
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
func NewWhoisXML(sys System) *WhoisXML {
	w := &WhoisXML{SourceType: requests.API}

	w.BaseService = *NewBaseService(w, "WhoisXML", sys)
	return w
}

// OnStart implements the Service interface.
func (w *WhoisXML) OnStart() error {
	w.BaseService.OnStart()

	w.API = w.System().Config().GetAPIKey(w.String())
	if w.API == nil || w.API.Key == "" {
		w.System().Config().Log.Printf("%s: API key data was not provided", w.String())
	}

	w.SetRateLimit(10 * time.Second)
	return nil
}

// OnWhoisRequest implements the Service interface.
func (w *WhoisXML) OnWhoisRequest(ctx context.Context, req *requests.WhoisRequest) {
	cfg := ctx.Value(requests.ContextConfig).(*config.Config)
	bus := ctx.Value(requests.ContextEventBus).(*eventbus.EventBus)
	if cfg == nil || bus == nil {
		return
	}

	if w.API == nil || w.API.Key == "" {
		return
	}

	if !cfg.IsDomainInScope(req.Domain) {
		return
	}

	u := w.getReverseWhoisURL(req.Domain)
	headers := map[string]string{"X-Authentication-Token": w.API.Key}

	var r = WhoisXMLBasicRequest{
		Search: "historic",
		Mode:   "purchase",
	}
	r.SearchTerms.Include = append(r.SearchTerms.Include, req.Domain)
	jr, _ := json.Marshal(r)

	page, err := http.RequestWebPage(u, bytes.NewReader(jr), headers, "", "")
	if err != nil {
		bus.Publish(requests.LogTopic, fmt.Sprintf("%s: %s: %w", w.String(), u, err))
		return
	}

	var q WhoisXMLResponse
	// Pull the table we need from the page content
	err = json.NewDecoder(strings.NewReader(page)).Decode(&q)
	if err != nil {
		bus.Publish(requests.LogTopic, fmt.Sprintf("Failed to decode json in WhoisXML.\nErr:%s", err))
		return
	}

	if q.Found > 0 {
		bus.Publish(requests.NewWhoisTopic, &requests.WhoisRequest{
			Domain:     req.Domain,
			NewDomains: q.List,
			Tag:        w.SourceType,
			Source:     w.String(),
		})
	}
}

func (w *WhoisXML) getReverseWhoisURL(domain string) string {
	return fmt.Sprint("https://reverse-whois-api.whoisxmlapi.com/api/v2")
}
