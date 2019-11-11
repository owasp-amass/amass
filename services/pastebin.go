package services

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/OWASP/Amass/v3/config"
	"github.com/OWASP/Amass/v3/eventbus"
	"github.com/OWASP/Amass/v3/net/http"
	"github.com/OWASP/Amass/v3/requests"
)

// Pastebin is the Service that handles access to the Pastebin data source.
type Pastebin struct {
	BaseService

	SourceType string
}

// NewPastebin returns he object initialized, but not yet started.
func NewPastebin(sys System) *Pastebin {
	p := &Pastebin{SourceType: requests.API}

	p.BaseService = *NewBaseService(p, "Pastebin", sys)
	return p
}

// OnStart implements the Service interface.
func (p *Pastebin) OnStart() error {
	p.BaseService.OnStart()

	p.SetRateLimit(3 * time.Second)
	return nil
}

// OnDNSRequest implements the Service interface.
func (p *Pastebin) OnDNSRequest(ctx context.Context, req *requests.DNSRequest) {
	cfg := ctx.Value(requests.ContextConfig).(*config.Config)
	bus := ctx.Value(requests.ContextEventBus).(*eventbus.EventBus)
	if cfg == nil || bus == nil {
		return
	}

	re := cfg.DomainRegex(req.Domain)
	if re == nil {
		return
	}

	p.CheckRateLimit()
	bus.Publish(requests.LogTopic, fmt.Sprintf("Querying %s for %s subdomains", p.String(), req.Domain))

	ids, err := p.extractIDs(req.Domain)
	if err != nil {
		bus.Publish(requests.LogTopic, fmt.Sprintf("%s: %s: %v", p.String(), req.Domain, err))
		return
	}

	for _, id := range ids {
		url := p.webURLDumpData(id)
		page, err := http.RequestWebPage(url, nil, nil, "", "")
		if err != nil {
			bus.Publish(requests.LogTopic, fmt.Sprintf("%s: %s: %v", p.String(), url, err))
			return
		}

		for _, name := range re.FindAllString(page, -1) {
			bus.Publish(requests.NewNameTopic, &requests.DNSRequest{
				Name:   name,
				Domain: req.Domain,
				Tag:    p.SourceType,
				Source: p.String(),
			})
		}
	}
}

// Extract the IDs from the pastebin Web response.
func (p *Pastebin) extractIDs(domain string) ([]string, error) {
	url := p.webURLDumpIDs(domain)
	page, err := http.RequestWebPage(url, nil, nil, "", "")
	if err != nil {
		return nil, err
	}

	// Extract the response given by pastebin
	var d struct {
		Search string `json:"search"`
		Count  int    `json:"count"`
		Items  []struct {
			ID   string `json:"id"`
			Tags string `json:"tags"`
			Time string `json:"time"`
		} `json:"data"`
	}
	err = json.Unmarshal([]byte(page), &d)
	if err != nil {
		return nil, err
	}

	var ids []string
	for _, item := range d.Items {
		ids = append(ids, item.ID)
	}

	return ids, nil
}

// Returns the Web URL to fetch all dump ids for a given doamin.
func (p *Pastebin) webURLDumpIDs(domain string) string {
	return fmt.Sprintf("https://psbdmp.ws/api/search/%s", domain)
}

// Returns the Web URL to get all dumps for a given doamin.
func (p *Pastebin) webURLDumpData(id string) string {
	return fmt.Sprintf("https://psbdmp.ws/api/dump/get/%s", id)
}
