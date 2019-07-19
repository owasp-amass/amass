// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package sources

import (
	"fmt"

	"github.com/OWASP/Amass/config"
	eb "github.com/OWASP/Amass/eventbus"
	"github.com/OWASP/Amass/requests"
	"github.com/OWASP/Amass/resolvers"
	"github.com/OWASP/Amass/services"
	"github.com/OWASP/Amass/utils"
)

// Riddler is the Service that handles access to the Riddler data source.
type Riddler struct {
	services.BaseService

	SourceType string
}

// NewRiddler returns he object initialized, but not yet started.
func NewRiddler(cfg *config.Config, bus *eb.EventBus, pool *resolvers.ResolverPool) *Riddler {
	r := &Riddler{SourceType: requests.SCRAPE}

	r.BaseService = *services.NewBaseService(r, "Riddler", cfg, bus, pool)
	return r
}

// OnStart implements the Service interface
func (r *Riddler) OnStart() error {
	r.BaseService.OnStart()

	go r.processRequests()
	return nil
}

func (r *Riddler) processRequests() {
	for {
		select {
		case <-r.Quit():
			return
		case req := <-r.DNSRequestChan():
			if r.Config().IsDomainInScope(req.Domain) {
				r.executeQuery(req.Domain)
			}
		case <-r.AddrRequestChan():
		case <-r.ASNRequestChan():
		case <-r.WhoisRequestChan():
		}
	}
}

func (r *Riddler) executeQuery(domain string) {
	re := r.Config().DomainRegex(domain)
	if re == nil {
		return
	}

	r.SetActive()
	url := r.getURL(domain)
	page, err := utils.RequestWebPage(url, nil, nil, "", "")
	if err != nil {
		r.Config().Log.Printf("%s: %s: %v", r.String(), url, err)
		return
	}

	for _, name := range re.FindAllString(page, -1) {
		r.Bus().Publish(requests.NewNameTopic, &requests.DNSRequest{
			Name:   cleanName(name),
			Domain: domain,
			Tag:    r.SourceType,
			Source: r.String(),
		})
	}
}

func (r *Riddler) getURL(domain string) string {
	format := "https://riddler.io/search?q=pld:%s"

	return fmt.Sprintf(format, domain)
}
