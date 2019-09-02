// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package sources

import (
	"fmt"

	"github.com/OWASP/Amass/config"
	eb "github.com/OWASP/Amass/eventbus"
	"github.com/OWASP/Amass/net/http"
	"github.com/OWASP/Amass/requests"
	"github.com/OWASP/Amass/resolvers"
	"github.com/OWASP/Amass/services"
)

// Netcraft is the Service that handles access to the Netcraft data source.
type Netcraft struct {
	services.BaseService

	SourceType string
}

// NewNetcraft returns he object initialized, but not yet started.
func NewNetcraft(cfg *config.Config, bus *eb.EventBus, pool *resolvers.ResolverPool) *Netcraft {
	n := &Netcraft{SourceType: requests.SCRAPE}

	n.BaseService = *services.NewBaseService(n, "Netcraft", cfg, bus, pool)
	return n
}

// OnStart implements the Service interface
func (n *Netcraft) OnStart() error {
	n.BaseService.OnStart()

	go n.processRequests()
	return nil
}

func (n *Netcraft) processRequests() {
	for {
		select {
		case <-n.Quit():
			return
		case req := <-n.DNSRequestChan():
			if n.Config().IsDomainInScope(req.Domain) {
				n.executeQuery(req.Domain)
			}
		case <-n.AddrRequestChan():
		case <-n.ASNRequestChan():
		case <-n.WhoisRequestChan():
		}
	}
}

func (n *Netcraft) executeQuery(domain string) {
	re := n.Config().DomainRegex(domain)
	if re == nil {
		return
	}

	n.SetActive()
	url := n.getURL(domain)
	page, err := http.RequestWebPage(url, nil, nil, "", "")
	if err != nil {
		n.Bus().Publish(requests.LogTopic, fmt.Sprintf("%s: %s: %v", n.String(), url, err))
		return
	}

	for _, sd := range re.FindAllString(page, -1) {
		n.Bus().Publish(requests.NewNameTopic, &requests.DNSRequest{
			Name:   cleanName(sd),
			Domain: domain,
			Tag:    n.SourceType,
			Source: n.String(),
		})
	}
}

func (n *Netcraft) getURL(domain string) string {
	format := "https://searchdns.netcraft.com/?restriction=site+ends+with&host=%s"

	return fmt.Sprintf(format, domain)
}
