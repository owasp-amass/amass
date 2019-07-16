// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package sources

import (
	"fmt"

	"github.com/OWASP/Amass/amass/core"
	"github.com/OWASP/Amass/amass/eventbus"
	"github.com/OWASP/Amass/amass/utils"
)

// Netcraft is the Service that handles access to the Netcraft data source.
type Netcraft struct {
	core.BaseService

	SourceType string
}

// NewNetcraft returns he object initialized, but not yet started.
func NewNetcraft(config *core.Config, bus *eventbus.EventBus) *Netcraft {
	n := &Netcraft{SourceType: core.SCRAPE}

	n.BaseService = *core.NewBaseService(n, "Netcraft", config, bus)
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
	page, err := utils.RequestWebPage(url, nil, nil, "", "")
	if err != nil {
		n.Config().Log.Printf("%s: %s, %v", n.String(), url, err)
		return
	}

	for _, sd := range re.FindAllString(page, -1) {
		n.Bus().Publish(core.NewNameTopic, &core.DNSRequest{
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
