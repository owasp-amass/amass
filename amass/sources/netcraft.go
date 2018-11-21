// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package sources

import (
	"fmt"

	"github.com/OWASP/Amass/amass/core"
	"github.com/OWASP/Amass/amass/utils"
	evbus "github.com/asaskevich/EventBus"
)

// Netcraft is the AmassService that handles access to the Netcraft data source.
type Netcraft struct {
	core.BaseAmassService

	Bus        evbus.Bus
	Config     *core.AmassConfig
	SourceType string
}

// Netcraft requires the enumeration configuration and event bus as parameters.
// The object returned is initialized, but has not yet been started.
func NewNetcraft(e *core.Enumeration, bus evbus.Bus, config *core.AmassConfig) *Netcraft {
	n := &Netcraft{
		Bus:        bus,
		Config:     config,
		SourceType: core.SCRAPE,
	}

	n.BaseAmassService = *core.NewBaseAmassService(e, "Netcraft", n)
	return n
}

// OnStart implements the AmassService interface
func (n *Netcraft) OnStart() error {
	n.BaseAmassService.OnStart()

	go n.startRootDomains()
	return nil
}

// OnStop implements the AmassService interface
func (n *Netcraft) OnStop() error {
	n.BaseAmassService.OnStop()
	return nil
}

func (n *Netcraft) startRootDomains() {
	// Look at each domain provided by the config
	for _, domain := range n.Config.Domains() {
		n.executeQuery(domain)
	}
}

func (n *Netcraft) executeQuery(domain string) {
	url := n.getURL(domain)
	page, err := utils.RequestWebPage(url, nil, nil, "", "")
	if err != nil {
		n.Config.Log.Printf("%s: %s, %v", n.String(), url, err)
		return
	}

	n.SetActive()
	re := n.Config.DomainRegex(domain)
	for _, sd := range re.FindAllString(page, -1) {
		req := &core.AmassRequest{
			Name:   cleanName(sd),
			Domain: domain,
			Tag:    n.SourceType,
			Source: n.String(),
		}

		if n.Enum().DupDataSourceName(req) {
			continue
		}
		n.Bus.Publish(core.NEWNAME, req)
	}
}

func (n *Netcraft) getURL(domain string) string {
	format := "https://searchdns.netcraft.com/?restriction=site+ends+with&host=%s"

	return fmt.Sprintf(format, domain)
}
