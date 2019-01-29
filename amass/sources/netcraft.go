// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package sources

import (
	"fmt"

	"github.com/OWASP/Amass/amass/core"
	"github.com/OWASP/Amass/amass/utils"
)

// Netcraft is the Service that handles access to the Netcraft data source.
type Netcraft struct {
	core.BaseService

	SourceType string
}

// NewNetcraft returns he object initialized, but not yet started.
func NewNetcraft(config *core.Config, bus *core.EventBus) *Netcraft {
	n := &Netcraft{SourceType: core.SCRAPE}

	n.BaseService = *core.NewBaseService(n, "Netcraft", config, bus)
	return n
}

// OnStart implements the Service interface
func (n *Netcraft) OnStart() error {
	n.BaseService.OnStart()

	go n.startRootDomains()
	return nil
}

func (n *Netcraft) startRootDomains() {
	// Look at each domain provided by the config
	for _, domain := range n.Config().Domains() {
		n.executeQuery(domain)
	}
}

func (n *Netcraft) executeQuery(domain string) {
	url := n.getURL(domain)
	page, err := utils.RequestWebPage(url, nil, nil, "", "")
	if err != nil {
		n.Config().Log.Printf("%s: %s, %v", n.String(), url, err)
		return
	}

	n.SetActive()
	re := n.Config().DomainRegex(domain)
	for _, sd := range re.FindAllString(page, -1) {
		n.Bus().Publish(core.NewNameTopic, &core.Request{
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
