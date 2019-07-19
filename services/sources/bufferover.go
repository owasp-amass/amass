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

// BufferOver is the Service that handles access to the BufferOver data source.
type BufferOver struct {
	services.BaseService

	SourceType string
}

// NewBufferOver returns he object initialized, but not yet started.
func NewBufferOver(c *config.Config, bus *eb.EventBus, pool *resolvers.ResolverPool) *BufferOver {
	b := &BufferOver{SourceType: requests.API}

	b.BaseService = *services.NewBaseService(b, "BufferOver", c, bus, pool)
	return b
}

// OnStart implements the Service interface
func (b *BufferOver) OnStart() error {
	b.BaseService.OnStart()

	go b.processRequests()
	return nil
}

func (b *BufferOver) processRequests() {
	for {
		select {
		case <-b.Quit():
			return
		case req := <-b.DNSRequestChan():
			if b.Config().IsDomainInScope(req.Domain) {
				b.executeQuery(req.Domain)
			}
		case <-b.AddrRequestChan():
		case <-b.ASNRequestChan():
		case <-b.WhoisRequestChan():
		}
	}
}

func (b *BufferOver) executeQuery(domain string) {
	re := b.Config().DomainRegex(domain)
	if re == nil {
		return
	}

	b.SetActive()
	url := b.getURL(domain)
	page, err := utils.RequestWebPage(url, nil, nil, "", "")
	if err != nil {
		b.Config().Log.Printf("%s: %s: %v", b.String(), url, err)
		return
	}

	for _, sd := range re.FindAllString(page, -1) {
		b.Bus().Publish(requests.NewNameTopic, &requests.DNSRequest{
			Name:   cleanName(sd),
			Domain: domain,
			Tag:    b.SourceType,
			Source: b.String(),
		})
	}
}

func (b *BufferOver) getURL(domain string) string {
	format := "https://dns.bufferover.run/dns?q=.%s"

	return fmt.Sprintf(format, domain)
}
