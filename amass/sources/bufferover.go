// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package sources

import (
	"fmt"

	"github.com/OWASP/Amass/amass/core"
	"github.com/OWASP/Amass/amass/utils"
)

// BufferOver is the Service that handles access to the BufferOver data source.
type BufferOver struct {
	core.BaseService

	SourceType string
}

// NewBufferOver returns he object initialized, but not yet started.
func NewBufferOver(config *core.Config, bus *core.EventBus) *BufferOver {
	b := &BufferOver{SourceType: core.API}

	b.BaseService = *core.NewBaseService(b, "BufferOver", config, bus)
	return b
}

// OnStart implements the Service interface
func (b *BufferOver) OnStart() error {
	b.BaseService.OnStart()

	go b.startRootDomains()
	return nil
}

func (b *BufferOver) startRootDomains() {
	// Look at each domain provided by the config
	for _, domain := range b.Config().Domains() {
		b.executeQuery(domain)
	}
}

func (b *BufferOver) executeQuery(domain string) {
	url := b.getURL(domain)
	page, err := utils.RequestWebPage(url, nil, nil, "", "")
	if err != nil {
		b.Config().Log.Printf("%s: %s: %v", b.String(), url, err)
		return
	}

	b.SetActive()
	re := b.Config().DomainRegex(domain)
	for _, sd := range re.FindAllString(page, -1) {
		b.Bus().Publish(core.NewNameTopic, &core.Request{
			Name:   cleanName(sd),
			Domain: domain,
			Tag:    b.SourceType,
			Source: b.String(),
		})
	}
}

func (b *BufferOver) getURL(domain string) string {
	format := "https://dns.bufferover.run/dns?q=%s"

	return fmt.Sprintf(format, domain)
}
