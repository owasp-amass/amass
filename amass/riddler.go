// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package amass

import (
	"fmt"

	"github.com/OWASP/Amass/amass/utils"
)

// Riddler is the AmassService that handles access to the Riddler data source.
type Riddler struct {
	BaseAmassService

	SourceType string
}

// NewRiddler returns he object initialized, but not yet started.
func NewRiddler(e *Enumeration) *Riddler {
	r := &Riddler{SourceType: SCRAPE}

	r.BaseAmassService = *NewBaseAmassService(e, "Riddler", r)
	return r
}

// OnStart implements the AmassService interface
func (r *Riddler) OnStart() error {
	r.BaseAmassService.OnStart()

	go r.startRootDomains()
	go r.processRequests()
	return nil
}

// OnStop implements the AmassService interface
func (r *Riddler) OnStop() error {
	r.BaseAmassService.OnStop()
	return nil
}

func (r *Riddler) processRequests() {
	for {
		select {
		case <-r.PauseChan():
			<-r.ResumeChan()
		case <-r.Quit():
			return
		case <-r.RequestChan():
			// This data source just throws away the checked DNS names
			r.SetActive()
		}
	}
}

func (r *Riddler) startRootDomains() {
	// Look at each domain provided by the config
	for _, domain := range r.Enum().Config.Domains() {
		r.executeQuery(domain)
	}
}

func (r *Riddler) executeQuery(domain string) {
	url := r.getURL(domain)
	page, err := utils.RequestWebPage(url, nil, nil, "", "")
	if err != nil {
		r.Enum().Log.Printf("%s: %s: %v", r.String(), url, err)
		return
	}

	r.SetActive()
	re := r.Enum().Config.DomainRegex(domain)
	for _, sd := range re.FindAllString(page, -1) {
		r.Enum().NewNameEvent(&AmassRequest{
			Name:   cleanName(sd),
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
