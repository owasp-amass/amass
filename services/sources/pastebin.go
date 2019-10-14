package sources

import (
	"time"
	"fmt"

	"github.com/OWASP/Amass/services"
	"github.com/OWASP/Amass/config"
	eb "github.com/OWASP/Amass/eventbus"
	"github.com/OWASP/Amass/resolvers"
	"github.com/OWASP/Amass/requests"
	"github.com/OWASP/Amass/net/http"
	"github.com/davecgh/go-spew/spew"
)



// Pastebin is the Service that handles access to the CertSpotter data source.
type Pastebin struct {
	services.BaseService

	SourceType string
	RateLimit  time.Duration
}

// NewPastebin returns he object initialized, but not yet started.
func NewPastebin(cfg *config.Config, bus *eb.EventBus, pool *resolvers.ResolverPool) *Pastebin {
	p := &Pastebin{
		SourceType: requests.API,
		RateLimit:  3 * time.Second,
	}

	p.BaseService = *services.NewBaseService(p, "Pastebin", cfg, bus, pool)
	return p
}


// OnStart implements the Service interface
func (p *Pastebin) OnStart() error {
	p.BaseService.OnStart()


	go p.processRequests()
	return nil
}

func (p *Pastebin) processRequests() {
	last := time.Now()

	for {
		select {
		case <-p.Quit():
			return
		case req := <-p.DNSRequestChan():
			if p.Config().IsDomainInScope(req.Domain) {
				if time.Now().Sub(last) < p.RateLimit {
					time.Sleep(p.RateLimit)
				}
				last = time.Now()
				p.executeQuery(req.Domain)
				last = time.Now()
			}
		case <-p.AddrRequestChan():
		case <-p.ASNRequestChan():
		case <-p.WhoisRequestChan():
		}
	}
}

func (p *Pastebin) executeQuery(domain string) {
	var err error
	var url, page string

	re := p.Config().DomainRegex(domain)
	spew.Dump(re)
	spew.Dump(p.webURLDumpIDs(domain))

	url = p.webURLDumpIDs(domain)
	page, err = http.RequestWebPage(url, nil, nil, "", "")
	if err != nil {
		p.Bus().Publish(requests.LogTopic, fmt.Sprintf("%s: %s: %v", p.String(), url, err))
		return
	}
	spew.Dump(page)

}

// Returns the Web URL to fetch all dump ids for a given doamin
func (p *Pastebin) webURLDumpIDs(domain string) string {
	return fmt.Sprintf("https://psbdmp.ws/api/search/%s", domain)
}