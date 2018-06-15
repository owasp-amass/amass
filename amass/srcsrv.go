// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package amass

import (
	"regexp"
	"strings"
	"time"

	evbus "github.com/asaskevich/EventBus"
	"github.com/caffix/amass/amass/sources"
)

type source struct {
	Query sources.Query
	Tag   string
	Str   string
}

type SourcesService struct {
	BaseAmassService

	bus          evbus.Bus
	responses    chan *AmassRequest
	sources      []*source
	inFilter     map[string]struct{}
	outFilter    map[string]struct{}
	domainFilter map[string]struct{}
}

func NewSourcesService(config *AmassConfig, bus evbus.Bus) *SourcesService {
	ss := &SourcesService{
		bus:          bus,
		responses:    make(chan *AmassRequest, 50),
		inFilter:     make(map[string]struct{}),
		outFilter:    make(map[string]struct{}),
		domainFilter: make(map[string]struct{}),
	}

	ss.BaseAmassService = *NewBaseAmassService("Sources Service", config, ss)

	ss.sources = []*source{
		&source{
			Query: sources.ArchiveItQuery,
			Str:   sources.ArchiveItSourceString,
			Tag:   ARCHIVE,
		},
		&source{
			Query: sources.ArchiveTodayQuery,
			Str:   sources.ArchiveTodaySourceString,
			Tag:   ARCHIVE,
		},
		&source{
			Query: sources.ArquivoQuery,
			Str:   sources.ArquivoSourceString,
			Tag:   ARCHIVE,
		},
		&source{
			Query: sources.AskQuery,
			Str:   sources.AskSourceString,
			Tag:   SCRAPE,
		},
		&source{
			Query: sources.BaiduQuery,
			Str:   sources.BaiduSourceString,
			Tag:   SCRAPE,
		},
		&source{
			Query: sources.BingQuery,
			Str:   sources.BingSourceString,
			Tag:   SCRAPE,
		},
		&source{
			Query: sources.CensysQuery,
			Str:   sources.CensysSourceString,
			Tag:   SCRAPE,
		},
		&source{
			Query: sources.CertDBQuery,
			Str:   sources.CertDBSourceString,
			Tag:   CERT,
		},
		&source{
			Query: sources.CertSpotterQuery,
			Str:   sources.CertSpotterSourceString,
			Tag:   CERT,
		},
		&source{
			Query: sources.CrtshQuery,
			Str:   sources.CrtshSourceString,
			Tag:   CERT,
		},
		&source{
			Query: sources.DNSDBQuery,
			Str:   sources.DNSDBSourceString,
			Tag:   SCRAPE,
		},
		&source{
			Query: sources.DNSDumpsterQuery,
			Str:   sources.DNSDumpsterSourceString,
			Tag:   SCRAPE,
		},
		&source{
			Query: sources.DogpileQuery,
			Str:   sources.DogpileSourceString,
			Tag:   SCRAPE,
		},
		&source{
			Query: sources.EntrustQuery,
			Str:   sources.EntrustSourceString,
			Tag:   CERT,
		},
		&source{
			Query: sources.ExaleadQuery,
			Str:   sources.ExaleadSourceString,
			Tag:   SCRAPE,
		},
		&source{
			Query: sources.FindSubdomainsQuery,
			Str:   sources.FindSubdomainsSourceString,
			Tag:   SCRAPE,
		},
		&source{
			Query: sources.GoogleQuery,
			Str:   sources.GoogleSourceString,
			Tag:   SCRAPE,
		},
		&source{
			Query: sources.HackerTargetQuery,
			Str:   sources.HackerTargetSourceString,
			Tag:   SCRAPE,
		},
		&source{
			Query: sources.IPv4InfoQuery,
			Str:   sources.IPv4InfoSourceString,
			Tag:   SCRAPE,
		},
		&source{
			Query: sources.LoCArchiveQuery,
			Str:   sources.LoCArchiveSourceString,
			Tag:   ARCHIVE,
		},
		&source{
			Query: sources.NetcraftQuery,
			Str:   sources.NetcraftSourceString,
			Tag:   SCRAPE,
		},
		&source{
			Query: sources.OpenUKArchiveQuery,
			Str:   sources.OpenUKArchiveSourceString,
			Tag:   ARCHIVE,
		},
		&source{
			Query: sources.PTRArchiveQuery,
			Str:   sources.PTRArchiveSourceString,
			Tag:   SCRAPE,
		},
		&source{
			Query: sources.RiddlerQuery,
			Str:   sources.RiddlerSourceString,
			Tag:   SCRAPE,
		},
		&source{
			Query: sources.RobtexQuery,
			Str:   sources.RobtexSourceString,
			Tag:   SCRAPE,
		},
		&source{
			Query: sources.SiteDossierQuery,
			Str:   sources.SiteDossierSourceString,
			Tag:   SCRAPE,
		},
		&source{
			Query: sources.ThreatCrowdQuery,
			Str:   sources.ThreatCrowdSourceString,
			Tag:   SCRAPE,
		},
		&source{
			Query: sources.ThreatMinerQuery,
			Str:   sources.ThreatMinerSourceString,
			Tag:   SCRAPE,
		},
		&source{
			Query: sources.UKGovArchiveQuery,
			Str:   sources.UKGovArchiveSourceString,
			Tag:   ARCHIVE,
		},
		&source{
			Query: sources.VirusTotalQuery,
			Str:   sources.VirusTotalSourceString,
			Tag:   SCRAPE,
		},
		&source{
			Query: sources.WaybackMachineQuery,
			Str:   sources.WaybackMachineSourceString,
			Tag:   ARCHIVE,
		},
		&source{
			Query: sources.YahooQuery,
			Str:   sources.YahooSourceString,
			Tag:   SCRAPE,
		},
	}
	return ss
}

func (ss *SourcesService) OnStart() error {
	ss.BaseAmassService.OnStart()

	ss.bus.SubscribeAsync(RESOLVED, ss.SendRequest, false)
	go ss.processRequests()
	go ss.processOutput()
	go ss.queryAllSources()
	return nil
}

func (ss *SourcesService) OnStop() error {
	ss.BaseAmassService.OnStop()

	ss.bus.Unsubscribe(RESOLVED, ss.SendRequest)
	return nil
}

func (ss *SourcesService) processRequests() {
	t := time.NewTicker(1 * time.Second)
	defer t.Stop()

	for {
		select {
		case <-t.C:
			if req := ss.NextRequest(); req != nil {
				go ss.handleRequest(req)
			}
		case <-ss.Quit():
			return
		}
	}
}

func (ss *SourcesService) handleRequest(req *AmassRequest) {
	if ss.inDup(req.Name) || !ss.Config().IsDomainInScope(req.Name) {
		return
	}

	ss.SetActive()
	for _, s := range ss.sources {
		go ss.queryOneSource(s, req.Domain, req.Name)
	}
}

func (ss *SourcesService) processOutput() {
	for {
		select {
		case req := <-ss.responses:
			ss.handleOutput(req)
		case <-ss.Quit():
			return
		}
	}
}

func (ss *SourcesService) handleOutput(req *AmassRequest) {
	re := regexp.MustCompile("^((252f)|(2f)|(3d))+")

	ss.SetActive()
	// Clean up the names scraped from the web
	req.Name = strings.ToLower(req.Name)
	if i := re.FindStringIndex(req.Name); i != nil {
		req.Name = req.Name[i[1]:]
	}
	req.Name = strings.TrimSpace(req.Name)

	if ss.outDup(req.Name) {
		return
	}

	if ss.Config().NoDNS {
		ss.bus.Publish(OUTPUT, &AmassOutput{
			Name:   req.Name,
			Domain: req.Domain,
			Tag:    req.Tag,
			Source: req.Source,
		})
	} else {
		ss.bus.Publish(DNSQUERY, req)
	}
}

func (ss *SourcesService) inDup(sub string) bool {
	ss.Lock()
	defer ss.Unlock()

	if _, found := ss.inFilter[sub]; found {
		return true
	}
	ss.inFilter[sub] = struct{}{}
	return false
}

func (ss *SourcesService) outDup(sub string) bool {
	ss.Lock()
	defer ss.Unlock()

	if _, found := ss.outFilter[sub]; found {
		return true
	}
	ss.outFilter[sub] = struct{}{}
	return false
}

func (ss *SourcesService) queryAllSources() {
	ss.SetActive()

	for _, domain := range ss.Config().Domains() {
		if _, found := ss.domainFilter[domain]; found {
			continue
		}

		ss.SendRequest(&AmassRequest{
			Name:   domain,
			Domain: domain,
		})
	}
}

func (ss *SourcesService) queryOneSource(s *source, domain, sub string) {
	names := s.Query(domain, sub)
	for _, name := range names {
		ss.responses <- &AmassRequest{
			Name:   name,
			Domain: domain,
			Tag:    s.Tag,
			Source: s.Str,
		}
	}
}
