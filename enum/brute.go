// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package enum

import (
	"strings"
	"time"

	"github.com/OWASP/Amass/graph"
	"github.com/OWASP/Amass/requests"
	"github.com/OWASP/Amass/stringset"
)

var topNames = []string{
	"www",
	"online",
	"webserver",
	"ns1",
	"mail",
	"smtp",
	"webmail",
	"prod",
	"test",
	"vpn",
	"ftp",
	"ssh",
}

func (e *Enumeration) startBruteForcing() {
	// Send in the root domain names for brute forcing
	for _, domain := range e.Config.Domains() {
		e.bruteSendNewNames(&requests.DNSRequest{
			Name:   domain,
			Domain: domain,
		})
	}

	curIdx := 0
	maxIdx := 7
	delays := []int{10, 25, 50, 75, 100, 150, 250, 500}
loop:
	for {
		select {
		case <-e.done:
			return
		default:
			element, ok := e.bruteQueue.Next()
			if !ok {
				time.Sleep(time.Duration(delays[curIdx]) * time.Millisecond)
				if curIdx < maxIdx {
					curIdx++
				}
				continue loop
			}

			curIdx = 0
			req := element.(*requests.DNSRequest)
			e.bruteSendNewNames(req)
		}
	}
}

func (e *Enumeration) bruteSendNewNames(req *requests.DNSRequest) {
	if !e.Config.IsDomainInScope(req.Name) {
		return
	}

	if len(req.Records) > 0 && !e.hasARecords(req) {
		return
	}

	subdomain := strings.ToLower(req.Name)
	domain := strings.ToLower(req.Domain)
	if subdomain == "" || domain == "" {
		return
	}

	for _, g := range e.Sys.GraphDatabases() {
		// CNAMEs are not a proper subdomain
		cname := g.IsCNAMENode(&graph.DataOptsParams{
			UUID:   e.Config.UUID.String(),
			Name:   subdomain,
			Domain: domain,
		})
		if cname {
			return
		}
	}

	for _, word := range e.Config.Wordlist {
		if word == "" {
			continue
		}

		e.newNameEvent(&requests.DNSRequest{
			Name:   word + "." + subdomain,
			Domain: domain,
			Tag:    requests.BRUTE,
			Source: "Brute Forcing",
		})
	}
}

func (e *Enumeration) performAlterations() {
	curIdx := 0
	maxIdx := 7
	delays := []int{10, 25, 50, 75, 100, 150, 250, 500}
loop:
	for {
		select {
		case <-e.done:
			return
		default:
			element, ok := e.altQueue.Next()
			if !ok {
				time.Sleep(time.Duration(delays[curIdx]) * time.Millisecond)
				if curIdx < maxIdx {
					curIdx++
				}
				continue loop
			}

			curIdx = 0
			req := element.(*requests.DNSRequest)

			if !e.Config.IsDomainInScope(req.Name) ||
				(len(strings.Split(req.Domain, ".")) == len(strings.Split(req.Name, "."))) {
				continue loop
			}

			for _, g := range e.Sys.GraphDatabases() {
				// CNAMEs are not a proper subdomain
				cname := g.IsCNAMENode(&graph.DataOptsParams{
					UUID:   e.Config.UUID.String(),
					Name:   req.Name,
					Domain: req.Domain,
				})
				if cname {
					continue loop
				}
			}

			newNames := stringset.New()

			e.markovModel.Train(req.Name)
			if e.markovModel.TotalTrainings() >= 50 &&
				(e.markovModel.TotalTrainings()%10 == 0) {
				newNames.InsertMany(e.markovModel.GenerateNames(100)...)
			}

			if e.Config.FlipNumbers {
				newNames.InsertMany(e.altState.FlipNumbers(req.Name)...)
			}
			if e.Config.AddNumbers {
				newNames.InsertMany(e.altState.AppendNumbers(req.Name)...)
			}
			if e.Config.FlipWords {
				newNames.InsertMany(e.altState.FlipWords(req.Name)...)
			}
			if e.Config.AddWords {
				newNames.InsertMany(e.altState.AddSuffixWord(req.Name)...)
				newNames.InsertMany(e.altState.AddPrefixWord(req.Name)...)
			}
			if e.Config.EditDistance > 0 {
				newNames.InsertMany(e.altState.FuzzyLabelSearches(req.Name)...)
			}

			for _, name := range newNames.Slice() {
				if !e.Config.IsDomainInScope(name) {
					continue
				}

				e.newNameEvent(&requests.DNSRequest{
					Name:   name,
					Domain: req.Domain,
					Tag:    requests.ALT,
					Source: "Alterations",
				})
			}
		}
	}
}
