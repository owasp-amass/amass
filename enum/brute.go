// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package enum

import (
	"strings"

	"github.com/OWASP/Amass/v3/requests"
	"github.com/OWASP/Amass/v3/stringset"
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

	for {
		select {
		case <-e.done:
			return
		case <-e.moreBrute:
			if element, ok := e.bruteQueue.Next(); ok {
				req := element.(*requests.DNSRequest)

				e.bruteSendNewNames(req)
			}
		}
	}
}

func (e *Enumeration) moreBruteForcing() {
	if !e.bruteQueue.Empty() {
		e.moreBrute <- struct{}{}
	}
}

func (e *Enumeration) bruteSendNewNames(req *requests.DNSRequest) {
	if !e.Config.IsDomainInScope(req.Name) {
		return
	}

	if len(req.Records) > 0 && (e.hasCNAMERecord(req) || !e.hasARecords(req)) {
		return
	}

	subdomain := strings.ToLower(req.Name)
	domain := strings.ToLower(req.Domain)
	if subdomain == "" || domain == "" {
		return
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
	for {
		select {
		case <-e.done:
			return
		case <-e.moreAlts:
			if element, ok := e.altQueue.Next(); ok {
				req := element.(*requests.DNSRequest)

				if e.Config.IsDomainInScope(req.Name) &&
					(len(strings.Split(req.Name, ".")) > len(strings.Split(req.Domain, "."))) {
					go e.executeAlts(req)
					go e.useMarkovModel(req)
				}
			}
		}
	}
}

func (e *Enumeration) moreAlterations() {
	if !e.altQueue.Empty() {
		e.moreAlts <- struct{}{}
	}
}

func (e *Enumeration) executeAlts(req *requests.DNSRequest) {
	names := stringset.New()

	if e.Config.FlipNumbers {
		names.InsertMany(e.altState.FlipNumbers(req.Name)...)
	}
	if e.Config.AddNumbers {
		names.InsertMany(e.altState.AppendNumbers(req.Name)...)
	}
	if e.Config.FlipWords {
		names.InsertMany(e.altState.FlipWords(req.Name)...)
	}
	if e.Config.AddWords {
		names.InsertMany(e.altState.AddSuffixWord(req.Name)...)
		names.InsertMany(e.altState.AddPrefixWord(req.Name)...)
	}
	if e.Config.EditDistance > 0 {
		names.InsertMany(e.altState.FuzzyLabelSearches(req.Name)...)
	}

	for name := range names {
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

func (e *Enumeration) useMarkovModel(req *requests.DNSRequest) {
	e.markovModel.Train(req.Name)

	if e.markovModel.TotalTrainings() < 50 || (e.markovModel.TotalTrainings()%10 != 0) {
		return
	}

	guesses := stringset.New(e.markovModel.GenerateNames(1000)...)

	for name := range guesses {
		domain := e.Config.WhichDomain(name)

		if domain == "" {
			continue
		}

		e.newNameEvent(&requests.DNSRequest{
			Name:   name,
			Domain: domain,
			Tag:    requests.GUESS,
			Source: "Markov Model",
		})
	}
}
