// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package amass

import (
	"strconv"
	"strings"
	"time"
	"unicode"
)

type AlterationService struct {
	BaseAmassService
}

func NewAlterationService(in, out chan *AmassRequest, config *AmassConfig) *AlterationService {
	as := new(AlterationService)

	as.BaseAmassService = *NewBaseAmassService("Alteration Service", config, as)

	as.input = in
	as.output = out
	return as
}

func (as *AlterationService) OnStart() error {
	as.BaseAmassService.OnStart()

	go as.processRequests()
	return nil
}

func (as *AlterationService) OnStop() error {
	as.BaseAmassService.OnStop()
	return nil
}

func (as *AlterationService) processRequests() {
	t := time.NewTicker(30 * time.Second)
	defer t.Stop()
loop:
	for {
		select {
		case req := <-as.Input():
			go as.executeAlterations(req)
		case <-t.C:
			as.SetActive(false)
		case <-as.Quit():
			break loop
		}
	}
}

// executeAlterations - Runs all the DNS name alteration methods as goroutines
func (as *AlterationService) executeAlterations(req *AmassRequest) {
	as.flipNumbersInName(req)
	as.appendNumbers(req)
	//go a.PrefixSuffixWords(name)
}

// flipNumbersInName - Method to flip numbers in a subdomain name
func (as *AlterationService) flipNumbersInName(req *AmassRequest) {
	n := req.Name
	parts := strings.SplitN(n, ".", 2)
	// Find the first character that is a number
	first := strings.IndexFunc(parts[0], unicode.IsNumber)
	if first < 0 {
		return
	}
	// Flip the first number and attempt a second number
	for i := 0; i < 10; i++ {
		sf := n[:first] + strconv.Itoa(i) + n[first+1:]

		as.secondNumberFlip(sf, req.Domain, first+1)
	}
	// Take the first number out
	as.secondNumberFlip(n[:first]+n[first+1:], req.Domain, -1)
}

func (as *AlterationService) secondNumberFlip(name, domain string, minIndex int) {
	parts := strings.SplitN(name, ".", 2)
	// Find the second character that is a number
	last := strings.LastIndexFunc(parts[0], unicode.IsNumber)
	if last < 0 || last < minIndex {
		as.sendAlteredName(name, domain)
		return
	}
	// Flip those numbers and send out the mutations
	for i := 0; i < 10; i++ {
		n := name[:last] + strconv.Itoa(i) + name[last+1:]

		as.SetActive(true)
		as.sendAlteredName(n, domain)
		// Do not go too fast
		time.Sleep(as.Config().Frequency * 2)
	}
	// Take the second number out
	as.sendAlteredName(name[:last]+name[last+1:], domain)
}

// appendNumbers - Method for appending a number to a subdomain name
func (as *AlterationService) appendNumbers(req *AmassRequest) {
	n := req.Name
	parts := strings.SplitN(n, ".", 2)

	for i := 0; i < 10; i++ {
		as.SetActive(true)
		// Send a LABEL-NUM altered name
		nhn := parts[0] + "-" + strconv.Itoa(i) + "." + parts[1]
		as.sendAlteredName(nhn, req.Domain)
		// Send a LABELNUM altered name
		nn := parts[0] + strconv.Itoa(i) + "." + parts[1]
		as.sendAlteredName(nn, req.Domain)
		// Do not go too fast
		time.Sleep(as.Config().Frequency * 2)
	}
}

/*
// prefixSuffixWords - Method for adding words to the prefix and suffix of a subdomain name
func (as *AlterationService) prefixSuffixWords(req *AmassRequest) {
	for _, word := range a.Wordlist {
		// Send the new names with the word as a prefix and suffix of the leftmost label
		as.prefixWord(req.Name, word, req.Domain)
		as.suffixWord(req.Name, word, req.Domain)
	}
}

func (as *AlterationService) prefixWord(name, word, domain string) {
	as.sendAlteredName(word+"-"+name, domain)
}

func (as *AlterationService) suffixWord(name, word, domain string) {
	parts := strings.SplitN(name, ".", 2)
	n := parts[0] + "-" + word + "." + parts[1]

	as.sendAlteredName(n, domain)
}
*/

// Checks that the name is valid and sends along for DNS resolve
func (as *AlterationService) sendAlteredName(name, domain string) {
	re := SubdomainRegex(domain)

	if re.MatchString(name) {
		as.SendOut(&AmassRequest{
			Name:   name,
			Domain: domain,
			Tag:    ALT,
			Source: "Alterations",
		})
	}
}
