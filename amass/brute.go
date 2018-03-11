// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package amass

import (
	"strings"
	"time"
)

type BruteForceService struct {
	BaseAmassService

	// The initial list of words provided to brute forcing
	wordlist []string

	// Subdomains that have been worked on by brute forcing
	subdomains map[string]struct{}

	// Determines if recursive brute forcing will be employed
	recursive bool
}

func NewBruteForceService(in, out chan *AmassRequest) *BruteForceService {
	bfs := &BruteForceService{
		subdomains: make(map[string]struct{}),
		recursive:  true,
	}

	bfs.BaseAmassService = *NewBaseAmassService("Brute Forcing Service", bfs)

	bfs.input = in
	bfs.output = out
	return bfs
}

func (bfs *BruteForceService) OnStart() error {
	bfs.BaseAmassService.OnStart()

	go bfs.processRequests()
	return nil
}

func (bfs *BruteForceService) OnStop() error {
	bfs.BaseAmassService.OnStop()
	return nil
}

func (bfs *BruteForceService) Wordlist() []string {
	bfs.Lock()
	defer bfs.Unlock()

	return bfs.wordlist
}

func (bfs *BruteForceService) SetWordlist(words []string) {
	bfs.Lock()
	defer bfs.Unlock()

	bfs.wordlist = words
}

func (bfs *BruteForceService) DisableRecursive() {
	bfs.Lock()
	defer bfs.Unlock()

	bfs.recursive = false
}

func (bfs *BruteForceService) sendOut(req *AmassRequest) {
	bfs.SetActive(true)
	bfs.Output() <- req
	bfs.SetActive(true)
}

func (bfs *BruteForceService) processRequests() {
	t := time.NewTicker(5 * time.Second)
	defer t.Stop()
loop:
	for {
		select {
		case req := <-bfs.Input():
			bfs.SetActive(true)
			bfs.checkForNewSubdomain(req)
		case <-t.C:
			bfs.SetActive(false)
		case <-bfs.Quit():
			break loop
		}
	}
}

func (bfs *BruteForceService) checkForNewSubdomain(req *AmassRequest) {
	bfs.Lock()
	defer bfs.Unlock()

	// Check if we have seen the Domain already
	if _, found := bfs.subdomains[req.Domain]; !found {
		bfs.subdomains[req.Domain] = struct{}{}
		go bfs.performBruteForcing(req.Domain, req.Domain, bfs.wordlist)
	}
	// If the Name is empty or recursive brute forcing is off, we are done here
	if req.Name == "" || !bfs.recursive {
		return
	}

	labels := strings.Split(req.Name, ".")
	num := len(labels)
	// Is this large enough to consider further?
	if num < 3 {
		return
	}
	// Have we already seen this subdomain?
	sub := strings.Join(labels[1:], ".")
	if _, found := bfs.subdomains[sub]; found {
		return
	}
	bfs.subdomains[sub] = struct{}{}
	// It needs to have more labels than the root domain
	if num-1 <= len(strings.Split(req.Domain, ".")) {
		return
	}
	// Otherwise, run the brute forcing on the proper subdomain
	go bfs.performBruteForcing(sub, req.Domain, bfs.wordlist)
}

func (bfs *BruteForceService) performBruteForcing(subdomain, root string, words []string) {
	for _, word := range words {
		go bfs.sendOut(&AmassRequest{
			Name:   word + "." + subdomain,
			Domain: root,
			Tag:    BRUTE,
			Source: "Brute Forcing",
		})
	}
}
