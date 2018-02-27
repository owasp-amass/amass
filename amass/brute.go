// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package amass

import (
	"sync"
	"time"
)

type BruteForce struct {
	sync.Mutex

	// Newly discovered words will show up on this channel
	MoreWords chan *Subdomain

	// Newly discovered subdomains show up on this channel
	MoreSubs chan *Subdomain

	// The channel where new attempts will be sent
	attempts chan *Subdomain

	// BruteForce internal goroutines use this for comms
	internal chan *Subdomain

	// Each of the subdomains and accociated root domains
	domains map[string]string

	// The wordlist being used to generate the attempts
	wordlist map[string]struct{}

	// Status that indicates when the attempts should be sent
	started bool
}

func NewBruteForce(names chan *Subdomain) *BruteForce {
	bf := &BruteForce{
		MoreWords: make(chan *Subdomain, 500),
		MoreSubs:  make(chan *Subdomain, 50),
		attempts:  names,
		internal:  make(chan *Subdomain, 50),
		domains:   make(map[string]string),
		wordlist:  make(map[string]struct{}),
	}
	go bf.processRequests()
	return bf
}

func (bf *BruteForce) AddWords(words []string) {
	for _, w := range words {
		bf.MoreWords <- &Subdomain{
			Name: w,
			Tag:  BRUTE,
		}
	}
}

func (bf *BruteForce) Start() {
	bf.Lock()
	defer bf.Unlock()

	bf.started = true
}

func (bf *BruteForce) hasStarted() bool {
	bf.Lock()
	defer bf.Unlock()

	return bf.started
}

// Goroutine that generates names from the provided wordlist + base
// domain names and sends them on the attempts channel for DNS resolution
func (bf *BruteForce) processRequests() {
	var queue []*Subdomain

	t := time.NewTicker(5 * time.Millisecond)
	defer t.Stop()

	for {
		select {
		case word := <-bf.MoreWords:
			if _, ok := bf.wordlist[word.Name]; !ok {
				for subdomain, root := range bf.domains {
					go bf.sendAttempt(&Subdomain{
						Name:   word.Name + "." + subdomain,
						Domain: root,
						Tag:    word.Tag,
					})
				}

				bf.wordlist[word.Name] = struct{}{}
			}
		case sub := <-bf.MoreSubs:
			if _, ok := bf.domains[sub.Name]; !ok {
				var words []string

				for w := range bf.wordlist {
					words = append(words, w)
				}
				go bf.wordlistForSubdomain(sub.Name, sub.Domain, words)
				bf.domains[sub.Name] = sub.Domain
			}
		case next := <-bf.internal:
			queue = append(queue, next)
		case <-t.C:
			if bf.hasStarted() && len(queue) > 0 {
				go bf.sendAttempt(queue[0])

				if len(queue) == 1 {
					queue = []*Subdomain{}
				} else {
					queue = queue[1:]
				}
			}
		}
	}
}

func (bf *BruteForce) wordlistForSubdomain(domain, root string, words []string) {
	for _, word := range words {
		bf.internal <- &Subdomain{
			Name:   word + "." + domain,
			Domain: root,
			Tag:    BRUTE,
		}
	}
}

func (bf *BruteForce) sendAttempt(a *Subdomain) {
	bf.attempts <- a
}
