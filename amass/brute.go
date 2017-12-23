// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package amass

import (
	"bufio"
	"time"
)

// BruteForce - Generates names from the provided wordlist + base
// domain names and sends them on the Names channel for DNS resolution
func (a *Amass) BruteForce(domains []string) {
	// We cannot perform this operation without a wordlist
	if a.Wordlist == nil {
		return
	}
	// Frequency is the max speed DNS requests will be sent
	t := time.NewTicker(a.Frequency)
	defer t.Stop()

	scanner := bufio.NewScanner(a.Wordlist)
	for range t.C {
		// Once we have used all the words, we are finished
		if !scanner.Scan() {
			break
		}
		// Get the next word in the list
		word := scanner.Text()
		if word == "" {
			continue
		}
		// Generate the next name for each base domain provided
		for _, d := range domains {
			name := word + "." + d

			a.Names <- &Subdomain{Name: name, Domain: d, Tag: BRUTE}
		}
	}
}
