// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package amass

import (
	"time"
)

// BruteForce - Generates names from the provided wordlist + base
// domain names and sends them on the Names channel for DNS resolution
func (a *Amass) BruteForce(domain, root string) {
	t := time.NewTicker(50 * time.Millisecond)
	defer t.Stop()

	for _, word := range a.Wordlist {
		<-t.C

		a.Names <- &Subdomain{
			Name:   word + "." + domain,
			Domain: root,
			Tag:    BRUTE,
		}
	}
}
