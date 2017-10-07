// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package amass

import (
	"bufio"
	"os"
	"time"
)

func BruteForce(domains []string, wordlist *os.File, subdomains chan *Subdomain, limit int64) {
	if wordlist == nil {
		return
	}

	// do not generate more than one name every 20th of a second
	l := limit / int64(len(domains))
	t := time.NewTicker(LimitToDuration(l))
	defer t.Stop()

	scanner := bufio.NewScanner(wordlist)

	for range t.C {
		if !scanner.Scan() {
			break
		}

		word := scanner.Text()
		if word == "" {
			continue
		}

		for _, d := range domains {
			name := word + "." + d

			subdomains <- &Subdomain{Name: name, Domain: d, Tag: BRUTE}
		}
	}
	return
}
