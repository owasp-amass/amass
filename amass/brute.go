// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package amass

import (
	"bufio"
	"os"
	"time"
)

func BruteForce(domains []string, wordlist *os.File, subdomains chan string) {
	if wordlist == nil {
		return
	}

	scanner := bufio.NewScanner(wordlist)

	for scanner.Scan() {
		word := scanner.Text()
		if word == "" {
			continue
		}

		for _, d := range domains {
			name := word + "." + d

			// don't allow brute forcing to overwhelm the channel
			if len(subdomains) == cap(subdomains) {
				time.Sleep(2 * time.Second)
			}

			subdomains <- name
		}
	}
	return
}
