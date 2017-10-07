// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package amass

import (
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"
)

type numFlipGuess struct {
	domainName          string
	domainNameLastLevel int
	firstNameLevel      int
	lock                sync.Mutex
	queue               []*Subdomain
	subdomains          chan *Subdomain
	re                  *regexp.Regexp
}

func (nf *numFlipGuess) flipNumsInName(cur, total int, name *Subdomain) {
	var i, index, counter int
	var before, after []rune

	// find the char index for cur
	for _, c := range name.Name {
		if unicode.IsNumber(c) {
			counter++
		}

		if counter == cur {
			break
		}
		index++
	}

	// grab chunks of string before and after
	for _, c := range name.Name {
		if i < index {
			before = append(before, c)
		}

		if i > index {
			after = append(after, c)
		}
		i++
	}

	// flip the number to make a new name
	for n := 0; n < 10; n++ {
		newName := &Subdomain{
			Name:   string(before) + strconv.Itoa(n) + string(after),
			Domain: nf.domainName,
			Tag:    FLIP,
		}

		if cur < total {
			go nf.flipNumsInName(cur+1, total, newName)
		}

		nf.subdomains <- newName
	}

	// send a version without the number in it
	withoutNum := string(before) + string(after)
	if nf.re.MatchString(withoutNum) {
		wn := &Subdomain{
			Name:   withoutNum,
			Domain: nf.domainName,
			Tag:    FLIP,
		}

		if cur < total {
			go nf.flipNumsInName(cur+1, total, wn)
		}

		nf.subdomains <- wn
	}
	return
}

func (nf *numFlipGuess) processName(name *Subdomain) {
	var counter int

	// check how many numbers are in the name
	for _, c := range name.Name {
		if unicode.IsNumber(c) {
			counter++
		}
	}

	// don't process a name with too many numbers either
	if counter == 0 || counter > 3 {
		return
	}

	nf.flipNumsInName(1, counter, name)
	return
}

func (nf *numFlipGuess) guessNames() {
	t := time.NewTicker(500 * time.Millisecond)
	defer t.Stop()

	for {
		select {
		case <-t.C:
			// check all the new names
			nf.lock.Lock()
			if len(nf.queue) > 0 {
				for _, n := range nf.queue {
					go nf.processName(n)
				}

				// empty the queue
				nf.queue = []*Subdomain{}
			}
			nf.lock.Unlock()
		}
	}
	return
}

func (nf *numFlipGuess) processDomainName(domain string) {
	nf.domainName = domain
	nf.firstNameLevel = len(strings.Split(domain, "."))
	nf.domainNameLastLevel = nf.firstNameLevel - 1
}

func (nf *numFlipGuess) AddName(name *Subdomain) {
	nf.lock.Lock()
	nf.queue = append(nf.queue, name)
	nf.lock.Unlock()
}

func (nf *numFlipGuess) Start() {
	return
}

func NumFlipGuess(domain string, subdomains chan *Subdomain) Guesser {
	nf := new(numFlipGuess)

	nf.re, _ = regexp.Compile(SUBRE + domain)
	nf.subdomains = subdomains
	nf.processDomainName(domain)
	go nf.guessNames()
	return nf
}
