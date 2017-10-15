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
	lock       sync.Mutex
	queue      []*Subdomain
	subdomains chan *Subdomain
	filter     map[string]bool
}

func (nf *numFlipGuess) flipNumsInName(name *Subdomain, first, second int) {
	var before, after []rune

	// grab chunks of string before and after the first number
	for i, c := range name.Name {
		if i < first {
			before = append(before, c)
		}

		if i > first {
			after = append(after, c)
		}
	}

	// flip the number to make a new name
	for n := 0; n < 10; n++ {
		sn := string(before) + strconv.Itoa(n) + string(after)
		sd := &Subdomain{
			Name:   sn,
			Domain: name.Domain,
			Tag:    FLIP,
		}

		if _, ok := nf.filter[sn]; !ok {
			nf.filter[sn] = true
			nf.subdomains <- sd

			if second != -1 {
				nf.flipNumsInName(sd, second, -1)
			}
		}
	}

	// send a version without the number in it
	withoutNum := string(before) + string(after)
	re, _ := regexp.Compile(SUBRE + name.Domain)

	if _, ok := nf.filter[withoutNum]; !ok && re.MatchString(withoutNum) {
		nf.filter[withoutNum] = true

		sd := &Subdomain{
			Name:   withoutNum,
			Domain: name.Domain,
			Tag:    FLIP,
		}

		nf.subdomains <- sd

		if second != -1 {
			nf.flipNumsInName(sd, second-1, -1)
		}
	}
	return
}

func (nf *numFlipGuess) processName(name *Subdomain) {
	var index int

	first := -1
	second := -1

	words := strings.Split(name.Name, ".")
	l := len(words) - len(strings.Split(name.Domain, "."))

	// we want the two rightmost numbers of the leftmost word
loop:
	for i, w := range words {
		if i >= l {
			// don't consider the domain name portion
			break
		}

		for i, c := range w {
			// if we are starting a new word and
			// have the numbers, we are done
			if i == 0 && first != -1 && second != -1 {
				break loop
			}

			if unicode.IsNumber(c) {
				if first == -1 {
					first = index
				} else if second == -1 {
					second = index
				} else {
					first = second
					second = index
				}
			}

			index++
		}
	}

	if first != -1 {
		nf.flipNumsInName(name, first, second)
	}
	return
}

func (nf *numFlipGuess) guessNames() {
	for {
		sd := nf.getNext()

		if sd != nil {
			nf.processName(sd)
		} else {
			time.Sleep(500 * time.Millisecond)
		}
	}
	return
}

func (nf *numFlipGuess) getNext() *Subdomain {
	var l int
	var sd *Subdomain

	nf.lock.Lock()
	defer nf.lock.Unlock()

	l = len(nf.queue)
	if l > 1 {
		sd = nf.queue[0]
		nf.queue = nf.queue[1:]
	} else if l == 1 {
		sd = nf.queue[0]
		nf.queue = []*Subdomain{}
	}

	return sd
}

func (nf *numFlipGuess) AddName(name *Subdomain) {
	nf.lock.Lock()
	nf.queue = append(nf.queue, name)
	nf.lock.Unlock()
}

func (nf *numFlipGuess) Start() {
	return
}

func NumFlipGuess(subdomains chan *Subdomain) Guesser {
	nf := new(numFlipGuess)

	nf.subdomains = subdomains
	nf.filter = make(map[string]bool)

	go nf.guessNames()
	return nf
}
