// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package amass

import (
	"math/rand"
	"regexp"
	"strings"
	"sync"
	"time"
)

type lenDist struct {
	Length float64
	Dist   float64
}

type level struct {
	Length                  float64
	Dist                    float64
	NumWordsWithLen         map[int]lenDist
	NumWordsWithFirstChar   map[rune]lenDist
	NumTimesCharFollowsChar map[rune]map[rune]lenDist
	Ngrams                  map[rune]map[string]lenDist
}

type ngramGuess struct {
	domainName               string
	domainNameLastLevel      int
	firstNameLevel           int
	ngramSize                int
	maxAttempts, curAttempts int
	totalNames               float64
	averageNameLength        float64
	levels                   map[int]level
	distGenerated            bool
	characters               map[rune]lenDist
	epsilon                  float64
	lock                     sync.Mutex
	queue                    []*Subdomain
	subdomains               chan *Subdomain
	limit                    int64
	once                     sync.Once
}

func initializeLevel() level {
	var l level

	l.NumWordsWithLen = make(map[int]lenDist)
	l.NumWordsWithFirstChar = make(map[rune]lenDist)
	l.NumTimesCharFollowsChar = make(map[rune]map[rune]lenDist)
	l.Ngrams = make(map[rune]map[string]lenDist)

	return l
}

func (ng *ngramGuess) updateCharacterFreq(name string) {
	for _, c := range name {
		if ld, ok := ng.characters[c]; ok {
			ld.Length++
			ng.characters[c] = ld
		} else {
			ng.characters[c] = lenDist{Length: 1.0, Dist: 0.0}
		}
	}
	return
}

func (ng *ngramGuess) updateLevelInfo(name string) {
	var words []string
	reverse := strings.Split(name, ".")
	maxi := len(reverse) - 1

	// put the words in the correct order
	for i := 0; i <= maxi; i++ {
		li := maxi - i

		words = append(words, reverse[li])
	}

	for i, w := range words {
		// check if this word is part of the domain name
		if i < ng.firstNameLevel {
			continue
		}

		wlen := len(w)

		l, ok := ng.levels[i]
		if !ok {
			ng.levels[i] = initializeLevel()
			l = ng.levels[i]
		}

		if i == maxi {
			l.Length++
		}

		// increase count for num of words having wlen chars
		if numchars, ok := l.NumWordsWithLen[wlen]; ok {
			numchars.Length++
			l.NumWordsWithLen[wlen] = numchars
		} else {
			l.NumWordsWithLen[wlen] = lenDist{Length: 1.0, Dist: 0.0}
		}

		var first rune
		for _, c := range w {
			first = c
			break
		}

		// increase count for num of words beginning with first
		if numfirst, ok := l.NumWordsWithFirstChar[first]; ok {
			numfirst.Length++
			l.NumWordsWithFirstChar[first] = numfirst
		} else {
			l.NumWordsWithFirstChar[first] = lenDist{Length: 1.0, Dist: 0.0}
		}

		// increase counters for character state transitions
		var prev rune
		for i, r := range w {
			if i != 0 {
				if tr, ok := l.NumTimesCharFollowsChar[prev]; ok {
					if ld, ok := tr[r]; ok {
						ld.Length++
						tr[r] = ld
					} else {
						tr[r] = lenDist{Length: 1, Dist: 0.0}
					}
					l.NumTimesCharFollowsChar[prev] = tr
				} else {
					l.NumTimesCharFollowsChar[prev] = make(map[rune]lenDist)
					l.NumTimesCharFollowsChar[prev][r] = lenDist{Length: 1, Dist: 0.0}
				}
			}
			prev = r
		}

		// increase counters for all occuring ngrams
		if wlen >= ng.ngramSize {
			for i := 0; i+ng.ngramSize <= wlen-1; i++ {
				ngram := w[i : i+ng.ngramSize]

				// get first char as rune
				var f rune
				for _, c := range ngram {
					f = c
					break
				}

				if n, ok := l.Ngrams[f]; ok {
					if ld, ok := n[ngram]; ok {
						ld.Length++
						n[ngram] = ld
					} else {
						n[ngram] = lenDist{Length: 1, Dist: 0.0}
					}
					l.Ngrams[f] = n
				} else {
					l.Ngrams[f] = make(map[string]lenDist)
					l.Ngrams[f][ngram] = lenDist{Length: 1, Dist: 0.0}
				}
			}
		}

		// update all changes
		ng.levels[i] = l
	}
	return
}

func (ng *ngramGuess) calculateDists() {
	var numchars float64

	// get total number of characters
	for _, v := range ng.characters {
		numchars += v.Length
	}

	// calculate the character distributions
	for k, v := range ng.characters {
		v.Dist = v.Length / numchars
		ng.characters[k] = v
	}

	// calculate the distributions for level-specific data
	for k, v := range ng.levels {
		// calculate the DNS name length distributions
		v.Dist = v.Length / ng.totalNames

		// get total number of words for this level
		var totalWords float64
		for _, ld := range v.NumWordsWithLen {
			totalWords += ld.Length
		}

		// calculate the dist of word-length for the level
		for k, ld := range v.NumWordsWithLen {
			ld.Dist = ld.Length / totalWords
			v.NumWordsWithLen[k] = ld
		}

		// calculate the dist of first chars occuring in words for the level
		for k, ld := range v.NumWordsWithFirstChar {
			ld.Dist = ld.Length / totalWords
			v.NumWordsWithFirstChar[k] = ld
		}

		// calculate the dist of char transitions in words for the level
		for r, tr := range v.NumTimesCharFollowsChar {
			var totalTrans float64

			// get total number of trans from this character
			for _, ld := range tr {
				totalTrans += ld.Length
			}

			// calculate the dist for trans from first char to second char
			for r, ld := range tr {
				ld.Dist = ld.Length / totalTrans
				tr[r] = ld
			}

			// update the transition data
			v.NumTimesCharFollowsChar[r] = tr
		}

		// calculate the dist for ngrams starting with the same char
		for r, ngrams := range v.Ngrams {
			var totalNgrams float64

			// get total number of ngrams for this character
			for _, ld := range ngrams {
				totalNgrams += ld.Length
			}

			// calculate the dist
			for n, ld := range ngrams {
				ld.Dist = ld.Length / totalNgrams
				ngrams[n] = ld
			}

			// update the ngram data
			v.Ngrams[r] = ngrams
		}

		// update the level
		ng.levels[k] = v
	}
	return
}

func (ng *ngramGuess) getWordsInName() int {
	var found bool
	var accum float64

	r := rand.Float64()
	length := ng.firstNameLevel
	numWords := len(ng.levels)

	for k, v := range ng.levels {
		if v.Length != 0 {
			accum += v.Dist - (ng.epsilon / float64(numWords))
		}

		if k >= ng.firstNameLevel && r <= accum {
			length = k + 1
			found = true
			break
		}
	}

	if !found {
		var super []int
		var others []int

		// create superset of legit name levels
		for i := ng.firstNameLevel; i <= 6; i++ {
			super = append(super, i)
		}

		// select a length not already seen
		for _, v := range super {
			if _, ok := ng.levels[v]; !ok {
				others = append(others, v)
			}
		}

		if len(others) > 1 {
			i := rand.Int() % (len(others) - 1)
			length = others[i]
		} else if len(others) == 1 {
			length = others[0]
		}
	}

	return length
}

func (ng *ngramGuess) getWordLength(lnum int) int {
	var found bool
	var accum float64

	l := ng.levels[lnum]
	r := rand.Float64()
	numLens := len(l.NumWordsWithLen)
	length := 1

	for sz, ld := range l.NumWordsWithLen {
		accum += ld.Dist - (ng.epsilon / float64(numLens))

		if r <= accum {
			length = sz
			found = true
			break
		}
	}

	if !found {
		var others []int

		// select a length not already seen
		for i := 1; i <= 63; i++ {
			if _, ok := l.NumWordsWithLen[i]; !ok {
				others = append(others, i)
			}
		}

		if len(others) > 1 {
			i := rand.Int() % (len(others) - 1)
			length = others[i]
		} else if len(others) == 1 {
			length = others[0]
		}
	}

	return length
}

func (ng *ngramGuess) getFirstCharacter(lnum int) rune {
	var found bool
	var accum float64
	var char rune

	l := ng.levels[lnum]
	r := rand.Float64()
	numFirsts := len(l.NumWordsWithFirstChar)

	for c, ld := range l.NumWordsWithFirstChar {
		accum += ld.Dist - (ng.epsilon / float64(numFirsts))

		if r <= accum {
			char = c
			found = true
			break
		}
	}

	if !found {
		var others []rune

		// select a character not already used first
		for f := range ng.characters {
			if _, ok := l.NumWordsWithFirstChar[f]; !ok {
				others = append(others, f)
			}
		}

		if len(others) > 1 {
			i := rand.Int() % (len(others) - 1)
			char = others[i]
			found = true
		} else if len(others) == 1 {
			char = others[0]
			found = true
		}
	}

	if !found {
		return ng.getRandomCharacter()
	}

	return char
}

func (ng *ngramGuess) getTransition(lnum int, cur rune) rune {
	var char rune
	var found bool
	var accum float64

	l := ng.levels[lnum]
	r := rand.Float64()
	numTrans := len(l.NumTimesCharFollowsChar)

	// select the next character
	for c, ld := range l.NumTimesCharFollowsChar[cur] {
		accum += ld.Dist - (ng.epsilon / float64(numTrans))

		if r <= accum {
			char = c
			found = true
			break
		}
	}

	if t, ok := l.NumTimesCharFollowsChar[cur]; ok && !found {
		var others []rune

		// select a character not already in this trans graph
		for c := range ng.characters {
			if _, ok := t[c]; !ok {
				others = append(others, c)
			}
		}

		if len(others) > 1 {
			i := rand.Int() % (len(others) - 1)
			char = others[i]
			found = true
		} else if len(others) == 1 {
			char = others[0]
			found = true
		}
	}

	if !found {
		// there was no transition from the prev char
		return ng.getRandomCharacter()
	}
	return char
}

func (ng *ngramGuess) getRandomCharacter() rune {
	var char rune
	var counter int

	mlen := len(ng.characters)
	rchar := rand.Int() % mlen

	for c := range ng.characters {
		counter++

		if counter == rchar {
			char = c
			break
		}
	}

	return char
}

func (ng *ngramGuess) getNgram(lnum int, first rune) (string, rune) {
	var accum float64
	var ngram string
	var last rune

	l := ng.levels[lnum]
	r := rand.Float64()

	// get the correct ngram
	for ng, ld := range l.Ngrams[first] {
		accum += ld.Dist

		if r <= accum {
			ngram = ng
			break
		}
	}

	// get the last rune
	for _, c := range ngram {
		last = c
	}

	return ngram, last
}

func (ng *ngramGuess) getName() string {
	var name string

	numWords := ng.getWordsInName()
	// start just past the domain name
	for i := ng.firstNameLevel; i < numWords; i++ {
		var first []rune

		rWordlen := ng.getWordLength(i)
		cur := ng.getFirstCharacter(i)

		first = append(first, cur)
		word := string(first)

		// we start this loop with a char in the word
		for x := 1; x < rWordlen; {
			cur = ng.getTransition(i, cur)

			if x+ng.ngramSize >= rWordlen {
				var next []rune
				// a ngram will not fit, add the char to the word
				next = append(next, cur)
				word = word + string(next)
				x++
			} else {
				ngram, last := ng.getNgram(i, cur)
				if ngram != "" {
					// found one!
					cur = last
					word = word + ngram
					x = x + ng.ngramSize
				} else {
					var next []rune
					// just add the rune to the word
					next = append(next, cur)
					word = word + string(next)
					x++
				}
			}

		}
		// add the word to the name
		name = word + "." + name
	}
	return name + ng.domainName
}

func (ng *ngramGuess) guessNames(l int64) {
	t := time.NewTicker(LimitToDuration(l))
	defer t.Stop()

	re, _ := regexp.Compile(SUBRE + ng.domainName)
loop:
	for {
		select {
		case <-t.C:
			// get all the new names
			ng.lock.Lock()
			if len(ng.queue) > 0 {
				for _, n := range ng.queue {
					sample := float64(len(n.Name))

					ng.totalNames++
					ng.averageNameLength -= ng.averageNameLength / ng.totalNames
					ng.averageNameLength += sample / ng.totalNames
					ng.updateCharacterFreq(n.Name)
					ng.updateLevelInfo(n.Name)
				}

				// empty the queue
				ng.queue = []*Subdomain{}

				// update the frequency data
				ng.calculateDists()
				ng.distGenerated = true
			}
			ng.lock.Unlock()

			if ng.distGenerated {
				name := ng.getName()

				if re.MatchString(name) {
					ng.curAttempts++
					ng.subdomains <- &Subdomain{
						Name:   name,
						Domain: ng.domainName,
						Tag:    SMART,
					}
				}
			}

			if ng.curAttempts >= ng.maxAttempts {
				break loop
			}
		}
	}
	return
}

func (ng *ngramGuess) processDomainName(domain string) {
	ng.domainName = domain
	ng.firstNameLevel = len(strings.Split(domain, "."))
	ng.domainNameLastLevel = ng.firstNameLevel - 1
	return
}

func (ng *ngramGuess) AddName(name *Subdomain) {
	ng.lock.Lock()
	ng.queue = append(ng.queue, name)
	ng.lock.Unlock()
	return
}

func (ng *ngramGuess) Start() {
	body := func() {
		go ng.guessNames(ng.limit)
	}

	ng.once.Do(body)
	return
}

func init() {
	rand.Seed(time.Now().UTC().UnixNano())
	return
}

func NgramGuess(domain string, subdomains chan *Subdomain, limit int64, max int) Guesser {
	ng := new(ngramGuess)

	ng.ngramSize = 2
	ng.epsilon = 0.001
	ng.maxAttempts = max
	ng.levels = make(map[int]level)
	ng.characters = make(map[rune]lenDist)
	ng.subdomains = subdomains
	ng.limit = limit
	ng.processDomainName(domain)

	return ng
}
