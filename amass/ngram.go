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
	maxAttempts, curAttempts int
	totalNames               float64
	averageNameLength        float64
	levels                   map[int]*level
	freqGenerated            bool
	characters               map[rune]lenDist
	lock                     sync.Mutex
	queue                    []*Subdomain
	subdomains               chan *Subdomain
	once                     sync.Once
}

var (
	allChars  string = "abcdefghijklmnopqrstuvwxyz0123456789-."
	ngramSize int    = 2
	allNgrams []string
)

func initializeLevel() *level {
	l := new(level)

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

func (l *level) updateNumWords(length int) {
	if numchars, ok := l.NumWordsWithLen[length]; ok {
		numchars.Length++
		l.NumWordsWithLen[length] = numchars
	} else {
		l.NumWordsWithLen[length] = lenDist{Length: 1.0, Dist: 0.0}
	}
}

func (l *level) updateFirstChar(word string) {
	var first rune

	for _, c := range word {
		first = c
		break
	}

	if numfirst, ok := l.NumWordsWithFirstChar[first]; ok {
		numfirst.Length++
		l.NumWordsWithFirstChar[first] = numfirst
	} else {
		l.NumWordsWithFirstChar[first] = lenDist{Length: 1.0, Dist: 0.0}
	}
	return
}

func (l *level) updateCharTransitions(word string) {
	var prev rune

	for i, r := range word {
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
	return
}

func (l *level) updateNgrams(word string) {
	wlen := len(word)

	if wlen >= ngramSize {
		for i := 0; i+ngramSize <= wlen-1; i++ {
			ngram := word[i : i+ngramSize]

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
		l.updateNumWords(wlen)
		// increase count for num of words beginning with first
		l.updateFirstChar(w)
		// increase counters for character state transitions
		l.updateCharTransitions(w)
		// increase counters for all occuring ngrams
		l.updateNgrams(w)
	}
	return
}

func (l *level) smoothCalcWordLenFreq() {
	var totalWords float64

	// get total number of words for this level
	for _, ld := range l.NumWordsWithLen {
		totalWords += ld.Length
	}

	// perform smoothing
	for i := 1; i <= 63; i++ {
		if ld, ok := l.NumWordsWithLen[i]; ok {
			ld.Length++
			l.NumWordsWithLen[i] = ld
		} else {
			l.NumWordsWithLen[i] = lenDist{Length: 1.0, Dist: 0.0}
		}
	}

	sv := len(l.NumWordsWithLen)
	for k, ld := range l.NumWordsWithLen {
		ld.Dist = ld.Length / (totalWords + float64(sv))
		l.NumWordsWithLen[k] = ld
	}
	return
}

func (l *level) smoothCalcFirstCharFreq() {
	var totalWords float64

	// get total number of words for this level
	for _, ld := range l.NumWordsWithFirstChar {
		totalWords += ld.Length
	}

	// perform smoothing
	for _, c := range allChars {
		if c == '-' || c == '.' {
			// cannot start with special chars
			continue
		}

		if ld, ok := l.NumWordsWithFirstChar[c]; ok {
			ld.Length++
			l.NumWordsWithFirstChar[c] = ld
		} else {
			l.NumWordsWithFirstChar[c] = lenDist{Length: 1.0, Dist: 0.0}
		}
	}

	sv := len(l.NumWordsWithFirstChar)
	for k, ld := range l.NumWordsWithFirstChar {
		ld.Dist = ld.Length / (totalWords + float64(sv))
		l.NumWordsWithFirstChar[k] = ld
	}
	return
}

func (l *level) smoothCalcTransitionFreq() {
	// fill in zero frequency characters
	for _, c := range allChars {
		if _, ok := l.NumTimesCharFollowsChar[c]; !ok {
			l.NumTimesCharFollowsChar[c] = make(map[rune]lenDist)
		}
	}

	for _, tr := range l.NumTimesCharFollowsChar {
		var totalTrans float64

		// get total number of trans from this character
		for _, ld := range tr {
			totalTrans += ld.Length
		}

		// perform smoothing
		for _, c := range allChars {
			if ld, ok := tr[c]; ok {
				ld.Length++
				tr[c] = ld
			} else {
				tr[c] = lenDist{Length: 1.0, Dist: 0.0}
			}
		}

		sv := len(tr)
		// calculate the freq for trans from first char to second char
		for r, ld := range tr {
			ld.Dist = ld.Length / (totalTrans + float64(sv))
			tr[r] = ld
		}
	}
	return
}

func (l *level) smoothCalcNgramFreq() {
	for r, ngrams := range l.Ngrams {
		var totalNgrams float64

		// get total number of ngrams for this character
		for _, ld := range ngrams {
			totalNgrams += ld.Length
		}

		// perform smoothing
		for _, ngram := range allNgrams {
			var first rune

			for _, ngr := range ngram {
				first = ngr
				break
			}

			if r == first {
				if ld, ok := ngrams[ngram]; ok {
					ld.Length++
					ngrams[ngram] = ld
				} else {
					ngrams[ngram] = lenDist{Length: 1.0, Dist: 0.0}
				}
			}
		}

		sv := len(ngrams)
		// calculate the freq
		for n, ld := range ngrams {
			ld.Dist = ld.Length / (totalNgrams + float64(sv))
			ngrams[n] = ld
		}
	}
	return
}

func (ng *ngramGuess) smoothCalcFreq() {
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

	// calculate the frequencies for level-specific data
	for _, l := range ng.levels {
		// calculate the DNS name length distributions
		l.Dist = l.Length / ng.totalNames

		// calculate the dist of word-length for the level
		l.smoothCalcWordLenFreq()
		// calculate the dist of first chars occuring in words for the level
		l.smoothCalcFirstCharFreq()
		// calculate the dist of char transitions in words for the level
		l.smoothCalcTransitionFreq()
		// calculate the dist for ngrams starting with the same char
		l.smoothCalcNgramFreq()
	}
	return
}

func (ng *ngramGuess) getWordsInName() int {
	var accum float64

	r := rand.Float64()
	length := ng.firstNameLevel + 1

	for k, v := range ng.levels {
		if v.Length != 0 {
			accum += v.Dist
		}

		if k >= ng.firstNameLevel && r <= accum {
			length = k + 1
			break
		}
	}

	return length
}

func (l *level) getWordLength() int {
	var accum float64

	r := rand.Float64()
	length := 1

	for sz, ld := range l.NumWordsWithLen {
		accum += ld.Dist

		if r <= accum {
			length = sz
			break
		}
	}

	return length
}

func (l *level) getFirstCharacter() rune {
	var accum float64
	var char rune

	r := rand.Float64()

	for c, ld := range l.NumWordsWithFirstChar {
		accum += ld.Dist

		if r <= accum {
			char = c
			break
		}
	}

	return char
}

func (l *level) getTransition(cur rune) rune {
	var char rune
	var accum float64

	r := rand.Float64()

	// select the next character
	for c, ld := range l.NumTimesCharFollowsChar[cur] {
		accum += ld.Dist

		if r <= accum {
			char = c
			break
		}
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

func (l *level) getNgram(first rune) (string, rune) {
	var accum float64
	var ngram string
	var last rune

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
		l := ng.levels[i]

		rWordlen := l.getWordLength()
		cur := l.getFirstCharacter()

		first = append(first, cur)
		word := string(first)

		// we start this loop with a char in the word
		for x := 1; x < rWordlen; {
			cur = l.getTransition(cur)

			if x+ngramSize >= rWordlen {
				var next []rune
				// a ngram will not fit, add the char to the word
				next = append(next, cur)
				word = word + string(next)
				x++
			} else {
				ngram, last := l.getNgram(cur)

				cur = last
				word = word + ngram
				x = x + ngramSize
			}
		}
		// add the word to the name
		name = word + "." + name
	}
	return name + ng.domainName
}

func (ng *ngramGuess) guessNames() {
	re, _ := regexp.Compile(SUBRE + ng.domainName)

	for {
		ng.lock.Lock()
		if len(ng.queue) > 0 {
			// get all the new names
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
			ng.smoothCalcFreq()
			ng.freqGenerated = true
		}
		ng.lock.Unlock()

		if ng.freqGenerated {
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
			break
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
		go ng.guessNames()
	}

	ng.once.Do(body)
	return
}

func init() {
	rand.Seed(time.Now().UTC().UnixNano())
	allNgrams = []string{}

	for _, c1 := range allChars {
		for _, c2 := range allChars {
			allNgrams = append(allNgrams, string([]rune{c1, c2}))
		}
	}
	return
}

func NgramGuess(domain string, subdomains chan *Subdomain, max int) Guesser {
	ng := new(ngramGuess)

	ng.maxAttempts = max
	ng.levels = make(map[int]*level)
	ng.characters = make(map[rune]lenDist)
	ng.subdomains = subdomains
	ng.processDomainName(domain)
	return ng
}
