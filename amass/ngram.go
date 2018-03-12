// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package amass

import (
	"math/rand"
	"strings"
	"time"
	"unicode/utf8"
)

const (
	allChars   string = "abcdefghijklmnopqrstuvwxyz0123456789-"
	ngramSize  int    = 2
	maxGuesses int    = 50000
)

var (
	allNgrams []string
)

type lenDist struct {
	Length float64
	Dist   float64
}

func init() {
	allNgrams = []string{}

	for _, c1 := range allChars {
		for _, c2 := range allChars {
			allNgrams = append(allNgrams, string([]rune{c1, c2}))
		}
	}
}

type NgramService struct {
	BaseAmassService

	// The names successfully resolved by DNS
	goodNames map[string]struct{}

	// The last time that input was received
	lastInput time.Time

	// Subdomains names detected from input
	subdomains map[string]string

	startedGuessing         bool
	numGood, guesses        int
	totalNames              float64
	averageNameLength       float64
	numWordsWithLen         map[int]*lenDist
	numWordsWithFirstChar   map[rune]*lenDist
	numTimesCharFollowsChar map[rune]map[rune]*lenDist
	ngrams                  map[rune]map[string]*lenDist
	characters              map[rune]*lenDist
}

func NewNgramService(in, out chan *AmassRequest, config *AmassConfig) *NgramService {
	ns := &NgramService{
		goodNames:               make(map[string]struct{}),
		subdomains:              make(map[string]string),
		numWordsWithLen:         make(map[int]*lenDist),
		numWordsWithFirstChar:   make(map[rune]*lenDist),
		numTimesCharFollowsChar: make(map[rune]map[rune]*lenDist),
		ngrams:                  make(map[rune]map[string]*lenDist),
		characters:              make(map[rune]*lenDist),
	}

	ns.BaseAmassService = *NewBaseAmassService("Ngram Service", config, ns)

	ns.input = in
	ns.output = out
	return ns
}

func (ns *NgramService) OnStart() error {
	ns.BaseAmassService.OnStart()

	go ns.processRequests()

	if ns.Config().BruteForcing {
		ns.SetActive(true)
	}
	return nil
}

func (ns *NgramService) OnStop() error {
	ns.BaseAmassService.OnStop()
	ns.SetActive(false)
	return nil
}

func (ns *NgramService) sendOut(req *AmassRequest) {
	go func() {
		ns.Output() <- req
	}()
}

func (ns *NgramService) processRequests() {
	t := time.NewTicker(20 * time.Second)
	defer t.Stop()

	ns.SetLastInput(time.Now())
loop:
	for {
		select {
		case req := <-ns.Input():
			go ns.inspectResolvedName(req)
			ns.SetLastInput(time.Now())
		case <-t.C:
			go ns.checkToBegin()
		case <-ns.Quit():
			break loop
		}
	}
}

func (ns *NgramService) inspectResolvedName(req *AmassRequest) {
	ns.Lock()
	defer ns.Unlock()

	// Check if we have seen the Domain already
	if _, found := ns.subdomains[req.Domain]; !found {
		ns.subdomains[req.Domain] = req.Domain
	}
	// If the Name is empty, we are done here
	if req.Name == "" {
		return
	}
	// Add the leftmost label to the goodNames
	if _, found := ns.goodNames[req.Name]; !found {
		ns.goodNames[req.Name] = struct{}{}
	}
	// Do not continue if recursive brute forcing is off
	if !ns.Config().Recursive {
		return
	}
	// Obtain each label from the subdomain name
	labels := strings.Split(req.Name, ".")
	num := len(labels)
	// Is this large enough to consider further?
	if num < 3 {
		return
	}
	// Have we already seen this subdomain?
	sub := strings.Join(labels[1:], ".")
	if _, found := ns.subdomains[sub]; !found {
		// Add it to our collection
		ns.subdomains[sub] = req.Domain
	}
}

func (ns *NgramService) checkToBegin() {
	var start bool

	if !ns.Config().BruteForcing || ns.IsGuessing() {
		return
	}
	// Check if it's time to begin guessing
	diff := time.Now().Sub(ns.LastInput())
	if diff >= 30*time.Second && ns.NumGood() >= 100 {
		ns.SetActive(true)
		start = true
	} else if diff >= time.Minute {
		ns.SetActive(false)
	}

	if start && !ns.IsGuessing() {
		ns.MarkGuessing()
		ns.StartGuessing()
	}
}

func (ns *NgramService) StartGuessing() {
	ns.Train()

	numOfGuesses := maxGuesses / ns.NumSubdomains()

	t := time.NewTicker(50 * time.Millisecond)
	defer t.Stop()

	subs := ns.Subdomains()
	for ns.NumGuesses() <= numOfGuesses {
		// Do not go too fast
		<-t.C
		// Obtain a valid word
		word, err := ns.NextGuess()
		if err != nil {
			continue
		}
		// Send the guess to all known subdomains
		for _, sub := range subs {
			ns.sendOut(&AmassRequest{
				Name:   word + "." + sub.Name,
				Domain: sub.Domain,
				Tag:    ns.Tag(),
				Source: "Ngram Guesser",
			})
		}
	}
	ns.SetActive(false)
}

func (ns *NgramService) Train() {
	ns.Lock()
	defer ns.Unlock()

	for name := range ns.goodNames {
		labels := strings.Split(name, ".")
		hostname := labels[0]
		sample := float64(len(hostname))

		ns.totalNames++
		ns.averageNameLength -= ns.averageNameLength / ns.totalNames
		ns.averageNameLength += sample / ns.totalNames
		ns.updateCharacterFreq(hostname)
		ns.updateNameInfo(hostname)
	}
	// Update the frequency data
	ns.smoothCalcFreq()
}

func (ns *NgramService) NextGuess() (string, error) {
	wlen := ns.getWordLength()
	cur := ns.getFirstCharacter()
	guess := string([]rune{cur})
	// We start this loop with a char in the word
	for x := 1; x < wlen; {
		cur = ns.getTransition(cur)

		if x+ngramSize >= wlen {
			var next []rune
			// A ngram will not fit, add the char to the word
			next = append(next, cur)
			guess = guess + string(next)
			x++
		} else {
			ngram, last := ns.getNgram(cur)

			cur = last
			guess = guess + ngram
			x = x + ngramSize
		}
	}
	// Check that the last char is not the dash
	if last, size := utf8.DecodeLastRuneInString(guess); last == '-' {
		newLen := len(guess) - size

		if newLen > 1 {
			guess = guess[:newLen]
		}
	}
	ns.incGuesses()
	return guess, nil
}

func (ns *NgramService) NumSubdomains() int {
	ns.Lock()
	defer ns.Unlock()

	return len(ns.subdomains)
}

func (ns *NgramService) Subdomains() []*AmassRequest {
	var subs []*AmassRequest

	ns.Lock()
	defer ns.Unlock()

	for sub, domain := range ns.subdomains {
		subs = append(subs, &AmassRequest{
			Name:   sub,
			Domain: domain,
		})
	}
	return subs
}

func (ns *NgramService) NumGuesses() int {
	ns.Lock()
	defer ns.Unlock()

	return ns.guesses
}

func (ns *NgramService) incGuesses() {
	ns.Lock()
	defer ns.Unlock()

	ns.guesses++
}

func (ns *NgramService) AddGoodWords(words []string) {
	ns.Lock()
	defer ns.Unlock()

	for _, name := range words {
		if _, found := ns.goodNames[name]; !found {
			ns.goodNames[name] = struct{}{}
			ns.numGood++
		}
	}
}

func (ns *NgramService) GoodWords() []string {
	var words []string

	ns.Lock()
	defer ns.Unlock()

	for k := range ns.goodNames {
		words = append(words, k)
	}
	return words
}

func (ns *NgramService) NumGood() int {
	ns.Lock()
	defer ns.Unlock()

	return ns.numGood
}

func (ns *NgramService) LastInput() time.Time {
	ns.Lock()
	defer ns.Unlock()

	return ns.lastInput
}

func (ns *NgramService) SetLastInput(last time.Time) {
	ns.Lock()
	defer ns.Unlock()

	ns.lastInput = last
}

func (ns *NgramService) IsGuessing() bool {
	ns.Lock()
	defer ns.Unlock()

	return ns.startedGuessing
}

func (ns *NgramService) MarkGuessing() {
	ns.Lock()
	defer ns.Unlock()

	ns.startedGuessing = true
}

func (ns *NgramService) Tag() string {
	return "ngram"
}

func newLenDist() *lenDist {
	return &lenDist{
		Length: 1.0,
		Dist:   0.0,
	}
}

func (ns *NgramService) updateCharacterFreq(name string) {
	for _, c := range name {
		if ld, ok := ns.characters[c]; ok {
			ld.Length++
		} else {
			ns.characters[c] = newLenDist()
		}
	}
}

func (ns *NgramService) updateNumWords(length int) {
	if numchars, ok := ns.numWordsWithLen[length]; ok {
		numchars.Length++
	} else {
		ns.numWordsWithLen[length] = newLenDist()
	}
}

func (ns *NgramService) updateFirstChar(word string) {
	first, _ := utf8.DecodeRuneInString(word)
	if first == '-' {
		return
	}

	if numfirst, ok := ns.numWordsWithFirstChar[first]; ok {
		numfirst.Length++
	} else {
		ns.numWordsWithFirstChar[first] = newLenDist()
	}
}

func (ns *NgramService) updateCharTransitions(word string) {
	var prev rune

	for i, r := range word {
		if i == 0 {
			prev = r
			continue
		}

		if tr, ok := ns.numTimesCharFollowsChar[prev]; ok {
			if ld, ok := tr[r]; ok {
				ld.Length++
				tr[r] = ld
			} else {
				tr[r] = newLenDist()
			}
			ns.numTimesCharFollowsChar[prev] = tr
		} else {
			ns.numTimesCharFollowsChar[prev] = make(map[rune]*lenDist)
			ns.numTimesCharFollowsChar[prev][r] = newLenDist()
		}
		prev = r
	}
}

func (ns *NgramService) updateNgrams(word string) {
	wlen := len(word)

	if wlen >= ngramSize {
		for i := 0; i+ngramSize <= wlen-1; i++ {
			ngram := word[i : i+ngramSize]

			// Get first char as a rune
			f, _ := utf8.DecodeRuneInString(ngram)

			if n, ok := ns.ngrams[f]; ok {
				if ld, ok := n[ngram]; ok {
					ld.Length++
					n[ngram] = ld
				} else {
					n[ngram] = newLenDist()
				}
				ns.ngrams[f] = n
			} else {
				ns.ngrams[f] = make(map[string]*lenDist)
				ns.ngrams[f][ngram] = newLenDist()
			}
		}
	}
}

func (ns *NgramService) updateNameInfo(name string) {
	wlen := utf8.RuneCountInString(name)

	ns.totalNames++
	// Increase count for num of words having wlen chars
	ns.updateNumWords(wlen)
	// Increase count for num of words beginning with first
	ns.updateFirstChar(name)
	// Increase counters for character state transitions
	ns.updateCharTransitions(name)
	// Increase counters for all occuring ngrams
	ns.updateNgrams(name)
}

func (ns *NgramService) smoothCalcWordLenFreq() {
	var totalWords float64

	// Get total number of words for this level
	for _, ld := range ns.numWordsWithLen {
		totalWords += ld.Length
	}
	// Perform smoothing
	for i := 1; i <= 63; i++ {
		if ld, ok := ns.numWordsWithLen[i]; ok {
			ld.Length++
		} else {
			ns.numWordsWithLen[i] = newLenDist()
		}
	}

	sv := len(ns.numWordsWithLen)
	for k, ld := range ns.numWordsWithLen {
		ld.Dist = ld.Length / (totalWords + float64(sv))
		ns.numWordsWithLen[k] = ld
	}
}

func (ns *NgramService) smoothCalcFirstCharFreq() {
	var totalWords float64

	// Get total number of words for this level
	for _, ld := range ns.numWordsWithFirstChar {
		totalWords += ld.Length
	}
	// Perform smoothing
	for _, c := range allChars {
		if c == '-' {
			// Cannot start with special chars
			continue
		}

		if ld, ok := ns.numWordsWithFirstChar[c]; ok {
			ld.Length++
		} else {
			ns.numWordsWithFirstChar[c] = newLenDist()
		}
	}

	sv := len(ns.numWordsWithFirstChar)
	for _, ld := range ns.numWordsWithFirstChar {
		ld.Dist = ld.Length / (totalWords + float64(sv))
	}
}

func (ns *NgramService) smoothCalcTransitionFreq() {
	// Fill in zero frequency characters
	for _, c := range allChars {
		if _, ok := ns.numTimesCharFollowsChar[c]; !ok {
			ns.numTimesCharFollowsChar[c] = make(map[rune]*lenDist)
		}
	}

	for _, tr := range ns.numTimesCharFollowsChar {
		var totalTrans float64

		// Get total number of trans from this character
		for _, ld := range tr {
			totalTrans += ld.Length
		}
		// Perform smoothing
		for _, c := range allChars {
			if ld, ok := tr[c]; ok {
				ld.Length++
				tr[c] = ld
			} else {
				tr[c] = newLenDist()
			}
		}

		sv := len(tr)
		// Calculate the freq for trans from first char to second char
		for _, ld := range tr {
			ld.Dist = ld.Length / (totalTrans + float64(sv))
		}
	}
}

func (ns *NgramService) smoothCalcNgramFreq() {
	for r, ngrams := range ns.ngrams {
		var totalNgrams float64

		// Get total number of ngrams for this character
		for _, ld := range ngrams {
			totalNgrams += ld.Length
		}
		// Perform smoothing
		for _, ngram := range allNgrams {
			first, _ := utf8.DecodeRuneInString(ngram)

			if r == first {
				if ld, ok := ngrams[ngram]; ok {
					ld.Length++
				} else {
					ngrams[ngram] = newLenDist()
				}
			}
		}

		sv := len(ngrams)
		// Calculate the freq
		for _, ld := range ngrams {
			ld.Dist = ld.Length / (totalNgrams + float64(sv))
		}
	}
}

func (ns *NgramService) smoothCalcFreq() {
	var numchars float64

	// Get total number of characters
	for _, v := range ns.characters {
		numchars += v.Length
	}
	// Calculate the character distributions
	for _, v := range ns.characters {
		v.Dist = v.Length / numchars
	}
	// Calculate the frequencies
	// calculate the dist of word-length for the level
	ns.smoothCalcWordLenFreq()
	// calculate the dist of first chars occuring in words for the level
	ns.smoothCalcFirstCharFreq()
	// calculate the dist of char transitions in words for the level
	ns.smoothCalcTransitionFreq()
	// calculate the dist for ngrams starting with the same char
	ns.smoothCalcNgramFreq()
}

func (ns *NgramService) getWordLength() int {
	var accum float64

	r := rand.Float64()
	length := 1

	for sz, ld := range ns.numWordsWithLen {
		accum += ld.Dist

		if r <= accum {
			length = sz
			break
		}
	}
	return length
}

func (ns *NgramService) getFirstCharacter() rune {
	var accum float64
	var char rune

	r := rand.Float64()

	for c, ld := range ns.numWordsWithFirstChar {
		accum += ld.Dist

		if r <= accum {
			char = c
			break
		}
	}
	return char
}

func (ns *NgramService) getTransition(cur rune) rune {
	var char rune
	var accum float64

	r := rand.Float64()
	// Select the next character
	for c, ld := range ns.numTimesCharFollowsChar[cur] {
		accum += ld.Dist

		if cur == '-' && c == '-' {
			continue
		} else if r <= accum {
			char = c
			break
		}
	}
	return char
}

func (ns *NgramService) getRandomCharacter() rune {
	var char rune
	var counter int

	mlen := len(ns.characters)
	rchar := rand.Int() % mlen

	for c := range ns.characters {
		counter++

		if counter == rchar {
			char = c
			break
		}
	}
	return char
}

func (ns *NgramService) getNgram(first rune) (string, rune) {
	var accum float64
	var ngram string

	r := rand.Float64()
	// Get the correct ngram
	for ng, ld := range ns.ngrams[first] {
		accum += ld.Dist

		if r <= accum {
			ngram = ng
			break
		}
	}
	// Get the last rune
	last, _ := utf8.DecodeLastRuneInString(ngram)
	return ngram, last
}
