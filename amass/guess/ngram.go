// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package guess

import (
	"errors"
	"math/rand"
	"strings"
	"sync"
	"unicode/utf8"
)

type lenDist struct {
	Length float64
	Dist   float64
}

type NgramGuesser struct {
	sync.Mutex
	Trained                  bool
	numGood, numBad, guesses int
	good, bad                []string
	totalNames               float64
	averageNameLength        float64
	numWordsWithLen          map[int]*lenDist
	numWordsWithFirstChar    map[rune]*lenDist
	numTimesCharFollowsChar  map[rune]map[rune]*lenDist
	ngrams                   map[rune]map[string]*lenDist
	characters               map[rune]*lenDist
}

const (
	allChars  string = "abcdefghijklmnopqrstuvwxyz0123456789-"
	ngramSize int    = 2
)

var (
	allNgrams []string
)

func init() {
	allNgrams = []string{}

	for _, c1 := range allChars {
		for _, c2 := range allChars {
			allNgrams = append(allNgrams, string([]rune{c1, c2}))
		}
	}
}

func NewNgramGuesser() Guesser {
	return &NgramGuesser{}
}

func (ng *NgramGuesser) Train() {
	ng.Lock()
	defer ng.Unlock()

	// Reset the training data
	ng.totalNames = 0
	ng.averageNameLength = 0
	ng.numWordsWithLen = make(map[int]*lenDist)
	ng.numWordsWithFirstChar = make(map[rune]*lenDist)
	ng.numTimesCharFollowsChar = make(map[rune]map[rune]*lenDist)
	ng.ngrams = make(map[rune]map[string]*lenDist)
	ng.characters = make(map[rune]*lenDist)

	for _, name := range ng.good {
		labels := strings.Split(name, ".")
		hostname := labels[0]
		sample := float64(len(hostname))

		ng.totalNames++
		ng.averageNameLength -= ng.averageNameLength / ng.totalNames
		ng.averageNameLength += sample / ng.totalNames
		ng.updateCharacterFreq(hostname)
		ng.updateNameInfo(hostname)
	}
	// Update the frequency data
	ng.smoothCalcFreq()
	ng.Trained = true
}

func (ng *NgramGuesser) NextGuess() (string, error) {
	if !ng.Trained {
		return "", errors.New("This guesser has not been trained yet")
	}

	wlen := ng.getWordLength()
	cur := ng.getFirstCharacter()
	guess := string([]rune{cur})
	// We start this loop with a char in the word
	for x := 1; x < wlen; {
		cur = ng.getTransition(cur)

		if x+ngramSize >= wlen {
			var next []rune
			// A ngram will not fit, add the char to the word
			next = append(next, cur)
			guess = guess + string(next)
			x++
		} else {
			ngram, last := ng.getNgram(cur)

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
	ng.incGuesses()
	return guess, nil
}

func (ng *NgramGuesser) NumGuesses() int {
	ng.Lock()
	defer ng.Unlock()

	return ng.guesses
}

func (ng *NgramGuesser) incGuesses() {
	ng.Lock()
	defer ng.Unlock()

	ng.guesses++
}

func (ng *NgramGuesser) AddGoodWords(words []string) {
	ng.Lock()
	defer ng.Unlock()

	ng.good = append(ng.good, words...)
	ng.numGood += len(words)
}

func (ng *NgramGuesser) AddBadWords(words []string) {
	ng.Lock()
	defer ng.Unlock()

	ng.bad = append(ng.bad, words...)
	ng.numBad += len(words)
}

func (ng *NgramGuesser) GoodWords() []string {
	ng.Lock()
	defer ng.Unlock()

	return ng.good
}

func (ng *NgramGuesser) BadWords() []string {
	ng.Lock()
	defer ng.Unlock()

	return ng.bad
}

func (ng *NgramGuesser) NumGood() int {
	ng.Lock()
	defer ng.Unlock()

	return ng.numGood
}

func (ng *NgramGuesser) NumBad() int {
	ng.Lock()
	defer ng.Unlock()

	return ng.numBad
}

func (ng *NgramGuesser) Tag() string {
	return "ngram"
}

func newLenDist() *lenDist {
	return &lenDist{
		Length: 1.0,
		Dist:   0.0,
	}
}

func (ng *NgramGuesser) updateCharacterFreq(name string) {
	for _, c := range name {
		if ld, ok := ng.characters[c]; ok {
			ld.Length++
		} else {
			ng.characters[c] = newLenDist()
		}
	}
}

func (ng *NgramGuesser) updateNumWords(length int) {
	if numchars, ok := ng.numWordsWithLen[length]; ok {
		numchars.Length++
	} else {
		ng.numWordsWithLen[length] = newLenDist()
	}
}

func (ng *NgramGuesser) updateFirstChar(word string) {
	first, _ := utf8.DecodeRuneInString(word)
	if first == '-' {
		return
	}

	if numfirst, ok := ng.numWordsWithFirstChar[first]; ok {
		numfirst.Length++
	} else {
		ng.numWordsWithFirstChar[first] = newLenDist()
	}
}

func (ng *NgramGuesser) updateCharTransitions(word string) {
	var prev rune

	for i, r := range word {
		if i == 0 {
			prev = r
			continue
		}

		if tr, ok := ng.numTimesCharFollowsChar[prev]; ok {
			if ld, ok := tr[r]; ok {
				ld.Length++
				tr[r] = ld
			} else {
				tr[r] = newLenDist()
			}
			ng.numTimesCharFollowsChar[prev] = tr
		} else {
			ng.numTimesCharFollowsChar[prev] = make(map[rune]*lenDist)
			ng.numTimesCharFollowsChar[prev][r] = newLenDist()
		}

		prev = r
	}
}

func (ng *NgramGuesser) updateNgrams(word string) {
	wlen := len(word)

	if wlen >= ngramSize {
		for i := 0; i+ngramSize <= wlen-1; i++ {
			ngram := word[i : i+ngramSize]

			// Get first char as a rune
			f, _ := utf8.DecodeRuneInString(ngram)

			if n, ok := ng.ngrams[f]; ok {
				if ld, ok := n[ngram]; ok {
					ld.Length++
					n[ngram] = ld
				} else {
					n[ngram] = newLenDist()
				}
				ng.ngrams[f] = n
			} else {
				ng.ngrams[f] = make(map[string]*lenDist)
				ng.ngrams[f][ngram] = newLenDist()
			}
		}
	}
}

func (ng *NgramGuesser) updateNameInfo(name string) {
	wlen := utf8.RuneCountInString(name)

	ng.totalNames++
	// Increase count for num of words having wlen chars
	ng.updateNumWords(wlen)
	// Increase count for num of words beginning with first
	ng.updateFirstChar(name)
	// Increase counters for character state transitions
	ng.updateCharTransitions(name)
	// Increase counters for all occuring ngrams
	ng.updateNgrams(name)
}

func (ng *NgramGuesser) smoothCalcWordLenFreq() {
	var totalWords float64

	// Get total number of words for this level
	for _, ld := range ng.numWordsWithLen {
		totalWords += ld.Length
	}
	// Perform smoothing
	for i := 1; i <= 63; i++ {
		if ld, ok := ng.numWordsWithLen[i]; ok {
			ld.Length++
		} else {
			ng.numWordsWithLen[i] = newLenDist()
		}
	}

	sv := len(ng.numWordsWithLen)
	for k, ld := range ng.numWordsWithLen {
		ld.Dist = ld.Length / (totalWords + float64(sv))
		ng.numWordsWithLen[k] = ld
	}
}

func (ng *NgramGuesser) smoothCalcFirstCharFreq() {
	var totalWords float64

	// Get total number of words for this level
	for _, ld := range ng.numWordsWithFirstChar {
		totalWords += ld.Length
	}
	// Perform smoothing
	for _, c := range allChars {
		if c == '-' {
			// Cannot start with special chars
			continue
		}

		if ld, ok := ng.numWordsWithFirstChar[c]; ok {
			ld.Length++
		} else {
			ng.numWordsWithFirstChar[c] = newLenDist()
		}
	}

	sv := len(ng.numWordsWithFirstChar)
	for _, ld := range ng.numWordsWithFirstChar {
		ld.Dist = ld.Length / (totalWords + float64(sv))
	}
}

func (ng *NgramGuesser) smoothCalcTransitionFreq() {
	// Fill in zero frequency characters
	for _, c := range allChars {
		if _, ok := ng.numTimesCharFollowsChar[c]; !ok {
			ng.numTimesCharFollowsChar[c] = make(map[rune]*lenDist)
		}
	}

	for _, tr := range ng.numTimesCharFollowsChar {
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

func (ng *NgramGuesser) smoothCalcNgramFreq() {
	for r, ngrams := range ng.ngrams {
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

func (ng *NgramGuesser) smoothCalcFreq() {
	var numchars float64

	// Get total number of characters
	for _, v := range ng.characters {
		numchars += v.Length
	}
	// Calculate the character distributions
	for _, v := range ng.characters {
		v.Dist = v.Length / numchars
	}
	// Calculate the frequencies
	// calculate the dist of word-length for the level
	ng.smoothCalcWordLenFreq()
	// calculate the dist of first chars occuring in words for the level
	ng.smoothCalcFirstCharFreq()
	// calculate the dist of char transitions in words for the level
	ng.smoothCalcTransitionFreq()
	// calculate the dist for ngrams starting with the same char
	ng.smoothCalcNgramFreq()
}

func (ng *NgramGuesser) getWordLength() int {
	var accum float64

	r := rand.Float64()
	length := 1

	for sz, ld := range ng.numWordsWithLen {
		accum += ld.Dist

		if r <= accum {
			length = sz
			break
		}
	}
	return length
}

func (ng *NgramGuesser) getFirstCharacter() rune {
	var accum float64
	var char rune

	r := rand.Float64()

	for c, ld := range ng.numWordsWithFirstChar {
		accum += ld.Dist

		if r <= accum {
			char = c
			break
		}
	}
	return char
}

func (ng *NgramGuesser) getTransition(cur rune) rune {
	var char rune
	var accum float64

	r := rand.Float64()
	// Select the next character
	for c, ld := range ng.numTimesCharFollowsChar[cur] {
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

func (ng *NgramGuesser) getRandomCharacter() rune {
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

func (ng *NgramGuesser) getNgram(first rune) (string, rune) {
	var accum float64
	var ngram string

	r := rand.Float64()
	// Get the correct ngram
	for ng, ld := range ng.ngrams[first] {
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
