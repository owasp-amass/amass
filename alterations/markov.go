// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package alterations

import (
	"math/rand"
	"regexp"
	"strings"
	"sync"

	"github.com/OWASP/Amass/v3/stringset"
)

const (
	maxDNSNameLen  = 253
	maxDNSLabelLen = 63
	dnsChars       = "abcdefghijklmnopqrstuvwxyz0123456789-."
)

var (
	markovBlacklistedLabels = []string{"www"}
)

// LenDist provides a counter and frequency across peer elements.
type LenDist struct {
	Count float64
	Freq  float64
}

// MarkovModel trains on DNS names and provides data for generating name guesses.
type MarkovModel struct {
	sync.Mutex
	Ngrams         map[string]map[rune]*LenDist
	ngramSize      int
	totalTrainings int
	subdomains     map[string]struct{}
	re             *regexp.Regexp
}

// NewMarkovModel returns a MarkovModel used for training on and generating DNS names.
func NewMarkovModel(ngramSize int) *MarkovModel {
	m := &MarkovModel{
		Ngrams:     make(map[string]map[rune]*LenDist),
		ngramSize:  ngramSize,
		subdomains: make(map[string]struct{}),
	}

	m.re = regexp.MustCompile(`(([a-zA-Z0-9]{1}|[_a-zA-Z0-9]{1}[_a-zA-Z0-9-]{0,61}[a-zA-Z0-9]{1})[.]{1})+[a-zA-Z]{0,61}`)
	return m
}

// NgramSize returns the maximum size ngrams used by this markov model.
func (m *MarkovModel) NgramSize() int {
	return m.ngramSize
}

// TotalTrainings returns the number of times the model has been trained.
func (m *MarkovModel) TotalTrainings() int {
	m.Lock()
	defer m.Unlock()

	return m.totalTrainings
}

// Subdomains returns all the subdomain names in the collection maintained by the model.
func (m *MarkovModel) Subdomains() []string {
	m.Lock()
	defer m.Unlock()

	var results []string
	for k := range m.subdomains {
		results = append(results, k)
	}
	return results
}

// AddSubdomain accepts a FQDN and adds the largest proper subdomain to
// the collection maintained by the model.
func (m *MarkovModel) AddSubdomain(name string) {
	m.Lock()
	defer m.Unlock()

	_, subdomain := m.labelAndSubdomain(name)
	if subdomain == "" {
		return
	}
	// Add the subdomain to the collection
	if _, found := m.subdomains[subdomain]; !found {
		m.subdomains[subdomain] = struct{}{}
	}
}

// Train enriches the model adding the name provided to the existing data.
func (m *MarkovModel) Train(name string) {
	abs := func(val int) int {
		if val < 0 {
			return -val
		}
		return val
	}

	l, _ := m.labelAndSubdomain(name)
	if l == "" {
		return
	}

	// Do not allow blacklisted labels to pollute the model
	for _, bl := range markovBlacklistedLabels {
		if l == bl {
			return
		}
	}

	label := append([]rune(l), '.')
	for i, char := range label {
		if i-m.ngramSize < 0 {
			var ngram string

			for j := 0; j < abs(i-m.ngramSize); j++ {
				ngram += "`"
			}
			ngram += string(label[0:i])
			m.updateModel(ngram, char)
		} else {
			m.updateModel(string(label[i-m.ngramSize:i]), char)
		}
	}

	m.Lock()
	m.totalTrainings++
	m.Unlock()
	m.updateFrequencies()
}

func (m *MarkovModel) updateModel(ngram string, char rune) {
	m.Lock()
	defer m.Unlock()

	// Has this ngram been seen before?
	if _, ok := m.Ngrams[ngram]; !ok {
		m.Ngrams[ngram] = make(map[rune]*LenDist)
		// Smooth out the characters for this new ngram
		for _, c := range dnsChars {
			m.Ngrams[ngram][c] = &LenDist{Count: 1}
		}
	}
	// Just in case this char has not been seen before
	if _, ok := m.Ngrams[ngram][char]; !ok {
		m.Ngrams[ngram][char] = new(LenDist)
	}

	m.Ngrams[ngram][char].Count++
}

func (m *MarkovModel) updateFrequencies() {
	m.Lock()
	defer m.Unlock()

	for ngram := range m.Ngrams {
		var total float64

		for char := range m.Ngrams[ngram] {
			total += m.Ngrams[ngram][char].Count
		}
		for _, ld := range m.Ngrams[ngram] {
			ld.Freq = ld.Count / total
		}
	}
}

// GenerateNames returns 'num' guesses for each of the subdomains provided.
// If no subdomains are provided, all the subdomains previously added to the
// model will be used instead.
func (m *MarkovModel) GenerateNames(num int, subdomains ...string) []string {
	names := stringset.New()

	if num <= 0 {
		return names.Slice()
	}

	if len(subdomains) == 0 {
		subdomains = m.Subdomains()
	}

	if len(subdomains) == 0 {
		return names.Slice()
	}

	for i := 0; i < num; {
		label := m.GenerateLabel()
		if label == "" {
			continue
		}
		i++

		for _, sub := range m.Subdomains() {
			name := label + "." + sub

			if !m.re.MatchString(name) {
				continue
			}

			names.Insert(name)
		}
	}

	return names.Slice()
}

// GenerateLabel returns a valid DNS name label based on the trained model.
func (m *MarkovModel) GenerateLabel() string {
	// Continue until a good label has been generated
	for {
		var label string

		for i := 0; i < m.ngramSize; i++ {
			label += "`"
		}

		max := maxDNSLabelLen + m.ngramSize
		for i := 0; i < max; i++ {
			char := m.generateChar(label[i : i+m.ngramSize])

			if char == "." {
				break
			}
			label += char
		}

		label = strings.Trim(label, "`")
		label = strings.Trim(label, "-")
		if label == "" {
			continue
		}

		if len(label) > 0 && len(label) <= maxDNSLabelLen {
			return label
		}
	}

	return ""
}

func (m *MarkovModel) generateChar(ngram string) string {
	m.Lock()
	chars, ok := m.Ngrams[ngram]
	m.Unlock()

	if ok {
		r := rand.Float64()

		var accum float64
		for char, ld := range chars {
			accum += ld.Freq

			if r <= accum {
				return string(char)
			}
		}
	}

	r := []rune(ngram)
	l := len(r)
	if l-1 < 0 {
		return "."
	}

	return m.generateChar(string(r[:l-1]))
}

func (m *MarkovModel) labelAndSubdomain(name string) (string, string) {
	parts := strings.SplitN(name, ".", 2)
	if len(parts) != 2 {
		return "", ""
	}

	return parts[0], parts[1]
}
