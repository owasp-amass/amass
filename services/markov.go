// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package services

import (
	"context"
	"math/rand"
	"strings"
	"sync"

	"github.com/OWASP/Amass/config"
	"github.com/OWASP/Amass/eventbus"
	"github.com/OWASP/Amass/requests"
	"github.com/OWASP/Amass/resolvers"
)

const (
	markovMinForGen    = 100
	markovNumGenerated = 50000
	markovNumForUpdate = 10
)

var (
	markovBlacklistedLabels = []string{"www"}
)

// LenDist provides a counter and frequency across peer elements.
type LenDist struct {
	Count float64
	Freq  float64
}

// MarkovModel trains on DNS names resolved and provides data for generating name guesses.
type MarkovModel struct {
	sync.Mutex
	NgramSize   int
	TotalLabels int
	Ngrams      map[string]map[rune]*LenDist
	Subdomains  map[string]*requests.DNSRequest
}

// MarkovService is the Service that perform DNS name guessing using markov chain models.
type MarkovService struct {
	BaseService

	SourceType string
}

// NewMarkovModel returns a MarkovModel used for training on and generating DNS names.
func NewMarkovModel() *MarkovModel {
	return &MarkovModel{
		NgramSize:  3,
		Ngrams:     make(map[string]map[rune]*LenDist),
		Subdomains: make(map[string]*requests.DNSRequest),
	}
}

// NewMarkovService returns he object initialized, but not yet started.
func NewMarkovService(sys System) *MarkovService {
	m := &MarkovService{SourceType: requests.ALT}

	m.BaseService = *NewBaseService(m, "Markov Model", sys)
	return m
}

// Type implements the Service interface.
func (m *MarkovService) Type() string {
	return m.SourceType
}

// OnDNSRequest implements the Service interface.
func (m *MarkovService) OnDNSRequest(ctx context.Context, req *requests.DNSRequest) {
	bus := ctx.Value(requests.ContextEventBus).(*eventbus.EventBus)
	model := ctx.Value(requests.ContextMarkov).(*MarkovModel)
	if bus == nil || model == nil {
		return
	}

	model.Lock()
	defer model.Unlock()

	if model.TotalLabels < markovMinForGen {
		return
	}

	parts := strings.SplitN(req.Name, ".", 2)
	if len(parts) != 2 {
		return
	}
	// Add the domain/subdomain to the collection
	if _, ok := model.Subdomains[parts[1]]; !ok {
		model.Subdomains[parts[1]] = &requests.DNSRequest{
			Name:   parts[1],
			Domain: req.Domain,
		}
	}

	label := []rune(parts[0])
	// Do not allow blacklisted labels to pollute the model
	for _, bl := range markovBlacklistedLabels {
		if string(label) == bl {
			return
		}
	}

	label = append(label, '.')
	for i, char := range label {
		if i-model.NgramSize < 0 {
			var ngram string

			for j := 0; j < abs(i-model.NgramSize); j++ {
				ngram += "`"
			}
			ngram += string(label[0:i])
			m.updateModel(model, ngram, char)
		} else {
			m.updateModel(model, string(label[i-model.NgramSize:i]), char)
		}
	}

	model.TotalLabels++
	if model.TotalLabels&markovNumForUpdate == 0 {
		m.generateNames(ctx)
	}
}

func abs(val int) int {
	if val < 0 {
		return -val
	}
	return val
}

func (m *MarkovService) updateModel(model *MarkovModel, ngram string, char rune) {
	if _, ok := model.Ngrams[ngram]; !ok {
		model.Ngrams[ngram] = make(map[rune]*LenDist)
	}
	if _, ok := model.Ngrams[ngram][char]; !ok {
		model.Ngrams[ngram][char] = new(LenDist)
	}
	model.Ngrams[ngram][char].Count++
}

func (m *MarkovService) updateFrequencies(model *MarkovModel) {
	for ngram := range model.Ngrams {
		var total float64

		for char := range model.Ngrams[ngram] {
			total += model.Ngrams[ngram][char].Count
		}
		for _, ld := range model.Ngrams[ngram] {
			ld.Freq = ld.Count / total
		}
	}
}

func (m *MarkovService) generateNames(ctx context.Context) {
	model := ctx.Value(requests.ContextMarkov).(*MarkovModel)
	if model == nil {
		return
	}

	num := markovNumGenerated
	if l := len(model.Subdomains); l > 0 {
		num /= l
	}

	for i := 0; i < num; i++ {
		label := m.generateLabel(model)

		for _, sub := range model.Subdomains {
			go m.sendGeneratedName(ctx, label+"."+sub.Name, sub.Domain)
		}
	}
}

func (m *MarkovService) generateLabel(model *MarkovModel) string {
	var result string

	for i := 0; i < model.NgramSize; i++ {
		result += "`"
	}

	max := resolvers.MaxDNSLabelLen + model.NgramSize
	for i := 0; i < max; i++ {
		char := m.generateChar(model, result[i:i+model.NgramSize])

		if char == "." {
			break
		}
		result += char
	}
	if label := strings.Trim(result, "`"); len(label) > 0 && len(label) <= resolvers.MaxDNSLabelLen {
		return label
	}
	return m.generateLabel(model)
}

func (m *MarkovService) generateChar(model *MarkovModel, ngram string) string {
	if chars, ok := model.Ngrams[ngram]; ok {
		r := rand.Float64()

		var accum float64
		for char, ld := range chars {
			accum += ld.Freq

			if r <= accum {
				return string(char)
			}
		}
	}

	chars := []rune(ngram)
	l := len(chars)
	if l-1 < 0 {
		return "."
	}
	return m.generateChar(model, string(chars[:l-1]))
}

func (m *MarkovService) sendGeneratedName(ctx context.Context, name, domain string) {
	cfg := ctx.Value(requests.ContextConfig).(*config.Config)
	bus := ctx.Value(requests.ContextEventBus).(*eventbus.EventBus)
	if cfg == nil || bus == nil {
		return
	}

	name = strings.Trim(name, "-")
	if name == "" {
		return
	}

	re := cfg.DomainRegex(domain)
	if re == nil || !re.MatchString(name) {
		return
	}

	bus.Publish(requests.NewNameTopic, &requests.DNSRequest{
		Name:   name,
		Domain: domain,
		Tag:    m.Type(),
		Source: m.String(),
	})
}
