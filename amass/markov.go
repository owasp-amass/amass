// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package amass

import (
	"math/rand"
	"strings"
	"sync"
	"time"

	"github.com/OWASP/Amass/amass/core"
	"github.com/OWASP/Amass/amass/utils"
	"github.com/miekg/dns"
)

const (
	markovMinForGen    = 100
	markovNumGenerated = 50000
	markovNumForUpdate = 10
)

var (
	markovBlacklistedLabels = []string{"www"}
)

type lenDist struct {
	Count float64
	Freq  float64
}

type markovModel struct {
	sync.Mutex
	NgramSize   int
	TotalLabels int
	Ngrams      map[string]map[rune]*lenDist
}

// MarkovService is the Service that perform DNS name guessing using markov chain models.
type MarkovService struct {
	core.BaseService

	updateLock sync.Mutex
	updated    bool
	generating bool
	ready      bool
	model      *markovModel
	subsLock   sync.Mutex
	subs       map[string]*core.DNSRequest
	inFilter   *utils.StringFilter
	outFilter  *utils.StringFilter
}

// NewMarkovService returns he object initialized, but not yet started.
func NewMarkovService(config *core.Config, bus *core.EventBus) *MarkovService {
	m := &MarkovService{
		subs:      make(map[string]*core.DNSRequest),
		inFilter:  utils.NewStringFilter(),
		outFilter: utils.NewStringFilter(),
		model: &markovModel{
			NgramSize: 3,
			Ngrams:    make(map[string]map[rune]*lenDist),
		},
	}

	m.BaseService = *core.NewBaseService(m, "Markov Model", config, bus)
	return m
}

// OnStart implements the Service interface.
func (m *MarkovService) OnStart() error {
	m.BaseService.OnStart()

	if m.Config().Alterations {
		m.Bus().Subscribe(core.NameResolvedTopic, m.SendDNSRequest)
		go m.processRequests()
	}
	return nil
}

// OnLowNumberOfNames implements the Service interface.
func (m *MarkovService) OnLowNumberOfNames() error {
	m.model.Lock()
	total := m.model.TotalLabels
	m.model.Unlock()

	if total < markovMinForGen || !m.isReady() || m.isGenerating() || !m.isUpdated() {
		return nil
	}

	m.markGenerating(true)
	m.updateFrequencies()
	m.generateNames()
	m.markReady(false)
	m.markGenerating(false)
	m.markUpdated(false)
	return nil
}

func (m *MarkovService) processRequests() {
	t := time.NewTicker(time.Minute)
	defer t.Stop()

	for {
		select {
		case <-m.PauseChan():
			<-m.ResumeChan()
		case <-m.Quit():
			return
		case <-t.C:
			if !m.isGenerating() {
				m.markReady(true)
			}
		case req := <-m.DNSRequestChan():
			go m.trainModel(req)
		case <-m.AddrRequestChan():
		case <-m.ASNRequestChan():
		case <-m.WhoisRequestChan():
		}
	}
}

func (m *MarkovService) correctRecordTypes(req *core.DNSRequest) bool {
	var ok bool
	for _, r := range req.Records {
		t := uint16(r.Type)

		if t == dns.TypeTXT || t == dns.TypeA || t == dns.TypeAAAA || t == dns.TypeCNAME {
			ok = true
			break
		}
	}
	return ok
}

func (m *MarkovService) trainModel(req *core.DNSRequest) {
	if !m.correctRecordTypes(req) ||
		m.inFilter.Duplicate(req.Name) ||
		!m.Config().IsDomainInScope(req.Name) {
		return
	}

	parts := strings.SplitN(req.Name, ".", 2)
	if len(parts) != 2 {
		return
	}
	// Add the domain/subdomain to the collection
	m.subsLock.Lock()
	if _, ok := m.subs[parts[1]]; !ok {
		m.subs[parts[1]] = &core.DNSRequest{
			Name:   parts[1],
			Domain: req.Domain,
		}
	}
	m.subsLock.Unlock()

	label := []rune(parts[0])
	// Do not allow blacklisted labels to pollute the model
	for _, bl := range markovBlacklistedLabels {
		if string(label) == bl {
			return
		}
	}

	// The same name should not leave the service
	m.outFilter.Duplicate(req.Name)

	label = append(label, '.')
	for i, char := range label {
		if i-m.model.NgramSize < 0 {
			var ngram string

			for j := 0; j < abs(i-m.model.NgramSize); j++ {
				ngram += "`"
			}
			ngram += string(label[0:i])
			m.updateModel(ngram, char)
		} else {
			m.updateModel(string(label[i-m.model.NgramSize:i]), char)
		}
	}
	m.SetActive()
	m.updateTotal()
}

func abs(val int) int {
	if val < 0 {
		return -val
	}
	return val
}

func (m *MarkovService) updateModel(ngram string, char rune) {
	m.model.Lock()
	defer m.model.Unlock()

	if _, ok := m.model.Ngrams[ngram]; !ok {
		m.model.Ngrams[ngram] = make(map[rune]*lenDist)
	}
	if _, ok := m.model.Ngrams[ngram][char]; !ok {
		m.model.Ngrams[ngram][char] = new(lenDist)
	}
	m.model.Ngrams[ngram][char].Count++
}

func (m *MarkovService) updateFrequencies() {
	m.model.Lock()
	defer m.model.Unlock()

	for ngram := range m.model.Ngrams {
		var total float64

		for char := range m.model.Ngrams[ngram] {
			total += m.model.Ngrams[ngram][char].Count
		}
		for _, ld := range m.model.Ngrams[ngram] {
			ld.Freq = ld.Count / total
		}
	}
}

func (m *MarkovService) generateNames() {
	num := markovNumGenerated

	m.subsLock.Lock()
	if l := len(m.subs); l > 0 {
		num /= l
	}
	m.subsLock.Unlock()

	for i := 0; i < num; i++ {
		label := m.generateLabel()

		m.subsLock.Lock()
		for _, sub := range m.subs {
			go m.sendGeneratedName(label+"."+sub.Name, sub.Domain)
		}
		m.subsLock.Unlock()
	}
}

func (m *MarkovService) generateLabel() string {
	var result string

	for i := 0; i < m.model.NgramSize; i++ {
		result += "`"
	}

	max := maxDNSLabelLen + m.model.NgramSize
	for i := 0; i < max; i++ {
		char := m.generateChar(result[i : i+m.model.NgramSize])

		if char == "." {
			break
		}
		result += char
	}
	if label := strings.Trim(result, "`"); len(label) > 0 && len(label) <= maxDNSLabelLen {
		return label
	}
	return m.generateLabel()
}

func (m *MarkovService) generateChar(ngram string) string {
	m.model.Lock()
	if chars, ok := m.model.Ngrams[ngram]; ok {
		r := rand.Float64()

		var accum float64
		for char, ld := range chars {
			accum += ld.Freq

			if r <= accum {
				m.model.Unlock()
				return string(char)
			}
		}
	}
	m.model.Unlock()

	chars := []rune(ngram)
	l := len(chars)
	if l-1 < 0 {
		return "."
	}
	return m.generateChar(string(chars[:l-1]))
}

func (m *MarkovService) sendGeneratedName(name, domain string) {
	name = strings.Trim(name, "-")
	if name == "" || m.outFilter.Duplicate(name) {
		return
	}

	re := m.Config().DomainRegex(domain)
	if re == nil || !re.MatchString(name) {
		return
	}

	m.SetActive()
	m.Bus().Publish(core.NewNameTopic, &core.DNSRequest{
		Name:   name,
		Domain: domain,
		Tag:    core.ALT,
		Source: m.String(),
	})
}

func (m *MarkovService) updateTotal() {
	m.model.Lock()
	defer m.model.Unlock()

	m.model.TotalLabels++
	if m.model.TotalLabels%markovNumForUpdate == 0 {
		go m.markUpdated(true)
	}
}

func (m *MarkovService) markUpdated(mark bool) {
	m.updateLock.Lock()
	defer m.updateLock.Unlock()

	m.updated = mark
}

func (m *MarkovService) isUpdated() bool {
	m.updateLock.Lock()
	defer m.updateLock.Unlock()

	return m.updated
}

func (m *MarkovService) markGenerating(mark bool) {
	m.updateLock.Lock()
	defer m.updateLock.Unlock()

	m.generating = mark
}

func (m *MarkovService) isGenerating() bool {
	m.updateLock.Lock()
	defer m.updateLock.Unlock()

	return m.generating
}

func (m *MarkovService) markReady(mark bool) {
	m.updateLock.Lock()
	defer m.updateLock.Unlock()

	m.ready = mark
}

func (m *MarkovService) isReady() bool {
	m.updateLock.Lock()
	defer m.updateLock.Unlock()

	return m.ready
}
