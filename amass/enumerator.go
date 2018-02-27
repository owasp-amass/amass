// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package amass

import (
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/caffix/amass/amass/guess"
)

const (
	defaultNumberOfGuesses = 10000

	DataSourcePhase = 0
	BruteForcePhase = 1
)

type Enumerator struct {
	sync.Mutex

	// User provided domains to be enumerated
	Domains []string

	// Determines if brute forcing techniques will be employed
	Brute bool

	// The configuration desired for the amass package
	Config AmassConfig

	// User provided channel to receive the name through
	Names chan *Subdomain

	// The signal channel for showing activity during the enumeration
	Activity chan struct{}

	// Keeps track of which of the multiple enumeration phases we are currently in
	enumPhase int

	// Filter for not double-checking subdomain names
	nameFilter map[string]struct{}

	// Make sure resolved names are not provided to the user more than once
	resolved map[string]struct{}

	// These are proper subdomains discovered during the enumeration
	subdomains map[string]struct{}

	// The amass object used for this subdomain enumeration
	amass *Amass

	// The done channel for web search engine subdomain name searches
	done chan int

	// The slice of Archivers used to search web sites
	archives []Archiver

	// Will become trained to successfully resolved names and guess new names
	guesser guess.Guesser
}

func NewEnumerator(domains []string, names chan *Subdomain, config AmassConfig, brute bool) *Enumerator {
	e := &Enumerator{
		Domains:    domains,
		Brute:      brute,
		Config:     config,
		Names:      names,
		Activity:   make(chan struct{}),
		nameFilter: make(map[string]struct{}),
		resolved:   make(map[string]struct{}),
		subdomains: make(map[string]struct{}),
		amass:      NewAmassWithConfig(config),
		done:       make(chan int, 20),
		guesser:    guess.NewNgramGuesser(),
	}
	// Get all the archives to be used
	e.getArchives()
	return e
}

func (e *Enumerator) setPhase(phase int) {
	e.Lock()
	defer e.Unlock()

	e.enumPhase = phase
}

func (e *Enumerator) phase() int {
	e.Lock()
	defer e.Unlock()

	return e.enumPhase
}

// This is the driver function that performs a complete enumeration.
func (e *Enumerator) Start() {
	var activity bool
	var completed int

	totalSearches := NUM_SEARCHES * len(e.Domains)
	// Start the simple searches to get us started
	e.startSearches()
	// When this timer fires, the enumeration will end
	t := time.NewTimer(30 * time.Second)
	defer t.Stop()

	// Start brute forcing
	for _, d := range e.Domains {
		e.amass.BruteForcing.MoreSubs <- &Subdomain{Name: d, Domain: d}
	}

	good := make(chan *Subdomain, 500)
	bad := make(chan *Subdomain, 500)
	// Start the smart guessers
	go e.maintainGuessers(good, bad)
loop:
	for {
		select {
		case n := <-e.amass.Names: // New subdomains come in here
			e.nameAttempt(n)
			activity = true
		case r := <-e.amass.Resolved: // Names that have been resolved via dns lookup
			e.goodName(r)
			good <- r
			activity = true
		case f := <-e.amass.Failed: // Names that did not successfully resolve
			bad <- f
			activity = true
		case <-e.done: // Searches that have finished
			completed++
		case <-t.C: // Periodic checks happen in here
			// The phase is complete if searches are finished, no dns queries left, and no activity
			if !activity && completed == totalSearches && e.amass.DNSRequestQueueEmpty() {
				if e.phase() == DataSourcePhase {
					if e.Brute == false {
						break loop
					}

					e.setPhase(BruteForcePhase)
					e.amass.BruteForcing.AddWords(e.amass.Wordlist)
					e.amass.BruteForcing.Start()
				} else {
					break loop
				}
			}
			// Otherwise, keep the process going
			t.Reset(5 * time.Second)
			activity = false
		}
	}
}

func (e *Enumerator) nameAttempt(name *Subdomain) {
	name.Name = trim252F(name.Name)
	if name.Name == "" {
		return
	}

	// Have we seen this name already?
	if _, ok := e.nameFilter[name.Name]; ok {
		return
	}
	// Add it to the name filter
	e.nameFilter[name.Name] = struct{}{}

	if name.Domain == "" {
		name.Domain = getDomainFromName(name.Name, e.Domains)
		// Are we still without the root domain?
		if name.Domain == "" {
			return
		}
	}
	go e.amass.AddDNSRequest(name)
	// Show that we're continuing to work hard
	e.Activity <- struct{}{}
}

func (e *Enumerator) goodName(name *Subdomain) {
	name.Name = trim252F(name.Name)
	if _, ok := e.resolved[name.Name]; ok {
		return
	}
	e.resolved[name.Name] = struct{}{}

	e.amass.AttemptSweep(name.Domain, name.Address)
	// Give it to the user!
	e.Names <- name
	// Check if this subdomain/host name has an archived web page
	for _, ar := range e.archives {
		ar.CheckHistory(name)
	}
	// Try altering the names to create new names
	e.amass.ExecuteAlterations(name)
	// Check if we can perform a recursive brute forcing operation
	e.checkForRecursiveBruteForce(name)
}

func (e *Enumerator) maintainGuessers(good, bad chan *Subdomain) {
	goodWords := make(map[string]struct{})
	badWords := make(map[string]struct{})

	t := time.NewTicker(5 * time.Millisecond)
	defer t.Stop()

	for {
		select {
		case g := <-good:
			labels := strings.Split(g.Name, ".")

			if _, found := goodWords[labels[0]]; !found {
				e.guesser.AddGoodWords([]string{labels[0]})
				goodWords[labels[0]] = struct{}{}
			}

			// Train the ML algorithm again?
			if e.guesser.NumGuesses() > 0 && e.guesser.NumGood()%25 == 0 {
				var words []string

				for w := range goodWords {
					words = append(words, w)
				}

				e.guesser.Train()
			}
		case b := <-bad:
			labels := strings.Split(b.Name, ".")

			if _, found := badWords[labels[0]]; !found {
				e.guesser.AddBadWords([]string{labels[0]})
				badWords[labels[0]] = struct{}{}
			}
		case <-t.C:
			e.attemptGuess()
			if e.guesser.NumGuesses() > defaultNumberOfGuesses {
				t.Stop()
			}
		}
	}
}

func (e *Enumerator) attemptGuess() {
	num := e.guesser.NumGuesses()

	if e.phase() != BruteForcePhase || num > defaultNumberOfGuesses {
		return
	}
	// Check if the Guesser needs to be trained for the first time
	if num == 0 {
		e.guesser.Train()
	}
	// Make the next guess
	if next, err := e.guesser.NextGuess(); err == nil {
		go e.sendGuess(next)
	}
}

// sendGuess will be executed as a goroutine to prevent blocking
func (e *Enumerator) sendGuess(next string) {
	e.amass.BruteForcing.MoreWords <- &Subdomain{
		Name: next,
		Tag:  e.guesser.Tag(),
	}
}

func (e *Enumerator) startSearches() {
	searches := []Searcher{
		e.amass.AskSearch(),
		e.amass.BaiduSearch(),
		e.amass.CensysSearch(),
		e.amass.CrtshSearch(),
		//e.amass.GoogleSearch(),
		e.amass.NetcraftSearch(),
		e.amass.RobtexSearch(),
		e.amass.BingSearch(),
		e.amass.DogpileSearch(),
		e.amass.YahooSearch(),
		e.amass.VirusTotalSearch(),
		e.amass.DNSDumpsterSearch(),
	}

	// Fire off the searches
	for _, d := range e.Domains {
		for _, s := range searches {
			go s.Search(d, e.done)
		}
	}
}

func (e *Enumerator) getArchives() {
	e.archives = []Archiver{
		e.amass.WaybackMachineArchive(),
		e.amass.LibraryCongressArchive(),
		e.amass.ArchiveIsArchive(),
		e.amass.ArchiveItArchive(),
		e.amass.ArquivoArchive(),
		e.amass.BayerischeArchive(),
		e.amass.PermaArchive(),
		e.amass.UKWebArchive(),
		e.amass.UKGovArchive(),
	}
}

func (e *Enumerator) checkForRecursiveBruteForce(name *Subdomain) {
	labels := strings.Split(name.Name, ".")
	num := len(labels)

	// Is this large enough to consider further?
	if num < 3 {
		return
	}
	// Have we already seen this subdomain?
	sub := strings.Join(labels[1:], ".")
	if _, ok := e.subdomains[sub]; ok {
		return
	}
	e.subdomains[sub] = struct{}{}
	// It needs to have more labels than the root domain
	if num-1 <= len(strings.Split(name.Domain, ".")) {
		return
	}
	// Otherwise, run the brute forcing on the proper subdomain
	e.amass.BruteForcing.MoreSubs <- &Subdomain{Name: sub, Domain: name.Domain}
}

func getDomainFromName(name string, domains []string) string {
	var result string

	for _, d := range domains {
		if strings.HasSuffix(name, d) {
			result = d
			break
		}
	}
	return result
}

func trim252F(subdomain string) string {
	s := strings.ToLower(subdomain)

	re, err := regexp.Compile("^((252f)|(2f)|(3d))+")
	if err != nil {
		return s
	}

	i := re.FindStringIndex(s)
	if i != nil {
		return s[i[1]:]
	}
	return s
}
