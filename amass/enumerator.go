// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package amass

import (
	"regexp"
	"strings"
	"time"

	"github.com/caffix/amass/amass/guess"
)

const (
	defaultNumberOfGuesses = 10000
)

type Enumerator struct {
	// User provided domains to be enumerated
	Domains []string

	// The configuration desired for the amass package
	Config AmassConfig

	// User provided channel to receive the name through
	Names chan *Subdomain

	// The signal channel for showing activity during the enumeration
	Activity chan struct{}

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
}

func NewEnumerator(domains []string, names chan *Subdomain, config AmassConfig) *Enumerator {
	e := &Enumerator{
		Domains:    domains,
		Config:     config,
		Names:      names,
		Activity:   make(chan struct{}),
		nameFilter: make(map[string]struct{}),
		resolved:   make(map[string]struct{}),
		subdomains: make(map[string]struct{}),
		amass:      NewAmassWithConfig(config),
		done:       make(chan int, 20),
	}
	// Get all the archives to be used
	e.getArchives()
	return e
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
		go e.amass.BruteForce(d, d)
	}

	good := make(chan *Subdomain, 500)
	bad := make(chan *Subdomain, 500)
	// Start the smart guessers
	go e.startGuessers(good, bad)
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
			if !activity && completed == totalSearches && e.amass.DNSRequestQueueEmpty() {
				// We are done if searches are finished, no dns queries left, and no activity
				break loop
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

func (e *Enumerator) startGuessers(good, bad chan *Subdomain) {
	type nameData struct {
		NumGood, NumBad int
		Good, Bad       []string
		Subs            map[string]struct{}
		Guess           guess.Guesser
	}

	t := time.NewTicker(50 * time.Millisecond)
	defer t.Stop()

	names := make(map[string]*nameData)
	for _, domain := range e.Domains {
		names[domain] = &nameData{
			Subs:  make(map[string]struct{}),
			Guess: guess.NewNgramGuesser(domain),
		}
	}

	var numGuesses int
	for {
		select {
		case g := <-good:
			data := names[g.Domain]

			data.NumGood++
			data.Good = append(data.Good, g.Name)

			labels := strings.Split(g.Name, ".")
			subdomain := strings.Join(labels[1:], ".")
			if _, ok := data.Subs[subdomain]; !ok {
				data.Subs[subdomain] = struct{}{}
			}

			if data.NumGood%100 == 0 {
				data.Guess.Train(data.Good, data.Bad)
			}
		case b := <-bad:
			names[b.Domain].NumBad++
			names[b.Domain].Bad = append(names[b.Domain].Bad, b.Name)
		case <-t.C:
			for domain, data := range names {
				if next, err := data.Guess.NextGuess(); err == nil {
					var subdomains []string

					for k := range data.Subs {
						subdomains = append(subdomains, k)
					}
					go e.processGuess(next, domain, subdomains)
				}
				numGuesses++
			}

			if numGuesses >= defaultNumberOfGuesses {
				t.Stop()
			}
		}
	}
}

func (e *Enumerator) processGuess(guess, domain string, subdomains []string) {
	for _, sub := range subdomains {
		e.amass.Names <- &Subdomain{
			Name:   guess + "." + sub,
			Domain: domain,
			Tag:    SMART,
		}
		/*fmt.Printf("SMART GUESS: %v\n", &Subdomain{
			Name:   guess + "." + sub,
			Domain: domain,
			Tag:    SMART,
		})*/
	}

}

func (e *Enumerator) startSearches() {
	searches := []Searcher{
		e.amass.AskSearch(),
		e.amass.CensysSearch(),
		e.amass.CrtshSearch(),
		e.amass.NetcraftSearch(),
		e.amass.RobtexSearch(),
		e.amass.BingSearch(),
		e.amass.DogpileSearch(),
		e.amass.YahooSearch(),
		e.amass.VirusTotalSearch(),
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
	go e.amass.BruteForce(sub, name.Domain)
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
