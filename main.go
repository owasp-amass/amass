// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"bufio"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"path"
	"regexp"
	"strings"
	"syscall"
	"time"

	"github.com/caffix/amass/amass"
	"github.com/caffix/recon"
)

var AsciiArt string = `

        .+++:.            :                             .+++.                   
      +W@@@@@@8        &+W@#               o8W8:      +W@@@@@@#.   oW@@@W#+     
     &@#+   .o@##.    .@@@o@W.o@@o       :@@#&W8o    .@#:  .:oW+  .@#+++&#&     
    +@&        &@&     #@8 +@W@&8@+     :@W.   +@8   +@:          .@8           
    8@          @@     8@o  8@8  WW    .@W      W@+  .@W.          o@#:         
    WW          &@o    &@:  o@+  o@+   #@.      8@o   +W@#+.        +W@8:       
    #@          :@W    &@+  &@+   @8  :@o       o@o     oW@@W+        oW@8      
    o@+          @@&   &@+  &@+   #@  &@.      .W@W       .+#@&         o@W.    
     WW         +@W@8. &@+  :&    o@+ #@      :@W&@&         &@:  ..     :@o    
     :@W:      o@# +Wo &@+        :W: +@W&o++o@W. &@&  8@#o+&@W.  #@:    o@+    
      :W@@WWWW@@8       +              :&W@@@@&    &W  .o#@@W&.   :W@WWW@@&     
        +o&&&&+.                                                    +oooo.                          

                                                  Subdomain Enumeration Tool
                                                       Created by Jeff Foley

`

func main() {
	var freq int64
	var count int
	var wordlist string
	var show, ip, whois, list, help bool

	flag.BoolVar(&help, "h", false, "Show the program usage message")
	flag.BoolVar(&ip, "ip", false, "Show the IP addresses for discovered names")
	flag.BoolVar(&show, "v", false, "Print the summary information")
	flag.BoolVar(&whois, "whois", false, "Include domains discoverd with reverse whois")
	flag.BoolVar(&list, "list", false, "List all domains to be used in the search")
	flag.Int64Var(&freq, "freq", 0, "Sets the number of max DNS queries per minute")
	flag.StringVar(&wordlist, "words", "", "Path to the wordlist file")
	flag.Parse()

	domains := flag.Args()
	if help || len(domains) == 0 {
		fmt.Println(AsciiArt)
		fmt.Printf("Usage: %s [options] domain extra_domain1 extra_domain2... (e.g. google.com)\n", path.Base(os.Args[0]))
		flag.PrintDefaults()
		return
	}

	if whois {
		// Add the domains discovered by whois
		domains = amass.UniqueAppend(domains, recon.ReverseWhois(flag.Arg(0))...)
	}

	if list {
		// Just show the domains and quit
		for _, d := range domains {
			fmt.Println(d)
		}
		return
	}

	stats := make(map[string]int)
	names := make(chan *amass.Subdomain, 100)
	// Collect all the names returned by the enumeration
	go func() {
		for {
			name := <-names

			count++
			stats[name.Tag]++
			if ip {
				fmt.Printf("\r%s\n", name.Name+","+name.Address)
			} else {
				fmt.Printf("\r%s\n", name.Name)
			}
		}
	}()

	// If the user interrupts the program, print the summary information
	sigs := make(chan os.Signal, 2)
	signal.Notify(sigs, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigs

		if show {
			printResults(count, stats)
		}

		os.Exit(0)
	}()

	config := amass.AmassConfig{
		Wordlist:  getWordlist(wordlist),
		Frequency: freqToDuration(freq),
	}
	// Fire off the driver function for enumeration
	enum := NewEnumerator(domains, names, config)
	go spinner(enum.Activity)
	enum.Start()

	if show {
		// Print the summary information
		printResults(count, stats)
	}
}

// PrintResults - Prints the summary information for the enumeration
func printResults(total int, stats map[string]int) {
	count := 1
	length := len(stats)

	fmt.Printf("\n%d names discovered - ", total)

	for k, v := range stats {
		if count < length {
			fmt.Printf("%s: %d, ", k, v)
		} else {
			fmt.Printf("%s: %d\n", k, v)
		}
		count++
	}
	return
}

func spinner(spin chan struct{}) {
	for {
		for _, r := range `-\|/` {
			<-spin
			fmt.Printf("\r%c", r)
			time.Sleep(75 * time.Millisecond)
		}
	}
}

const (
	defaultWordlistURL = "https://raw.githubusercontent.com/caffix/amass/master/wordlists/namelist.txt"
)

type Enumerator struct {
	// User provided domains to be enumerated
	Domains []string

	// The configuration desired for the amass package
	Config amass.AmassConfig

	// User provided channel to receive the name through
	Names chan *amass.Subdomain

	// The signal channel for showing activity during the enumeration
	Activity chan struct{}

	// Filter for not double-checking subdomain names
	nameFilter map[string]struct{}

	// Make sure resolved names are not provided to the user more than once
	resolved map[string]struct{}

	// These are proper subdomains discovered during the enumeration
	subdomains map[string]struct{}

	// The amass object used for this subdomain enumeration
	amass *amass.Amass

	// The done channel for web search engine subdomain name searches
	done chan int

	// The slice of Archivers used to search web sites
	archives []amass.Archiver
}

func NewEnumerator(domains []string, names chan *amass.Subdomain, config amass.AmassConfig) *Enumerator {
	e := &Enumerator{
		Domains:    domains,
		Config:     config,
		Names:      names,
		Activity:   make(chan struct{}),
		nameFilter: make(map[string]struct{}),
		resolved:   make(map[string]struct{}),
		subdomains: make(map[string]struct{}),
		amass:      amass.NewAmassWithConfig(config),
		done:       make(chan int, 20),
	}
	// Get all the archives to be used
	e.GetArchives()
	return e
}

// This is the driver function that performs a complete enumeration.
func (e *Enumerator) Start() {
	var activity bool
	var completed int

	totalSearches := amass.NUM_SEARCHES * len(e.Domains)
	// Start the simple searches to get us started
	e.StartSearches()
	// When this timer fires, the enumeration will end
	t := time.NewTimer(30 * time.Second)
	defer t.Stop()
	// Start brute forcing
	for _, d := range e.Domains {
		go e.amass.BruteForce(d, d)
	}
loop:
	for {
		select {
		case n := <-e.amass.Names: // New subdomains come in here
			e.NameAttempt(n)
			activity = true
		case r := <-e.amass.Resolved: // Names that have been resolved via dns lookup
			e.ResolvedName(r)
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

func (e *Enumerator) NameAttempt(name *amass.Subdomain) {
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

func (e *Enumerator) ResolvedName(name *amass.Subdomain) {
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

func (e *Enumerator) StartSearches() {
	searches := []amass.Searcher{
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

func (e *Enumerator) GetArchives() {
	e.archives = []amass.Archiver{
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

func (e *Enumerator) checkForRecursiveBruteForce(name *amass.Subdomain) {
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

func getWordlist(path string) []string {
	var list []string
	var wordlist io.Reader

	if path != "" {
		// Open the wordlist
		file, err := os.Open(path)
		if err != nil {
			fmt.Printf("Error opening the wordlist file: %v\n", err)
			return list
		}
		defer file.Close()
		wordlist = file
	} else {
		resp, err := http.Get(defaultWordlistURL)
		if err != nil {
			return list
		}
		defer resp.Body.Close()
		wordlist = resp.Body
	}

	scanner := bufio.NewScanner(wordlist)
	// Once we have used all the words, we are finished
	for scanner.Scan() {
		// Get the next word in the list
		word := scanner.Text()
		if word != "" {
			// Add the word to the list
			list = append(list, word)
		}
	}

	return list
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

func freqToDuration(freq int64) time.Duration {
	if freq > 0 {
		d := time.Duration(freq)

		if d < 60 {
			// we are dealing with number of seconds
			return (60 / d) * time.Second
		}

		// make it times per second
		d = d / 60

		m := 1000 / d
		if d < 1000 && m > 5 {
			return m * time.Millisecond
		}
	}
	// use the default rate
	return 5 * time.Millisecond
}
