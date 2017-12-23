// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path"
	"regexp"
	"strings"
	"sync"
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
	var config amass.AmassConfig
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

	var err error
	// Add the frequency to the configuration
	config.Frequency = freqToDuration(freq)
	// If provided, add the word list to the config
	if wordlist != "" {
		// Open the wordlist
		config.Wordlist, err = os.Open(wordlist)
		if err != nil {
			fmt.Printf("Error opening the wordlist file: %v\n", err)
			return
		}
		defer config.Wordlist.Close()
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
				fmt.Println(name.Name + "," + name.Address)
			} else {
				fmt.Println(name.Name)
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

	// Fire off the driver function for enumeration
	enumeration(domains, names, config)

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

// This is the driver function that performs a complete enumeration.
func enumeration(domains []string, names chan *amass.Subdomain, config amass.AmassConfig) {
	var activity bool
	var completed int
	var filterLock sync.Mutex

	done := make(chan int, 20)
	a := amass.NewAmassWithConfig(config)
	totalSearches := amass.NUM_SEARCHES * len(domains)
	// Start the simple searches to get us started
	startSearches(domains, a, done)
	// Get all the archives to be used
	archives := getArchives(a)
	// When this timer fires, the program will end
	t := time.NewTimer(30 * time.Second)
	defer t.Stop()
	// Filter for not double-checking subdomain names
	filterNames := make(map[string]struct{})
	// Filter for not double-checking IP addresses
	filterRDNS := make(map[string]struct{})
	filter := func(ip string) bool {
		filterLock.Lock()
		defer filterLock.Unlock()

		if _, ok := filterRDNS[ip]; ok {
			return true
		}
		filterRDNS[ip] = struct{}{}
		return false
	}
	// Make sure resolved names are not provided to the user more than once
	legitimate := make(map[string]struct{})
	// Start brute forcing
	go a.BruteForce(domains)
loop:
	for {
		select {
		case sd := <-a.Names: // New subdomains come in here
			sd.Name = trim252F(sd.Name)

			if sd.Name != "" {
				if _, ok := filterNames[sd.Name]; !ok {
					filterNames[sd.Name] = struct{}{}

					if sd.Domain == "" {
						sd.Domain = getDomainFromName(sd.Name, domains)
					}

					if sd.Domain != "" {
						// Is this new name valid?
						a.AddDNSRequest(sd)
					}
				}
			}
			activity = true
		case r := <-a.Resolved: // Names that have been resolved via dns lookup
			r.Name = trim252F(r.Name)

			if _, ok := legitimate[r.Name]; !ok {
				legitimate[r.Name] = struct{}{}

				a.AttemptSweep(r.Domain, r.Address, filter)
				// Give it to the user!
				names <- r
				// Check if this subdomain/host name has an archived web page
				for _, ar := range archives {
					ar.CheckHistory(r)
				}
				// Try altering the names to create new names
				a.ExecuteAlterations(r)
			}
			activity = true
		case <-done: // Searches that have finished
			completed++
		case <-t.C: // Periodic checks happen in here
			if !activity && completed == totalSearches && a.DNSRequestQueueEmpty() {
				// We are done if searches are finished, no dns queries left, and no activity
				break loop
			}
			// Otherwise, keep the process going
			t.Reset(5 * time.Second)
			activity = false
		}
	}
}

func startSearches(domains []string, a *amass.Amass, done chan int) {
	searches := []amass.Searcher{
		a.PGPSearch(),
		a.AskSearch(),
		a.CensysSearch(),
		a.CrtshSearch(),
		a.NetcraftSearch(),
		a.RobtexSearch(),
		a.BingSearch(),
		a.DogpileSearch(),
		a.YahooSearch(),
		a.GigablastSearch(),
		a.VirusTotalSearch(),
	}

	// Fire off the searches
	for _, d := range domains {
		for _, s := range searches {
			go s.Search(d, done)
		}
	}
}

func getArchives(a *amass.Amass) []amass.Archiver {
	archives := []amass.Archiver{
		a.WaybackMachineArchive(),
		a.LibraryCongressArchive(),
		a.ArchiveIsArchive(),
		a.ArchiveItArchive(),
		a.ArquivoArchive(),
		a.BayerischeArchive(),
		a.PermaArchive(),
		a.UKWebArchive(),
		a.UKGovArchive(),
	}
	return archives
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
