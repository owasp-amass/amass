// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"bufio"
	"flag"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"os"
	"os/signal"
	"path"
	"syscall"
	"time"

	"github.com/caffix/amass/amass"
	"github.com/caffix/recon"
)

const (
	defaultWordlistURL = "https://raw.githubusercontent.com/caffix/amass/master/wordlists/namelist.txt"
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
                                           Coded By Jeff Foley (@jeff_foley)

`

type outputParams struct {
	Verbose  bool
	PrintIPs bool
	Names    chan *amass.Subdomain
	Output   chan struct{}
	Done     chan struct{}
}

func main() {
	var freq int64
	var wordlist string
	var verbose, ip, brute, whois, list, help bool

	flag.BoolVar(&help, "h", false, "Show the program usage message")
	flag.BoolVar(&ip, "ip", false, "Show the IP addresses for discovered names")
	flag.BoolVar(&brute, "brute", false, "Execute brute forcing after searches")
	flag.BoolVar(&verbose, "v", false, "Print the summary information")
	flag.BoolVar(&whois, "whois", false, "Include domains discoverd with reverse whois")
	flag.BoolVar(&list, "l", false, "List all domains to be used in an enumeration")
	flag.Int64Var(&freq, "freq", 0, "Sets the number of max DNS queries per minute")
	flag.StringVar(&wordlist, "w", "", "Path to a different wordlist file")
	flag.Parse()

	domains := flag.Args()
	if help || len(domains) == 0 {
		fmt.Println(AsciiArt)
		fmt.Printf("Usage: %s [options] domain domain2 domain3... (e.g. example.com)\n", path.Base(os.Args[0]))
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

	config := amass.AmassConfig{
		Wordlist:  getWordlist(wordlist),
		Frequency: freqToDuration(freq),
	}
	output := make(chan struct{})
	done := make(chan struct{})

	// Seed the pseudo-random number generator
	rand.Seed(time.Now().UTC().UnixNano())
	// Fire off the driver function for enumeration
	enum := amass.NewEnumerator(domains, brute, config)

	go manageOutput(&outputParams{
		Verbose:  verbose,
		PrintIPs: ip,
		Names:    enum.Names,
		Output:   output,
		Done:     done,
	})
	// Execute the signal handler
	go catchSignals(output, done)
	// Begin the enumeration process
	enum.Start()
	// Signal for output to finish
	output <- struct{}{}
	<-done
}

func manageOutput(params *outputParams) {
	var total int

	stats := make(map[string]int)
loop:
	for {
		select {
		case name := <-params.Names: // Collect all the names returned by the enumeration
			total++
			stats[name.Tag]++
			if params.PrintIPs {
				fmt.Printf("\r%s\n", name.Name+","+name.Address)
			} else {
				fmt.Printf("\r%s\n", name.Name)
			}
		case <-params.Output: // Prints the summary information for the enumeration
			if params.Verbose {
				printStats(total, stats)
			}
			break loop
		}
	}
	close(params.Done)
}

func printStats(total int, stats map[string]int) {
	fmt.Printf("\r\n%d names discovered - ", total)

	cur, length := 1, len(stats)
	for k, v := range stats {
		if cur == length {
			fmt.Printf("%s: %d\n", k, v)
		} else {
			fmt.Printf("%s: %d, ", k, v)
		}
		cur++
	}
}

// If the user interrupts the program, print the summary information
func catchSignals(output, done chan struct{}) {
	sigs := make(chan os.Signal, 2)
	signal.Notify(sigs, os.Interrupt, syscall.SIGTERM)

	// Wait for a signal
	<-sigs
	// Start final output operations
	output <- struct{}{}
	// Wait for the broadcast indicating completion
	<-done
	os.Exit(0)
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

func freqToDuration(freq int64) time.Duration {
	if freq > 0 {
		d := time.Duration(freq)

		if d < 60 {
			// We are dealing with number of seconds
			return (60 / d) * time.Second
		}
		// Make it times per second
		d = d / 60
		m := 1000 / d
		if d < 1000 && m > 1 {
			return m * time.Millisecond
		}
	}
	// Use the default rate
	return amass.DefaultConfig().Frequency
}
