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
	enum := amass.NewEnumerator(domains, names, config)
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

	fmt.Printf("\r\n%d names discovered - ", total)

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
