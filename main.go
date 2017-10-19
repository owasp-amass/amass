// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path"
	"syscall"

	"github.com/caffix/amass/amass"
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
	var count int
	var wordlist string
	var config amass.AmassConfig
	var show, ip, whois, list, help bool
	names := make(chan *amass.Subdomain, 100)

	flag.BoolVar(&help, "h", false, "Show the program usage message")
	flag.BoolVar(&ip, "ip", false, "Show the IP addresses for discovered names")
	flag.BoolVar(&show, "v", false, "Print the summary information")
	flag.BoolVar(&whois, "whois", false, "Include domains discoverd with reverse whois")
	flag.BoolVar(&list, "list", false, "List all domains to be used in the search")
	flag.Int64Var(&config.Rate, "limit", 0, "Sets the number of max DNS queries per minute")
	flag.StringVar(&wordlist, "brute", "", "Path to the brute force wordlist file")
	flag.IntVar(&config.MaxSmart, "smart", 0, "Number of smart guessing attempts to make")
	flag.Parse()

	domains := flag.Args()
	if help || len(domains) == 0 {
		fmt.Println(AsciiArt)
		fmt.Printf("Usage: %s [options] domain extra_domain1 extra_domain2... (e.g. google.com)\n", path.Base(os.Args[0]))
		flag.PrintDefaults()
		return
	}

	if whois {
		domains = amass.UniqueAppend(domains, amass.ReverseWhois(flag.Arg(0))...)
	}

	if list {
		for _, d := range domains {
			fmt.Println(d)
		}
		return
	}

	var err error

	if wordlist != "" {
		config.Wordlist, err = os.Open(wordlist)

		if err != nil {
			fmt.Printf("Error opening the wordlist file: %v\n", err)
			return
		}

		defer config.Wordlist.Close()
	}

	stats := make(map[string]int)

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

	// if the user interrupts the program, check to print the summary information
	sigs := make(chan os.Signal, 2)
	signal.Notify(sigs, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigs

		if show {
			printResults(count, stats)
		}

		os.Exit(0)
	}()

	a := amass.NewAmassWithConfig(&config)
	if a == nil {
		return
	}

	// fire off the driver function for the enumeration process
	a.LookupSubdomainNames(domains, names)

	if show {
		printResults(count, stats)
	}
}

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
