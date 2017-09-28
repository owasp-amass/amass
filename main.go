// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"flag"
	"fmt"
	"os"
	"path"

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
	var show, ip, whois, list, help bool
	var names chan *amass.ValidSubdomain = make(chan *amass.ValidSubdomain, 20)

	flag.BoolVar(&help, "h", false, "Show the program usage message")
	flag.BoolVar(&ip, "ip", false, "Show the IP addresses for discovered names")
	flag.BoolVar(&show, "v", false, "Print the summary information")
	flag.BoolVar(&whois, "whois", false, "Include domains discoverd with reverse whois")
	flag.BoolVar(&list, "list", false, "List all domains to be used in the search")
	flag.StringVar(&wordlist, "brute", "", "Path to the brute force wordlist file")
	flag.Parse()

	if help {
		fmt.Println(AsciiArt)
		fmt.Printf("Usage: %s [options] domain extra_domain1 extra_domain2... (e.g. google.com)\n", path.Base(os.Args[0]))
		flag.PrintDefaults()
		return
	}

	domains := flag.Args()
	if domains == nil {
		fmt.Println(AsciiArt)
		fmt.Println("Use -h for usage information")
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

	var f *os.File
	var err error

	if wordlist != "" {
		f, err = os.Open(wordlist)

		if err != nil {
			fmt.Printf("Error opening the wordlist file: %v\n", err)
			return
		}

		defer f.Close()
	}

	go func() {
		for {
			name := <-names

			count++
			if ip {
				fmt.Println(name.Subdomain + "," + name.Address)
			} else {
				fmt.Println(name.Subdomain)
			}

		}
	}()

	amass.LookupSubdomainNames(domains, names, f)

	if show {
		fmt.Printf("\n%d legitimate hosts and subdomains discovered.\n", count)
	}
}
