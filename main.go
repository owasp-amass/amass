// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"bufio"
	"flag"
	"fmt"
	"io/ioutil"
	"math/rand"
	"net"
	"os"
	"os/signal"
	"path"
	"strconv"
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
                                           Coded By Jeff Foley (@jeff_foley)

`

type outputParams struct {
	Verbose  bool
	Sources  bool
	PrintIPs bool
	FileOut  string
	Results  chan *amass.AmassRequest
	Finish   chan struct{}
	Done     chan struct{}
}

func main() {
	var freq int64
	var IPs []net.IP
	var ASNs, Ports []int
	var CIDRs []*net.IPNet
	var wordlist, outfile, domainsfile, asns, ips, cidrs, ports string
	var fwd, verbose, extra, addrs, brute, recursive, alts, whois, list, help bool

	flag.BoolVar(&help, "h", false, "Show the program usage message")
	flag.BoolVar(&addrs, "addrs", false, "Show the IP addresses for discovered names")
	flag.BoolVar(&brute, "brute", false, "Execute brute forcing after searches")
	flag.BoolVar(&recursive, "norecursive", true, "Turn off recursive brute forcing")
	flag.BoolVar(&alts, "noalts", true, "Disable generation of altered names")
	flag.BoolVar(&verbose, "v", false, "Print the summary information")
	flag.BoolVar(&extra, "vv", false, "Print the data source information")
	flag.BoolVar(&whois, "whois", false, "Include domains discoverd with reverse whois")
	flag.BoolVar(&list, "l", false, "List all domains to be used in an enumeration")
	flag.Int64Var(&freq, "freq", 0, "Sets the number of max DNS queries per minute")
	flag.StringVar(&wordlist, "w", "", "Path to a different wordlist file")
	flag.StringVar(&outfile, "o", "", "Path to the output file")
	flag.StringVar(&domainsfile, "df", "", "Path to a file providing root domain names")
	flag.StringVar(&asns, "asns", "", "ASNs to be probed for certificates")
	flag.StringVar(&ips, "ips", "", "IP addresses to be probed for certificates")
	flag.StringVar(&cidrs, "cidrs", "", "CIDRs to be probed for certificates")
	flag.StringVar(&ports, "p", "", "Ports to be checked for certificates")
	flag.Parse()

	if extra {
		verbose = true
	}
	if asns != "" {
		ASNs = parseInts(asns)
		fwd = true
	}
	if ips != "" {
		IPs = parseIPs(ips)
		fwd = true
	}
	if cidrs != "" {
		CIDRs = parseCIDRs(cidrs)
		fwd = true
	}
	// Get root domain names provided from the command-line
	domains := flag.Args()
	// Now, get domains provided by a file
	if domainsfile != "" {
		domains = amass.UniqueAppend(domains, getLinesFromFile(domainsfile)...)
	}
	if len(domains) > 0 {
		fwd = true
	}
	// Should the help output be provided?
	if help || !fwd {
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

	// Seed the default pseudo-random number generator
	rand.Seed(time.Now().UTC().UnixNano())

	finish := make(chan struct{})
	done := make(chan struct{})
	results := make(chan *amass.AmassRequest, 100)

	go manageOutput(&outputParams{
		Verbose:  verbose,
		Sources:  extra,
		PrintIPs: addrs,
		FileOut:  outfile,
		Results:  results,
		Finish:   finish,
		Done:     done,
	})
	// Execute the signal handler
	go catchSignals(finish, done)
	// Grab the words from an identified wordlist
	var words []string
	if wordlist != "" {
		words = getLinesFromFile(wordlist)
	}
	// Setup the amass configuration
	config := amass.CustomConfig(&amass.AmassConfig{
		Domains:      domains,
		ASNs:         ASNs,
		CIDRs:        CIDRs,
		IPs:          IPs,
		Ports:        Ports,
		Wordlist:     words,
		BruteForcing: brute,
		Recursive:    recursive,
		Alterations:  alts,
		Frequency:    freqToDuration(freq),
		Output:       results,
	})
	// Begin the enumeration process
	amass.StartAmass(config)
	// Signal for output to finish
	finish <- struct{}{}
	<-done
}

type asnData struct {
	Name      string
	Netblocks map[string]int
}

func manageOutput(params *outputParams) {
	var total int
	var allLines string

	tags := make(map[string]int)
	asns := make(map[int]*asnData)
loop:
	for {
		select {
		case result := <-params.Results: // Collect all the names returned by the enumeration
			total++
			updateData(result, tags, asns)

			var line string
			if params.Sources {
				line += fmt.Sprintf("%-14s", "["+result.Source+"] ")
			}
			if params.PrintIPs {
				line += fmt.Sprintf("%s\n", result.Name+","+result.Address)
			} else {
				line += fmt.Sprintf("%s\n", result.Name)
			}

			// Add line to the others and print it out
			allLines += line
			fmt.Print(line)
		case <-params.Finish:
			break loop
		}
	}
	// Check to print the summary information
	if params.Verbose {
		printSummary(total, tags, asns)
	}
	// Check to output the results to a file
	if params.FileOut != "" {
		ioutil.WriteFile(params.FileOut, []byte(allLines), 0644)
	}
	// Signal that output is complete
	close(params.Done)
}

func updateData(req *amass.AmassRequest, tags map[string]int, asns map[int]*asnData) {
	tags[req.Tag]++

	// Update the ASN information
	data, found := asns[req.ASN]
	if !found {
		asns[req.ASN] = &asnData{
			Name:      req.ISP,
			Netblocks: make(map[string]int),
		}
		data = asns[req.ASN]
	}
	// Increment how many IPs were in this netblock
	data.Netblocks[req.Netblock.String()]++
}

func printSummary(total int, tags map[string]int, asns map[int]*asnData) {
	if total == 0 {
		fmt.Println("No names were discovered")
		return
	}
	fmt.Printf("\n%d names discovered - ", total)

	// Print the stats using tag information
	num, length := 1, len(tags)
	for k, v := range tags {
		fmt.Printf("%s: %d", k, v)
		if num < length {
			fmt.Print(", ")
		}
		num++
	}
	fmt.Println("")

	// Print a line across the terminal
	for i := 0; i < 8; i++ {
		fmt.Print("----------")
	}
	fmt.Println("")

	// Print the ASN and netblock information
	for asn, data := range asns {
		fmt.Printf("ASN: %d - %s\n", asn, data.Name)

		for cidr, ips := range data.Netblocks {
			s := strconv.Itoa(ips)

			fmt.Printf("\t%-18s\t%-3s Subdomain Name(s)\n", cidr, s)
		}
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

func getLinesFromFile(path string) []string {
	var lines []string

	// Open the file
	file, err := os.Open(path)
	if err != nil {
		fmt.Printf("Error opening the file %s: %v\n", path, err)
		return lines
	}
	defer file.Close()
	// Get each line from the file
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		// Get the next line
		text := scanner.Text()
		if text != "" {
			lines = append(lines, strings.TrimSpace(text))
		}
	}
	return lines
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

func parseInts(s string) []int {
	var results []int

	nums := strings.Split(s, ",")

	for _, n := range nums {
		i, err := strconv.Atoi(n)
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
		results = append(results, i)
	}
	return results
}

func parseIPs(s string) []net.IP {
	var results []net.IP

	ips := strings.Split(s, ",")

	for _, ip := range ips {
		addr := net.ParseIP(ip)
		if addr == nil {
			fmt.Printf("%s is not a valid IP address\n", ip)
			os.Exit(1)
		}
		results = append(results, addr)
	}
	return results
}

func parseCIDRs(s string) []*net.IPNet {
	var results []*net.IPNet

	cidrs := strings.Split(s, ",")

	for _, cidr := range cidrs {
		_, ipnet, err := net.ParseCIDR(cidr)
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
		results = append(results, ipnet)
	}
	return results
}
