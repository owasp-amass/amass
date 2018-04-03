// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"bufio"
	"bytes"
	"flag"
	"fmt"
	"io/ioutil"
	"math/rand"
	"net"
	"os"
	"os/signal"
	"path"
	//"runtime/pprof"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/caffix/amass/amass"
	"github.com/caffix/recon"
	"github.com/fatih/color"
)

type outputParams struct {
	Verbose  bool
	Sources  bool
	PrintIPs bool
	FileOut  string
	Results  chan *amass.AmassRequest
	Finish   chan struct{}
	Done     chan struct{}
}

// Types that implement the flag.Value interface for parsing
type parseIPs []net.IP
type parseCIDRs []*net.IPNet
type parseInts []int

var (
	banner string = `

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

`
	// Colors used to ease the reading of program output
	y      = color.New(color.FgHiYellow)
	g      = color.New(color.FgHiGreen)
	r      = color.New(color.FgHiRed)
	b      = color.New(color.FgHiBlue)
	yellow = color.New(color.FgHiYellow).SprintFunc()
	green  = color.New(color.FgHiGreen).SprintFunc()
	blue   = color.New(color.FgHiBlue).SprintFunc()
	// Command-line switches and provided parameters
	help        = flag.Bool("h", false, "Show the program usage message")
	version     = flag.Bool("version", false, "Print the version number of this amass binary")
	ips         = flag.Bool("ip", false, "Show the IP addresses for discovered names")
	brute       = flag.Bool("brute", false, "Execute brute forcing after searches")
	recursive   = flag.Bool("norecursive", true, "Turn off recursive brute forcing")
	alts        = flag.Bool("noalts", true, "Disable generation of altered names")
	verbose     = flag.Bool("v", false, "Print the summary information")
	extra       = flag.Bool("vv", false, "Print the data source information")
	whois       = flag.Bool("whois", false, "Include domains discoverd with reverse whois")
	list        = flag.Bool("l", false, "List all domains to be used in an enumeration")
	freq        = flag.Int64("freq", 0, "Sets the number of max DNS queries per minute")
	wordlist    = flag.String("w", "", "Path to a different wordlist file")
	outfile     = flag.String("o", "", "Path to the output file")
	domainsfile = flag.String("df", "", "Path to a file providing root domain names")
	proxy       = flag.String("proxy", "", "The URL used to reach the proxy")
)

func main() {
	var addrs parseIPs
	var cidrs parseCIDRs
	var asns, ports parseInts

	buf := new(bytes.Buffer)
	flag.CommandLine.SetOutput(buf)

	flag.Var(&addrs, "addr", "IPs and ranges to be probed for certificates")
	flag.Var(&cidrs, "net", "CIDRs to be probed for certificates")
	flag.Var(&asns, "asn", "ASNs to be probed for certificates")
	flag.Var(&ports, "p", "Ports to be checked for certificates")
	flag.Parse()

	// Should the help output be provided?
	if *help {
		printBanner()
		g.Printf("Usage: %s [options] domain domain2 domain3... (e.g. example.com)\n", path.Base(os.Args[0]))
		flag.PrintDefaults()
		g.Println(buf.String())
		return
	}
	if *version {
		fmt.Printf("version %s\n", amass.Version)
		return
	}
	if *extra {
		*verbose = true
	}
	// Get root domain names provided from the command-line
	domains := flag.Args()
	// Now, get domains provided by a file
	if *domainsfile != "" {
		domains = amass.UniqueAppend(domains, getLinesFromFile(*domainsfile)...)
	}
	if *whois {
		// Add the domains discovered by whois
		domains = amass.UniqueAppend(domains, recon.ReverseWhois(flag.Arg(0))...)
	}
	if *list {
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
		Verbose:  *verbose,
		Sources:  *extra,
		PrintIPs: *ips,
		FileOut:  *outfile,
		Results:  results,
		Finish:   finish,
		Done:     done,
	})
	// Execute the signal handler
	go catchSignals(finish, done)
	// Grab the words from an identified wordlist
	var words []string
	if *wordlist != "" {
		words = getLinesFromFile(*wordlist)
	}
	// Setup the amass configuration
	config := amass.CustomConfig(&amass.AmassConfig{
		IPs:          addrs,
		ASNs:         asns,
		CIDRs:        cidrs,
		Ports:        ports,
		Wordlist:     words,
		BruteForcing: *brute,
		Recursive:    *recursive,
		Alterations:  *alts,
		Frequency:    freqToDuration(*freq),
		Output:       results,
	})
	config.AddDomains(domains)
	// If no domains were provided, allow amass to discover them
	if len(domains) == 0 {
		config.AdditionalDomains = true
	}
	// Check if a proxy connection should be setup
	if *proxy != "" {
		err := config.SetupProxyConnection(*proxy)
		if err != nil {
			r.Println("The proxy address provided failed to make a connection")
			return
		}
	}
	//profFile, _ := os.Create("amass_debug.prof")
	//pprof.StartCPUProfile(profFile)
	//defer pprof.StopCPUProfile()
	err := amass.StartEnumeration(config)
	if err != nil {
		r.Println(err)
	}
	// Signal for output to finish
	finish <- struct{}{}
	<-done
}

func printBanner() {
	rightmost := 76
	desc := "In-Depth Subdomain Enumeration"
	author := "Coded By " + amass.Author

	pad := func(num int) {
		for i := 0; i < num; i++ {
			fmt.Print(" ")
		}
	}
	r.Println(banner)
	pad(rightmost - len(amass.Version))
	y.Println(amass.Version)
	pad(rightmost - len(desc))
	y.Println(desc)
	pad(rightmost - len(author))
	y.Printf("%s\n\n\n", author)
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

			var source, comma, ip string
			if params.Sources {
				source = fmt.Sprintf("%-14s", "["+result.Source+"] ")
			}
			if params.PrintIPs {
				comma = ","
				ip = result.Address
			}

			// Add line to the others and print it out
			allLines += fmt.Sprintf("%s%s%s%s\n", source, result.Name, comma, ip)
			fmt.Fprintf(color.Output, "%s%s%s%s\n",
				blue(source), green(result.Name), green(comma), yellow(ip))
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
		r.Println("No names were discovered")
		return
	}
	pad := func(num int, chr string) {
		for i := 0; i < num; i++ {
			b.Print(chr)
		}
	}

	fmt.Println()
	// Print the header information
	b.Print("Amass " + amass.Version)
	num := 80 - (len(amass.Version) + len(amass.Author) + 6)
	pad(num, " ")
	b.Printf("%s\n", amass.Author)
	pad(8, "----------")
	fmt.Fprintf(color.Output, "\n%s%s", yellow(strconv.Itoa(total)), green(" names discovered - "))
	// Print the stats using tag information
	num, length := 1, len(tags)
	for k, v := range tags {
		fmt.Fprintf(color.Output, "%s: %s", green(k), yellow(strconv.Itoa(v)))
		if num < length {
			g.Print(", ")
		}
		num++
	}
	fmt.Println()
	// Another line gets printed
	pad(8, "----------")
	fmt.Println()
	// Print the ASN and netblock information
	for asn, data := range asns {
		fmt.Fprintf(color.Output, "%s%s %s %s\n",
			blue("ASN: "), yellow(strconv.Itoa(asn)), green("-"), green(data.Name))

		for cidr, ips := range data.Netblocks {
			countstr := fmt.Sprintf("\t%-4s", strconv.Itoa(ips))
			cidrstr := fmt.Sprintf("\t%-18s", cidr)

			fmt.Fprintf(color.Output, "%s%s %s\n",
				yellow(cidrstr), yellow(countstr), blue("Subdomain Name(s)"))
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

// parseInts implementation of the flag.Value interface
func (p *parseInts) String() string {
	if p == nil {
		return ""
	}

	var nums []string
	for _, n := range *p {
		nums = append(nums, strconv.Itoa(n))
	}
	return strings.Join(nums, ",")
}

func (p *parseInts) Set(s string) error {
	if s == "" {
		return fmt.Errorf("Integer parsing failed")
	}

	nums := strings.Split(s, ",")
	for _, n := range nums {
		i, err := strconv.Atoi(strings.TrimSpace(n))
		if err != nil {
			return err
		}
		*p = append(*p, i)
	}
	return nil
}

// parseIPs implementation of the flag.Value interface
func (p *parseIPs) String() string {
	if p == nil {
		return ""
	}

	var ipaddrs []string
	for _, ipaddr := range *p {
		ipaddrs = append(ipaddrs, ipaddr.String())
	}
	return strings.Join(ipaddrs, ",")
}

func (p *parseIPs) Set(s string) error {
	if s == "" {
		return fmt.Errorf("IP address parsing failed")
	}

	ips := strings.Split(s, ",")
	for _, ip := range ips {
		// Is this an IP range?
		err := p.parseRange(ip)
		if err == nil {
			continue
		}
		addr := net.ParseIP(ip)
		if addr == nil {
			return fmt.Errorf("%s is not a valid IP address or range", ip)
		}
		*p = append(*p, addr)
	}
	return nil
}

func (p *parseIPs) appendIPString(addrs []string) error {
	for _, addr := range addrs {
		ip := net.ParseIP(addr)
		if ip == nil {
			return fmt.Errorf("Failed to parse %s as an IP address", addr)
		}

		*p = append(*p, ip)
	}
	return nil
}

func (p *parseIPs) parseRange(s string) error {
	twoIPs := strings.Split(s, "-")

	if twoIPs[0] == s {
		// This is not an IP range
		return fmt.Errorf("%s is not a valid IP range", s)
	}
	start := net.ParseIP(twoIPs[0])
	end := net.ParseIP(twoIPs[1])
	if end == nil {
		num, err := strconv.Atoi(twoIPs[1])
		if err == nil {
			end = net.ParseIP(twoIPs[0])
			end[len(end)-1] = byte(num)
		}
	}
	if start == nil || end == nil {
		// These should have parsed properly
		return fmt.Errorf("%s is not a valid IP range", s)
	}
	return p.appendIPString(amass.RangeHosts(start, end))
}

// parseCIDRs implementation of the flag.Value interface
func (p *parseCIDRs) String() string {
	if p == nil {
		return ""
	}

	var cidrs []string
	for _, ipnet := range *p {
		cidrs = append(cidrs, ipnet.String())
	}
	return strings.Join(cidrs, ",")
}

func (p *parseCIDRs) Set(s string) error {
	if s == "" {
		return fmt.Errorf("%s is not a valid CIDR", s)
	}

	cidrs := strings.Split(s, ",")
	for _, cidr := range cidrs {
		_, ipnet, err := net.ParseCIDR(cidr)
		if err != nil {
			return fmt.Errorf("Failed to parse %s as a CIDR", cidr)
		}

		*p = append(*p, ipnet)
	}
	return nil
}
