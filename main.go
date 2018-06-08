// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"bufio"
	"bytes"
	"flag"
	"fmt"
	"math/rand"
	"net"
	"os"
	"os/signal"
	"path"
	//"runtime/pprof"
	"encoding/json"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/caffix/amass/amass"
	"github.com/fatih/color"
)

type outputParams struct {
	Verbose  bool
	PrintIPs bool
	FileOut  string
	JSONOut  string
	Results  chan *amass.AmassOutput
	Done     chan struct{}
}

// Types that implement the flag.Value interface for parsing
type parseStrings []string
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
	help          = flag.Bool("h", false, "Show the program usage message")
	version       = flag.Bool("version", false, "Print the version number of this amass binary")
	ips           = flag.Bool("ip", false, "Show the IP addresses for discovered names")
	brute         = flag.Bool("brute", false, "Execute brute forcing after searches")
	active        = flag.Bool("active", false, "Turn on active information gathering methods")
	norecursive   = flag.Bool("norecursive", false, "Turn off recursive brute forcing")
	minrecursive  = flag.Int("min-for-recursive", 0, "Number of subdomain discoveries before recursive brute forcing")
	noalts        = flag.Bool("noalts", false, "Disable generation of altered names")
	verbose       = flag.Bool("v", false, "Print the data source and summary information")
	whois         = flag.Bool("whois", false, "Include domains discoverd with reverse whois")
	list          = flag.Bool("l", false, "List all domains to be used in an enumeration")
	freq          = flag.Int64("freq", 0, "Sets the number of max DNS queries per minute")
	wordlist      = flag.String("w", "", "Path to a different wordlist file")
	outfile       = flag.String("o", "", "Path to the output file")
	jsonfile      = flag.String("json", "", "Path to the JSON output file")
	visjsfile     = flag.String("visjs", "", "Path to the Visjs output HTML file")
	domainsfile   = flag.String("df", "", "Path to a file providing root domain names")
	resolvefile   = flag.String("rf", "", "Path to a file providing preferred DNS resolvers")
	blacklistfile = flag.String("blf", "", "Path to a file providing blacklisted subdomains")
	neo4j         = flag.String("neo4j", "", "URL in the format of user:password@address:port")
)

func main() {
	var netopts bool
	var addrs parseIPs
	var cidrs parseCIDRs
	var asns, ports parseInts
	var domains, resolvers, blacklist parseStrings

	// This is for the potentially required network flags
	network := flag.NewFlagSet("net", flag.ContinueOnError)
	network.Var(&addrs, "addr", "IPs and ranges separated by commas (can be used multiple times)")
	network.Var(&cidrs, "cidr", "CIDRs separated by commas (can be used multiple times)")
	network.Var(&asns, "asn", "ASNs separated by commas (can be used multiple times)")
	network.Var(&ports, "p", "Ports used to discover TLS certs (can be used multiple times)")

	defaultBuf := new(bytes.Buffer)
	flag.CommandLine.SetOutput(defaultBuf)
	netBuf := new(bytes.Buffer)
	network.SetOutput(netBuf)

	flag.Var(&domains, "d", "Domain names separated by commas (can be used multiple times)")
	flag.Var(&resolvers, "r", "IP addresses of preferred DNS resolvers (can be used multiple times)")
	flag.Var(&blacklist, "bl", "Blacklist of subdomain names that will not be investigated")
	flag.Parse()

	// Check if the 'net' subcommand flags need to be parsed
	if len(flag.Args()) >= 2 {
		err := network.Parse(flag.Args()[1:])
		if err != nil {
			r.Println(err)
		}

		if len(addrs) > 0 || len(cidrs) > 0 || len(asns) > 0 {
			netopts = true
		}
	}
	// Should the help output be provided?
	if *help {
		printBanner()
		g.Printf("Usage: %s [options] <-d domain> | <net>\n", path.Base(os.Args[0]))
		flag.PrintDefaults()
		network.PrintDefaults()
		g.Println(defaultBuf.String())

		g.Println("Flags for the 'net' subcommand:")
		g.Println(netBuf.String())
		return
	}
	if *version {
		fmt.Printf("version %s\n", amass.Version)
		return
	}
	// Now, get domains provided by a file
	if *domainsfile != "" {
		domains = amass.UniqueAppend(domains, getLinesFromFile(*domainsfile)...)
	}
	// Can an enumeration be performed with the provided parameters?
	if len(domains) == 0 && !netopts {
		r.Println("The required parameters were not provided")
		r.Println("Use the -h switch for help information")
		return
	}
	// Get the resolvers provided by file
	if *resolvefile != "" {
		resolvers = amass.UniqueAppend(resolvers, getLinesFromFile(*resolvefile)...)
	}
	// Get the blacklisted subdomains provided by file
	if *blacklistfile != "" {
		blacklist = amass.UniqueAppend(blacklist, getLinesFromFile(*blacklistfile)...)
	}
	// Seed the default pseudo-random number generator
	rand.Seed(time.Now().UTC().UnixNano())

	done := make(chan struct{})
	results := make(chan *amass.AmassOutput, 100)

	go manageOutput(&outputParams{
		Verbose:  *verbose,
		PrintIPs: *ips,
		FileOut:  *outfile,
		JSONOut:  *jsonfile,
		Results:  results,
		Done:     done,
	})
	// Execute the signal handler
	go catchSignals(results, done)
	// Grab the words from an identified wordlist
	var words []string
	if *wordlist != "" {
		words = getLinesFromFile(*wordlist)
	}
	// Setup the amass configuration
	alts := true
	recursive := true
	if *noalts {
		alts = false
	}
	if *norecursive {
		recursive = false
	}
	config := amass.CustomConfig(&amass.AmassConfig{
		IPs:             addrs,
		ASNs:            asns,
		CIDRs:           cidrs,
		Ports:           ports,
		Whois:           *whois,
		Wordlist:        words,
		BruteForcing:    *brute,
		Recursive:       recursive,
		MinForRecursive: *minrecursive,
		Active:          *active,
		Alterations:     alts,
		Frequency:       freqToDuration(*freq),
		Resolvers:       resolvers,
		Blacklist:       blacklist,
		Neo4jPath:       *neo4j,
		Output:          results,
	})
	if len(domains) > 0 {
		config.AddDomains(domains)
	}
	amass.ObtainAdditionalDomains(config)
	if *list {
		listDomains(config, *outfile)
		return
	}
	//profFile, _ := os.Create("amass_debug.prof")
	//pprof.StartCPUProfile(profFile)
	//defer pprof.StopCPUProfile()
	err := amass.StartEnumeration(config)
	if err != nil {
		r.Println(err)
	}
	if *visjsfile != "" {
		writeVisjsOutput(*visjsfile, config.Graph.ToVisjs())
	}
	// Wait for output manager to finish
	<-done
}

func listDomains(config *amass.AmassConfig, outfile string) {
	var fileptr *os.File
	var bufwr *bufio.Writer

	if outfile != "" {
		fileptr, err := os.OpenFile(outfile, os.O_WRONLY|os.O_CREATE, 0644)
		if err == nil {
			bufwr = bufio.NewWriter(fileptr)
			defer fileptr.Close()
		}
	}

	for _, d := range config.Domains() {
		g.Println(d)

		if bufwr != nil {
			bufwr.WriteString(d + "\n")
			bufwr.Flush()
		}
	}

	if bufwr != nil {
		fileptr.Sync()
	}
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

type jsonAddr struct {
	IP          string `json:"ip"`
	CIDR        string `json:"cidr"`
	ASN         int    `json:"asn"`
	Description string `json:"desc"`
}
type jsonSave struct {
	Name      string     `json:"name"`
	Domain    string     `json:"domain"`
	Addresses []jsonAddr `json:"addresses"`
	Tag       string     `json:"tag"`
	Source    string     `json:"source"`
}

func manageOutput(params *outputParams) {
	var total int
	var bufwr *bufio.Writer
	var enc *json.Encoder
	var outptr, jsonptr *os.File

	if params.FileOut != "" {
		outptr, err := os.OpenFile(params.FileOut, os.O_WRONLY|os.O_CREATE, 0644)
		if err == nil {
			bufwr = bufio.NewWriter(outptr)
			defer outptr.Close()
		}
	}

	if params.JSONOut != "" {
		jsonptr, err := os.OpenFile(params.JSONOut, os.O_WRONLY|os.O_CREATE, 0644)
		if err == nil {
			enc = json.NewEncoder(jsonptr)
			defer jsonptr.Close()
		}
	}

	tags := make(map[string]int)
	asns := make(map[int]*asnData)
	// Collect all the names returned by the enumeration
	for result := range params.Results {
		total++
		updateData(result, tags, asns)

		var source, comma, ips string
		if params.Verbose {
			source = fmt.Sprintf("%-14s", "["+result.Source+"] ")
		}
		if params.PrintIPs {
			comma = ","

			for i, a := range result.Addresses {
				if i != 0 {
					ips += ","
				}
				ips += a.Address.String()
			}
		}
		// Add line to the others and print it out
		line := fmt.Sprintf("%s%s%s%s\n", source, result.Name, comma, ips)
		fmt.Fprintf(color.Output, "%s%s%s%s\n",
			blue(source), green(result.Name), green(comma), yellow(ips))
		// Handle writing the line to a specified output file
		if bufwr != nil {
			bufwr.WriteString(line)
			bufwr.Flush()
		}
		// Handle encoding the result as JSON
		if enc != nil {
			save := &jsonSave{
				Name:   result.Name,
				Domain: result.Domain,
				Tag:    result.Tag,
				Source: result.Source,
			}

			for _, addr := range result.Addresses {
				save.Addresses = append(save.Addresses, jsonAddr{
					IP:          addr.Address.String(),
					CIDR:        addr.Netblock.String(),
					ASN:         addr.ASN,
					Description: addr.Description,
				})
			}
			enc.Encode(save)
		}
	}
	if outptr != nil {
		outptr.Sync()
	}
	if jsonptr != nil {
		jsonptr.Sync()
	}
	// Check to print the summary information
	if params.Verbose {
		printSummary(total, tags, asns)
	}
	// Signal that output is complete
	close(params.Done)
}

func updateData(output *amass.AmassOutput, tags map[string]int, asns map[int]*asnData) {
	tags[output.Tag]++

	// Update the ASN information
	for _, addr := range output.Addresses {
		data, found := asns[addr.ASN]
		if !found {
			asns[addr.ASN] = &asnData{
				Name:      addr.Description,
				Netblocks: make(map[string]int),
			}
			data = asns[addr.ASN]
		}
		// Increment how many IPs were in this netblock
		data.Netblocks[addr.Netblock.String()]++
	}
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

func writeVisjsOutput(path, html string) {
	fileptr, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE, 0644)
	if err != nil {
		return
	}
	defer fileptr.Close()

	fileptr.WriteString(html)
	fileptr.Sync()
}

// If the user interrupts the program, print the summary information
func catchSignals(output chan *amass.AmassOutput, done chan struct{}) {
	sigs := make(chan os.Signal, 2)
	signal.Notify(sigs, os.Interrupt, syscall.SIGTERM)

	// Wait for a signal
	<-sigs
	// Start final output operations
	close(output)
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

// parseStrings implementation of the flag.Value interface
func (p *parseStrings) String() string {
	if p == nil {
		return ""
	}
	return strings.Join(*p, ",")
}

func (p *parseStrings) Set(s string) error {
	if s == "" {
		return fmt.Errorf("String parsing failed")
	}

	str := strings.Split(s, ",")
	for _, s := range str {
		*p = append(*p, strings.TrimSpace(s))
	}
	return nil
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

func (p *parseIPs) appendIPs(addrs []net.IP) error {
	for _, addr := range addrs {
		*p = append(*p, addr)
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
	return p.appendIPs(amass.RangeHosts(start, end))
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
