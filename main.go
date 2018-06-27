// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"bufio"
	"bytes"
	"flag"
	"fmt"
	"log"
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
	Config        *amass.AmassConfig
	Verbose       bool
	PrintIPs      bool
	FileOut       string
	JSONOut       string
	VisjsOut      string
	GraphistryOut string
	GEXFOut       string
	D3Out         string
	Done          chan struct{}
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
	help           = flag.Bool("h", false, "Show the program usage message")
	version        = flag.Bool("version", false, "Print the version number of this amass binary")
	ips            = flag.Bool("ip", false, "Show the IP addresses for discovered names")
	brute          = flag.Bool("brute", false, "Execute brute forcing after searches")
	active         = flag.Bool("active", false, "Turn on active information gathering methods")
	norecursive    = flag.Bool("norecursive", false, "Turn off recursive brute forcing")
	minrecursive   = flag.Int("min-for-recursive", 0, "Number of subdomain discoveries before recursive brute forcing")
	nodns          = flag.Bool("nodns", false, "Disable DNS resolution of names and dependent features")
	noalts         = flag.Bool("noalts", false, "Disable generation of altered names")
	verbose        = flag.Bool("v", false, "Print the data source and summary information")
	whois          = flag.Bool("whois", false, "Include domains discoverd with reverse whois")
	list           = flag.Bool("l", false, "List all domains to be used in an enumeration")
	freq           = flag.Int64("freq", 0, "Sets the number of max DNS queries per minute")
	wordlist       = flag.String("w", "", "Path to a different wordlist file")
	allpath        = flag.String("oA", "", "Path prefix used for naming all output files")
	logpath        = flag.String("log", "", "Path to the log file where errors will be written")
	outpath        = flag.String("o", "", "Path to the text output file")
	jsonpath       = flag.String("json", "", "Path to the JSON output file")
	visjspath      = flag.String("visjs", "", "Path to the Visjs output HTML file")
	graphistrypath = flag.String("graphistry", "", "Path to the Graphistry JSON file")
	gexfpath       = flag.String("gexf", "", "Path to the Gephi Graph Exchange XML Format (GEXF) file")
	d3path         = flag.String("d3", "", "Path to the D3 v4 force simulation HTML file")
	domainspath    = flag.String("df", "", "Path to a file providing root domain names")
	resolvepath    = flag.String("rf", "", "Path to a file providing preferred DNS resolvers")
	blacklistpath  = flag.String("blf", "", "Path to a file providing blacklisted subdomains")
	neo4j          = flag.String("neo4j", "", "URL in the format of user:password@address:port")
)

func main() {
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
	}
	// Some input validation
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
	if *nodns && *ips {
		r.Println("IP addresses cannot be provided without DNS resolution")
		return
	}

	var words []string
	if *wordlist != "" {
		words = getLinesFromFile(*wordlist)
	}
	if *domainspath != "" {
		domains = UniqueAppend(domains, getLinesFromFile(*domainspath)...)
	}
	if *resolvepath != "" {
		resolvers = UniqueAppend(resolvers, getLinesFromFile(*resolvepath)...)
	}
	if *blacklistpath != "" {
		blacklist = UniqueAppend(blacklist, getLinesFromFile(*blacklistpath)...)
	}

	// Prepare output files
	logfile := *logpath
	txt := *outpath
	jsonfile := *jsonpath
	d3 := *d3path
	visjs := *visjspath
	gexf := *gexfpath
	graphistry := *graphistrypath
	if *allpath != "" {
		logfile = *allpath + ".log"
		txt = *allpath + ".txt"
		jsonfile = *allpath + ".json"
		d3 = *allpath + "_d3.html"
		visjs = *allpath + "_visjs.html"
		gexf = *allpath + ".gexf"
		graphistry = *allpath + "_graphistry.json"
	}

	// Seed the default pseudo-random number generator
	rand.Seed(time.Now().UTC().UnixNano())

	done := make(chan struct{})
	results := make(chan *amass.AmassOutput, 100)
	// Execute the signal handler
	go catchSignals(results, done)

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
		NoDNS:           *nodns,
		Frequency:       freqToDuration(*freq),
		Resolvers:       resolvers,
		Blacklist:       blacklist,
		Neo4jPath:       *neo4j,
		Output:          results,
	})
	if len(domains) > 0 {
		config.AddDomains(domains)
	}
	// Setup the log file for saving error messages
	if logfile != "" {
		fileptr, err := os.OpenFile(logfile, os.O_WRONLY|os.O_CREATE, 0644)
		if err != nil {
			r.Printf("Failed to open the log file: %v", err)
			return
		}
		defer func() {
			fileptr.Sync()
			fileptr.Close()
		}()
		config.Log = log.New(fileptr, "", log.Lmicroseconds)
	}
	amass.ObtainAdditionalDomains(config)
	if *list {
		listDomains(config, txt)
		return
	}
	// Can an enumeration be performed with the provided parameters?
	if len(config.Domains()) == 0 {
		r.Println("The parameters required for identifying a target were not provided")
		r.Println("Use the -h switch for help information")
		return
	}

	go manageOutput(&outputParams{
		Config:        config,
		Verbose:       *verbose,
		PrintIPs:      *ips,
		FileOut:       txt,
		JSONOut:       jsonfile,
		VisjsOut:      visjs,
		GraphistryOut: graphistry,
		GEXFOut:       gexf,
		D3Out:         d3,
		Done:          done,
	})
	//profFile, _ := os.Create("amass_debug.prof")
	//pprof.StartCPUProfile(profFile)
	//defer pprof.StopCPUProfile()
	err := amass.StartEnumeration(config)
	if err != nil {
		r.Println(err)
		return
	}
	// Wait for output manager to finish
	<-done
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
	os.Exit(1)
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

func WriteJSONData(f *os.File, result *amass.AmassOutput) {
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

	enc := json.NewEncoder(f)
	enc.Encode(save)
}

func WriteTextData(f *os.File, source, name, comma, ips string) {
	fmt.Fprintf(f, "%s%s%s%s\n", source, name, comma, ips)
}

func ResultToLine(result *amass.AmassOutput, params *outputParams) (string, string, string, string) {
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
	return source, result.Name, comma, ips
}

func manageOutput(params *outputParams) {
	var total int
	var err error
	var outptr, jsonptr *os.File

	if params.FileOut != "" {
		outptr, err = os.OpenFile(params.FileOut, os.O_WRONLY|os.O_CREATE, 0644)
		if err == nil {
			defer func() {
				outptr.Sync()
				outptr.Close()
			}()
		}
	}

	if params.JSONOut != "" {
		jsonptr, err = os.OpenFile(params.JSONOut, os.O_WRONLY|os.O_CREATE, 0644)
		if err == nil {
			defer func() {
				jsonptr.Sync()
				jsonptr.Close()
			}()
		}
	}

	tags := make(map[string]int)
	asns := make(map[int]*asnData)
	// Collect all the names returned by the enumeration
	for result := range params.Config.Output {
		total++
		updateData(result, tags, asns)

		source, name, comma, ips := ResultToLine(result, params)
		fmt.Fprintf(color.Output, "%s%s%s%s\n",
			blue(source), green(name), green(comma), yellow(ips))
		// Handle writing the line to a specified output file
		if outptr != nil {
			WriteTextData(outptr, source, name, comma, ips)
		}
		// Handle encoding the result as JSON
		if jsonptr != nil {
			WriteJSONData(jsonptr, result)
		}
	}

	amass.WriteVisjsFile(params.VisjsOut, params.Config)
	amass.WriteGraphistryFile(params.GraphistryOut, params.Config)
	amass.WriteGEXFFile(params.GEXFOut, params.Config)
	amass.WriteD3File(params.D3Out, params.Config)
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

	if len(asns) == 0 {
		return
	}
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
	return p.appendIPs(RangeHosts(start, end))
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

// NewUniqueElements - Removes elements that have duplicates in the original or new elements
func NewUniqueElements(orig []string, add ...string) []string {
	var n []string

	for _, av := range add {
		found := false
		s := strings.ToLower(av)

		// Check the original slice for duplicates
		for _, ov := range orig {
			if s == strings.ToLower(ov) {
				found = true
				break
			}
		}
		// Check that we didn't already add it in
		if !found {
			for _, nv := range n {
				if s == nv {
					found = true
					break
				}
			}
		}
		// If no duplicates were found, add the entry in
		if !found {
			n = append(n, s)
		}
	}
	return n
}

// UniqueAppend - Behaves like the Go append, but does not add duplicate elements
func UniqueAppend(orig []string, add ...string) []string {
	return append(orig, NewUniqueElements(orig, add...)...)
}

func RangeHosts(start, end net.IP) []net.IP {
	var ips []net.IP

	stop := net.ParseIP(end.String())
	addrInc(stop)
	for ip := net.ParseIP(start.String()); !ip.Equal(stop); addrInc(ip) {
		addr := net.ParseIP(ip.String())

		ips = append(ips, addr)
	}
	return ips
}

func addrInc(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}
