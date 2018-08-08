// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"bufio"
	"bytes"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"math/rand"
	"os"
	"os/signal"
	"path"
	"runtime"
	"runtime/pprof"
	"strings"
	"syscall"
	"time"

	"github.com/OWASP/Amass/amass"
	"github.com/OWASP/Amass/amass/utils"
	"github.com/fatih/color"
)

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
		PrintBanner()
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
		words = GetLinesFromFile(*wordlist)
	}
	if *domainspath != "" {
		domains = utils.UniqueAppend(domains, GetLinesFromFile(*domainspath)...)
	}
	if *resolvepath != "" {
		resolvers = utils.UniqueAppend(resolvers, GetLinesFromFile(*resolvepath)...)
	}
	if *blacklistpath != "" {
		blacklist = utils.UniqueAppend(blacklist, GetLinesFromFile(*blacklistpath)...)
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
	go CatchSignals(results, done)

	// Setup the amass configuration
	alts := true
	recursive := true
	if *noalts {
		alts = false
	}
	if *norecursive {
		recursive = false
	}
	enum := &amass.Enumeration{
		Log:             log.New(ioutil.Discard, "", 0),
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
		Frequency:       FreqToDuration(*freq),
		Resolvers:       resolvers,
		Blacklist:       blacklist,
		Neo4jPath:       *neo4j,
		Output:          results,
	}
	for _, domain := range domains {
		enum.AddDomain(domain)
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
		enum.Log = log.New(fileptr, "", log.Lmicroseconds)
	}
	enum.ObtainAdditionalDomains()
	if *list {
		ListDomains(enum, txt)
		return
	}
	// Can an enumeration be performed with the provided parameters?
	if len(enum.Domains()) == 0 {
		r.Println("No root domain names were provided or discovered")
		return
	}

	go ManageOutput(&OutputParams{
		Enum:          enum,
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

	err := enum.Start()
	if err != nil {
		r.Println(err)
		return
	}
	profFile, _ := os.Create("amass_mem.prof")
	defer profFile.Close()
	runtime.GC()
	pprof.WriteHeapProfile(profFile)
	// Wait for output manager to finish
	<-done
}

// If the user interrupts the program, print the summary information
func CatchSignals(output chan *amass.AmassOutput, done chan struct{}) {
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

func GetLinesFromFile(path string) []string {
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

func FreqToDuration(freq int64) time.Duration {
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
	return amass.DefaultFrequency
}
