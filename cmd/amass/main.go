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
	"os"
	"path"
	"strings"
	"time"

	"github.com/OWASP/Amass/amass"
	"github.com/OWASP/Amass/amass/dnssrv"
	"github.com/OWASP/Amass/amass/utils"
	"github.com/fatih/color"
)

var (
	finished chan struct{}
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
	active        = flag.Bool("active", false, "Attempt zone transfers and certificate name grabs")
	norecursive   = flag.Bool("norecursive", false, "Turn off recursive brute forcing")
	minrecursive  = flag.Int("min-for-recursive", 1, "Number of subdomain discoveries before recursive brute forcing")
	passive       = flag.Bool("passive", false, "Disable DNS resolution of names and dependent features")
	noalts        = flag.Bool("noalts", false, "Disable generation of altered names")
	timing        = flag.Int("T", int(amass.Normal), "Timing templates 0 (slowest) through 5 (fastest)")
	verbose       = flag.Bool("v", false, "Print the data source and summary information")
	whois         = flag.Bool("whois", false, "Include domains discoverd with reverse whois")
	list          = flag.Bool("l", false, "List all domains to be used in an enumeration")
	wordlist      = flag.String("w", "", "Path to a different wordlist file")
	allpath       = flag.String("oA", "", "Path prefix used for naming all output files")
	logpath       = flag.String("log", "", "Path to the log file where errors will be written")
	outpath       = flag.String("o", "", "Path to the text output file")
	jsonpath      = flag.String("json", "", "Path to the JSON output file")
	datapath      = flag.String("do", "", "Path to data operations output file")
	domainspath   = flag.String("df", "", "Path to a file providing root domain names")
	resolvepath   = flag.String("rf", "", "Path to a file providing preferred DNS resolvers")
	blacklistpath = flag.String("blf", "", "Path to a file providing blacklisted subdomains")
)

func main() {
	var ports parseInts
	var domains, resolvers, blacklist parseStrings

	defaultBuf := new(bytes.Buffer)
	flag.CommandLine.SetOutput(defaultBuf)

	flag.Var(&ports, "p", "Ports separated by commas (default: 443)")
	flag.Var(&domains, "d", "Domain names separated by commas (can be used multiple times)")
	flag.Var(&resolvers, "r", "IP addresses of preferred DNS resolvers (can be used multiple times)")
	flag.Var(&blacklist, "bl", "Blacklist of subdomain names that will not be investigated")
	flag.Parse()

	// Some input validation
	if *help {
		printBanner()
		g.Printf("Usage: %s [options] <-d domain>\n", path.Base(os.Args[0]))
		flag.PrintDefaults()
		g.Println(defaultBuf.String())
		return
	}
	if *version {
		fmt.Printf("version %s\n", amass.Version)
		return
	}
	if *passive && *ips {
		r.Println("IP addresses cannot be provided without DNS resolution")
		return
	}

	var words []string
	// Obtain parameters from provided files
	if *wordlist != "" {
		words = getLinesFromFile(*wordlist)
	}
	if *blacklistpath != "" {
		blacklist = utils.UniqueAppend(blacklist, getLinesFromFile(*blacklistpath)...)
	}
	if *domainspath != "" {
		domains = utils.UniqueAppend(domains, getLinesFromFile(*domainspath)...)
	}
	if *resolvepath != "" {
		resolvers = utils.UniqueAppend(resolvers, getLinesFromFile(*resolvepath)...)
	}
	dnssrv.SetCustomResolvers(resolvers)

	// Prepare output files
	logfile := *logpath
	txt := *outpath
	jsonfile := *jsonpath
	datafile := *datapath
	if *allpath != "" {
		logfile = *allpath + ".log"
		txt = *allpath + ".txt"
		jsonfile = *allpath + ".json"
		datafile = *allpath + "_data.json"
	}

	// Seed the default pseudo-random number generator
	rand.Seed(time.Now().UTC().UnixNano())
	// Setup the amass configuration
	alts := true
	recursive := true
	if *noalts {
		alts = false
	}
	if *norecursive {
		recursive = false
	}
	enum := amass.NewEnumeration()
	enum.Whois = *whois
	enum.Wordlist = words
	enum.BruteForcing = *brute
	enum.Recursive = recursive
	enum.MinForRecursive = *minrecursive
	enum.Active = *active
	enum.Alterations = alts
	enum.Timing = amass.EnumerationTiming(*timing)
	enum.Passive = *passive
	enum.Blacklist = blacklist

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
	// Setup the data operations output file
	if datafile != "" {
		fileptr, err := os.OpenFile(datafile, os.O_WRONLY|os.O_CREATE, 0644)
		if err != nil {
			r.Printf("Failed to open the data operations output file: %v", err)
			return
		}
		defer func() {
			fileptr.Sync()
			fileptr.Close()
		}()
		enum.DataOptsWriter = fileptr
	}
	enum.ObtainAdditionalDomains()
	if *list {
		listDomains(enum, txt)
		return
	}
	// Can an enumeration be performed with the provided parameters?
	if len(enum.Domains()) == 0 {
		r.Println("No root domain names were provided or discovered")
		return
	}

	finished = make(chan struct{})
	go manageOutput(&outputParams{
		Enum:     enum,
		Verbose:  *verbose,
		PrintIPs: *ips,
		FileOut:  txt,
		JSONOut:  jsonfile,
	})

	// Execute the signal handler
	go signalHandler(enum)

	err := enum.Start()
	if err != nil {
		r.Println(err)
		return
	}
	// Wait for output manager to finish
	<-finished
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
