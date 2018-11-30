// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net/http"
	"os"
	"path"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/OWASP/Amass/amass"
	"github.com/OWASP/Amass/amass/utils"
	"github.com/fatih/color"
)

type outputParams struct {
	Enum     *amass.Enumeration
	PrintSrc bool
	PrintIPs bool
	FileOut  string
	JSONOut  string
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

var (
	finished chan struct{}
	// Colors used to ease the reading of program output
	y      = color.New(color.FgHiYellow)
	g      = color.New(color.FgHiGreen)
	r      = color.New(color.FgHiRed)
	b      = color.New(color.FgHiBlue)
	fgR    = color.New(color.FgRed)
	fgY    = color.New(color.FgYellow)
	yellow = color.New(color.FgHiYellow).SprintFunc()
	green  = color.New(color.FgHiGreen).SprintFunc()
	blue   = color.New(color.FgHiBlue).SprintFunc()
	// Command-line switches and provided parameters
	help          = flag.Bool("h", false, "Show the program usage message")
	version       = flag.Bool("version", false, "Print the version number of this amass binary")
	unresolved    = flag.Bool("include-unresolvable", false, "Output DNS names that did not resolve")
	ips           = flag.Bool("ip", false, "Show the IP addresses for discovered names")
	brute         = flag.Bool("brute", false, "Execute brute forcing after searches")
	active        = flag.Bool("active", false, "Attempt zone transfers and certificate name grabs")
	norecursive   = flag.Bool("norecursive", false, "Turn off recursive brute forcing")
	minrecursive  = flag.Int("min-for-recursive", 1, "Number of subdomain discoveries before recursive brute forcing")
	passive       = flag.Bool("passive", false, "Disable DNS resolution of names and dependent features")
	noalts        = flag.Bool("noalts", false, "Disable generation of altered names")
	sources       = flag.Bool("src", false, "Print data sources for the discovered names")
	timing        = flag.Int("T", int(amass.Normal), "Timing templates 0 (slowest) through 5 (fastest)")
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
	flag.Usage = func() {
		printBanner()
		g.Fprintf(color.Error, "Usage: %s [options] <-d domain>\n", path.Base(os.Args[0]))
		flag.PrintDefaults()
		g.Fprintln(color.Error, defaultBuf.String())
		os.Exit(1)
	}

	flag.Var(&ports, "p", "Ports separated by commas (default: 443)")
	flag.Var(&domains, "d", "Domain names separated by commas (can be used multiple times)")
	flag.Var(&resolvers, "r", "IP addresses of preferred DNS resolvers (can be used multiple times)")
	flag.Var(&blacklist, "bl", "Blacklist of subdomain names that will not be investigated")
	flag.Parse()

	// Some input validation
	if *help || len(os.Args) == 1 {
		flag.Usage()
	}
	if *version {
		fmt.Fprintf(color.Error, "version %s\n", amass.Version)
		return
	}
	if *passive && *ips {
		r.Fprintln(color.Error, "IP addresses cannot be provided without DNS resolution")
		return
	}
	if *passive && *brute {
		r.Fprintln(color.Error, "Brute forcing cannot be performed without DNS resolution")
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
	if *resolvepath != "" {
		resolvers = utils.UniqueAppend(resolvers, getLinesFromFile(*resolvepath)...)
	}
	amass.SetCustomResolvers(resolvers)
	if *domainspath != "" {
		domains = utils.UniqueAppend(domains, getLinesFromFile(*domainspath)...)
	}
	if len(domains) == 0 {
		r.Println("No root domain names were provided")
		return
	}
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

	rLog, wLog := io.Pipe()
	enum := amass.NewEnumeration()
	enum.Log = log.New(wLog, "", log.Lmicroseconds)
	enum.Config.Wordlist = words
	enum.Config.BruteForcing = *brute
	enum.Config.Recursive = recursive
	enum.Config.MinForRecursive = *minrecursive
	enum.Config.Active = *active
	enum.Config.IncludeUnresolvable = *unresolved
	enum.Config.Alterations = alts
	enum.Config.Timing = amass.EnumerationTiming(*timing)
	enum.Config.Passive = *passive
	enum.Config.Blacklist = blacklist
	for _, domain := range domains {
		enum.Config.AddDomain(domain)
	}
	go writeLogsAndMessages(rLog, logfile)

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

	finished = make(chan struct{})
	go manageOutput(&outputParams{
		Enum:     enum,
		PrintSrc: *sources,
		PrintIPs: *ips,
		FileOut:  txt,
		JSONOut:  jsonfile,
	})
	// Execute the signal handler
	go signalHandler(enum)

	if err := enum.Start(); err != nil {
		r.Println(err)
		return
	}
	// Wait for output manager to finish
	<-finished
}

func getLinesFromFile(path string) []string {
	var lines []string
	var reader io.Reader

	// Open the file
	file, err := os.Open(path)
	if err != nil {
		r.Fprintf(color.Error, "Error opening the file %s: %v\n", path, err)
		return lines
	}
	defer file.Close()
	reader = file

	// We need to determine if this is a gzipped file or a plain text file, so we
	// first read the first 512 bytes to pass them down to http.DetectContentType
	// for mime detection. The file is rewinded before passing it along to the
	// next reader
	head := make([]byte, 512)
	if _, err = file.Read(head); err != nil {
		r.Fprintf(color.Error, "Error reading the first 512 bytes from %s: %s\n", path, err)
		return lines
	}
	if _, err = file.Seek(0, 0); err != nil {
		r.Fprintf(color.Error, "Error rewinding the file %s: %s\n", path, err)
		return lines
	}

	// Read the file as gzip if it's actually compressed
	if mt := http.DetectContentType(head); mt == "application/gzip" || mt == "application/x-gzip" {
		gzReader, err := gzip.NewReader(file)
		if err != nil {
			r.Fprintf(color.Error, "Error gz-reading the file %s: %v\n", path, err)
			return lines
		}
		defer gzReader.Close()
		reader = gzReader
	}
	// Get each line from the file
	scanner := bufio.NewScanner(reader)
	for scanner.Scan() {
		// Get the next line
		text := scanner.Text()
		if text != "" {
			lines = append(lines, strings.TrimSpace(text))
		}
	}
	return lines
}

func writeLogsAndMessages(logs *io.PipeReader, logfile string) {
	wildcard := regexp.MustCompile("DNS wildcard")
	avg := regexp.MustCompile("Average DNS names")

	var filePtr *os.File
	if logfile != "" {
		filePtr, err := os.OpenFile(logfile, os.O_WRONLY|os.O_CREATE, 0644)
		if err != nil {
			r.Printf("Failed to open the log file: %v", err)
		} else {
			defer func() {
				filePtr.Sync()
				filePtr.Close()
			}()
		}
	}

	scanner := bufio.NewScanner(logs)
	for scanner.Scan() {
		line := scanner.Text()

		if err := scanner.Err(); err != nil {
			fmt.Fprintf(color.Error, "Error reading the Amass logs: %v\n", err)
			break
		}

		if filePtr != nil {
			fmt.Fprintln(filePtr, line)
		}
		// Remove the timestamp
		parts := strings.Split(line, " ")
		line = strings.Join(parts[1:], " ")
		// Check for Amass DNS wildcard messages
		if wildcard.FindString(line) != "" {
			fgR.Fprintln(color.Error, line)
		}
		// Check for the Amass average DNS names messages
		if avg.FindString(line) != "" {
			fgY.Fprintln(color.Error, line)
		}
	}
}

func writeJSONData(f *os.File, result *amass.Output) {
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

func printBanner() {
	rightmost := 76
	version := "Version " + amass.Version
	desc := "In-Depth DNS Enumeration and Network Mapping"
	author := "Authored By " + amass.Author

	pad := func(num int) {
		for i := 0; i < num; i++ {
			fmt.Fprint(color.Error, " ")
		}
	}
	r.Fprintln(color.Error, amass.Banner)
	pad(rightmost - len(version))
	y.Fprintln(color.Error, version)
	pad(rightmost - len(author))
	y.Fprintln(color.Error, author)
	pad(rightmost - len(desc))
	y.Fprintf(color.Error, "%s\n\n\n", desc)
}

func resultToLine(result *amass.Output, params *outputParams) (string, string, string, string) {
	var source, comma, ips string

	if params.PrintSrc {
		source = fmt.Sprintf("%-18s", "["+result.Source+"] ")
	}
	if params.PrintIPs {
		comma = ","

		for i, a := range result.Addresses {
			if i != 0 {
				ips += ","
			}
			ips += a.Address.String()
		}
		if ips == "" {
			ips = "N/A"
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
	for result := range params.Enum.Output {
		if params.Enum.Config.Passive || len(result.Addresses) > 0 {
			total++
		}

		updateData(result, tags, asns)

		source, name, comma, ips := resultToLine(result, params)
		fmt.Fprintf(color.Output, "%s%s%s%s\n",
			blue(source), green(name), green(comma), yellow(ips))
		// Handle writing the line to a specified output file
		if outptr != nil {
			fmt.Fprintf(outptr, "%s%s%s%s\n", source, name, comma, ips)
		}
		// Handle encoding the result as JSON
		if jsonptr != nil {
			writeJSONData(jsonptr, result)
		}
	}
	if total == 0 {
		r.Println("No names were discovered")
	} else {
		printSummary(total, tags, asns)
	}
	close(finished)
}

func updateData(output *amass.Output, tags map[string]int, asns map[int]*asnData) {
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
	pad := func(num int, chr string) {
		for i := 0; i < num; i++ {
			b.Fprint(color.Error, chr)
		}
	}

	fmt.Fprintln(color.Error)
	// Print the header information
	title := "OWASP Amass v"
	site := "https://github.com/OWASP/Amass"
	b.Fprint(color.Error, title+amass.Version)
	num := 80 - (len(title) + len(amass.Version) + len(site))
	pad(num, " ")
	b.Fprintf(color.Error, "%s\n", site)
	pad(8, "----------")
	fmt.Fprintf(color.Error, "\n%s%s", yellow(strconv.Itoa(total)), green(" names discovered - "))
	// Print the stats using tag information
	num, length := 1, len(tags)
	for k, v := range tags {
		fmt.Fprintf(color.Error, "%s: %s", green(k), yellow(strconv.Itoa(v)))
		if num < length {
			g.Fprint(color.Error, ", ")
		}
		num++
	}
	fmt.Fprintln(color.Error)

	if len(asns) == 0 {
		return
	}
	// Another line gets printed
	pad(8, "----------")
	fmt.Fprintln(color.Error)
	// Print the ASN and netblock information
	for asn, data := range asns {
		fmt.Fprintf(color.Error, "%s%s %s %s\n",
			blue("ASN: "), yellow(strconv.Itoa(asn)), green("-"), green(data.Name))

		for cidr, ips := range data.Netblocks {
			countstr := fmt.Sprintf("\t%-4s", strconv.Itoa(ips))
			cidrstr := fmt.Sprintf("\t%-18s", cidr)

			fmt.Fprintf(color.Error, "%s%s %s\n",
				yellow(cidrstr), yellow(countstr), blue("Subdomain Name(s)"))
		}
	}
}
