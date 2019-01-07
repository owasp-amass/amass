// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package amass

import (
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/OWASP/Amass/amass/utils"
	"github.com/PuerkitoBio/fetchbot"
	"github.com/PuerkitoBio/goquery"
)

// Banner is the ASCII art logo used within help output.
var Banner = `

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

const (
	// Version is used to display the current version of Amass.
	Version = "2.8.8"

	// Author is used to display the founder of the amass package.
	Author = "Jeff Foley - @jeff_foley"
)

// Request tag types
const (
	OUTPUT = "amass:output"

	ALT     = "alt"
	ARCHIVE = "archive"
	API     = "api"
	AXFR    = "axfr"
	BRUTE   = "brute"
	CERT    = "cert"
	DNS     = "dns"
	SCRAPE  = "scrape"
)

// The various timing/speed templates for an Amass enumeration.
const (
	Paranoid EnumerationTiming = iota
	Sneaky
	Polite
	Normal
	Aggressive
	Insane
)

var (
	nameStripRE = regexp.MustCompile("^((20)|(25)|(2f)|(3d)|(40))+")
)

// EnumerationTiming represents a speed band for the enumeration to execute within.
type EnumerationTiming int

// Enumeration is the object type used to execute a DNS enumeration with Amass.
type Enumeration struct {
	Config *Config

	// Link graph that collects all the information gathered by the enumeration
	Graph *Graph

	// The channel that will receive the results
	Output chan *Output

	// Broadcast channel that indicates no further writes to the output channel
	Done chan struct{}

	// Logger for error messages
	Log *log.Logger

	// The writer used to save the data operations performed
	DataOptsWriter io.Writer

	// MaxFlow is a Semaphore that restricts the number of names moving through the architecture
	MaxFlow utils.Semaphore

	nameService  *NameService
	addrService  *AddressService
	dnsService   *DNSService
	dataService  *DataManagerService
	altService   *AlterationService
	bruteService *BruteForceService
	activeCert   *ActiveCertService
	dataSources  []Service

	trustedNameFilter *utils.StringFilter
	otherNameFilter   *utils.StringFilter

	// Pause/Resume channels for halting the enumeration
	pause  chan struct{}
	resume chan struct{}
}

// NewEnumeration returns an initialized Enumeration that has not been started yet.
func NewEnumeration() *Enumeration {
	enum := &Enumeration{
		Config:            new(Config),
		Graph:             NewGraph(),
		Output:            make(chan *Output, 100),
		Done:              make(chan struct{}),
		Log:               log.New(ioutil.Discard, "", 0),
		trustedNameFilter: utils.NewStringFilter(),
		otherNameFilter:   utils.NewStringFilter(),
		pause:             make(chan struct{}),
		resume:            make(chan struct{}),
	}
	enum.nameService = NewNameService(enum)
	enum.addrService = NewAddressService(enum)
	enum.dnsService = NewDNSService(enum)
	enum.dataService = NewDataManagerService(enum)
	enum.altService = NewAlterationService(enum)
	enum.bruteService = NewBruteForceService(enum)
	enum.activeCert = NewActiveCertService(enum)
	enum.dataSources = GetAllSources(enum)
	return enum
}

// Start begins the DNS enumeration process for the Amass Enumeration object.
func (e *Enumeration) Start() error {
	if e.Output == nil {
		return errors.New("The enumeration did not have an output channel")
	} else if e.Config.Passive && e.DataOptsWriter != nil {
		return errors.New("Data operations cannot be saved without DNS resolution")
	} else if len(e.Config.DisabledDataSources) > 0 {
		e.dataSources = e.Config.ExcludeDisabledDataSources(e.dataSources)
	} else if err := e.Config.CheckSettings(); err != nil {
		return err
	}

	e.MaxFlow = utils.NewTimedSemaphore(e.Config.Timing.ToMaxFlow(), e.Config.Timing.ToReleaseDelay())

	// Select the correct services to be used in this enumeration
	var services []Service
	if !e.Config.Passive {
		services = append(services, e.dnsService, e.dataService, e.activeCert)
	}
	services = append(services, e.nameService, e.addrService)
	if !e.Config.Passive {
		services = append(services, e.altService, e.bruteService)
	}
	// Grab all the data sources
	services = append(services, e.dataSources...)

	for _, srv := range services {
		if err := srv.Start(); err != nil {
			return err
		}
	}

	t := time.NewTicker(3 * time.Second)
loop:
	for {
		select {
		case <-e.Done:
			break loop
		case <-e.PauseChan():
			t.Stop()
		case <-e.ResumeChan():
			t = time.NewTicker(3 * time.Second)
		case <-t.C:
			done := true

			for _, srv := range services {
				if srv.IsActive() {
					done = false
					break
				}
			}

			if done {
				break loop
			}
		}
	}
	t.Stop()
	for _, srv := range services {
		srv.Stop()
	}
	time.Sleep(2 * time.Second)
	close(e.Output)
	return nil
}

// Pause temporarily halts the enumeration.
func (e *Enumeration) Pause() {
	e.pause <- struct{}{}
}

// PauseChan returns the channel that is signaled when Pause is called.
func (e *Enumeration) PauseChan() <-chan struct{} {
	return e.pause
}

// Resume causes a previously paused enumeration to resume execution.
func (e *Enumeration) Resume() {
	e.resume <- struct{}{}
}

// ResumeChan returns the channel that is signaled when Resume is called.
func (e *Enumeration) ResumeChan() <-chan struct{} {
	return e.resume
}

//-------------------------------------------------------------------------------------------------
// Various events that takes place between Amass engine services
//-------------------------------------------------------------------------------------------------

// NewNameEvent signals the NameService of a newly discovered DNS name.
func (e *Enumeration) NewNameEvent(req *Request) {
	if req == nil || req.Name == "" || req.Domain == "" {
		return
	}

	req.Name = strings.ToLower(utils.RemoveAsteriskLabel(req.Name))
	req.Domain = strings.ToLower(req.Domain)

	tt := TrustedTag(req.Tag)
	if !tt && e.otherNameFilter.Duplicate(req.Name) {
		return
	} else if tt && e.trustedNameFilter.Duplicate(req.Name) {
		return
	}

	if !e.Config.Passive {
		e.MaxFlow.Acquire(1)
	}
	go e.nameService.SendRequest(req)
}

// NewAddressEvent signals the AddressService of a newly discovered address.
func (e *Enumeration) NewAddressEvent(req *Request) {
	if req == nil || req.Address == "" {
		return
	}
	go e.addrService.SendRequest(req)
}

// NewSubdomainEvent signals the services of a newly discovered subdomain name.
func (e *Enumeration) NewSubdomainEvent(req *Request, times int) {
	if req == nil || req.Name == "" || req.Domain == "" {
		return
	}

	// CNAMEs are not a proper subdomain
	if e.Graph.CNAMENode(req.Name) != nil {
		return
	}

	if e.Config.BruteForcing && e.Config.Recursive {
		go e.bruteService.NewSubdomain(req, times)
	}
	go e.dnsService.NewSubdomain(req, times)
}

// ResolveNameEvent sends a request to be resolved by the DNS service.
func (e *Enumeration) ResolveNameEvent(req *Request) {
	if req == nil || req.Name == "" || req.Domain == "" {
		if !e.Config.Passive {
			e.MaxFlow.Release(1)
		}
		return
	}

	if e.Config.Blacklisted(req.Name) || (!TrustedTag(req.Tag) &&
		e.dnsService.GetWildcardType(req) == WildcardTypeDynamic) {
		if !e.Config.Passive {
			e.MaxFlow.Release(1)
		}
		return
	}
	go e.dnsService.SendRequest(req)
}

// ResolvedNameEvent signals the NameService of a newly resolved DNS name.
func (e *Enumeration) ResolvedNameEvent(req *Request) {
	if !TrustedTag(req.Tag) && e.dnsService.MatchesWildcard(req) {
		return
	}
	go e.nameService.Resolved(req)
}

// CheckedNameEvent signals all services interested in acting on new validated DNS names.
func (e *Enumeration) CheckedNameEvent(req *Request) {
	go e.dataService.SendRequest(req)

	if e.Config.Alterations {
		go e.altService.SendRequest(req)
	}

	if e.Config.BruteForcing && e.Config.Recursive && e.Config.MinForRecursive == 0 {
		go e.bruteService.SendRequest(req)
	}

	for _, source := range e.dataSources {
		go source.SendRequest(req)
	}
}

// ReverseDNSSweepEvent requests that a reverse DNS sweep be performed.
func (e *Enumeration) ReverseDNSSweepEvent(req *Request) {
	if e.Config.Passive {
		return
	}

	_, cidr, _, err := IPRequest(req.Address)
	if err != nil {
		e.Log.Printf("%v", err)
		return
	}

	go e.dnsService.ReverseDNSSweep(req.Address, cidr)
}

// ActiveCertEvent requests that a certificate be pulled and parsed for DNS names.
func (e *Enumeration) ActiveCertEvent(req *Request) {
	if e.Config.Active {
		go e.activeCert.SendRequest(req)
	}
}

// OutputEvent sends enumeration output to the package API caller.
func (e *Enumeration) OutputEvent(out *Output) {
	e.Output <- out
}

// TrustedTag returns true when the tag parameter is of a type that should be trusted even
// facing DNS wildcards.
func TrustedTag(tag string) bool {
	if tag == DNS || tag == CERT || tag == ARCHIVE || tag == AXFR {
		return true
	}
	return false
}

// ToMaxFlow returns the maximum number of names Amass should handle at once.
func (t EnumerationTiming) ToMaxFlow() int {
	var result int

	switch t {
	case Paranoid:
		result = 30
	case Sneaky:
		result = 100
	case Polite:
		result = 333
	case Normal:
		result = 1000
	case Aggressive:
		result = 10000
	case Insane:
		result = 100000
	}
	return result
}

// ToReleaseDelay returns the minimum delay between each MaxFlow semaphore release.
func (t EnumerationTiming) ToReleaseDelay() time.Duration {
	var result time.Duration

	switch t {
	case Paranoid:
		result = 33 * time.Millisecond
	case Sneaky:
		result = 10 * time.Millisecond
	case Polite:
		result = 3 * time.Millisecond
	case Normal:
		result = time.Millisecond
	case Aggressive:
		result = 100 * time.Microsecond
	case Insane:
		result = 10 * time.Microsecond
	}
	return result
}

// ToReleasesPerSecond returns the number of releases performed on MaxFlow each second.
func (t EnumerationTiming) ToReleasesPerSecond() int {
	var result int

	switch t {
	case Paranoid:
		result = 30
	case Sneaky:
		result = 100
	case Polite:
		result = 333
	case Normal:
		result = 1000
	case Aggressive:
		result = 10000
	case Insane:
		result = 100000
	}
	return result
}

// GetAllSources returns a slice of all data source services, initialized and ready.
func GetAllSources(e *Enumeration) []Service {
	return []Service{
		NewArchiveIt(e),
		NewArchiveToday(e),
		NewArquivo(e),
		NewAsk(e),
		NewBaidu(e),
		NewBinaryEdge(e),
		NewBing(e),
		NewCensys(e),
		NewCertDB(e),
		NewCertSpotter(e),
		NewCIRCL(e),
		NewCommonCrawl(e),
		NewCrtsh(e),
		NewDNSDB(e),
		NewDNSDumpster(e),
		NewDNSTable(e),
		NewDogpile(e),
		NewEntrust(e),
		NewExalead(e),
		NewFindSubdomains(e),
		NewGoogle(e),
		NewHackerTarget(e),
		NewIPv4Info(e),
		NewLoCArchive(e),
		NewNetcraft(e),
		NewOpenUKArchive(e),
		NewPassiveTotal(e),
		NewPTRArchive(e),
		NewRiddler(e),
		NewRobtex(e),
		NewSiteDossier(e),
		NewSecurityTrails(e),
		NewShodan(e),
		NewThreatCrowd(e),
		NewTwitter(e),
		NewUKGovArchive(e),
		NewUmbrella(e),
		NewURLScan(e),
		NewVirusTotal(e),
		NewWayback(e),
		NewYahoo(e),
	}
}

// GetAllSourceNames returns the names of all the available data sources.
func (e *Enumeration) GetAllSourceNames() []string {
	var names []string

	for _, source := range e.dataSources {
		names = append(names, source.String())
	}
	return names
}

// Clean up the names scraped from the web.
func cleanName(name string) string {
	if i := nameStripRE.FindStringIndex(name); i != nil {
		name = name[i[1]:]
	}
	name = strings.TrimSpace(strings.ToLower(name))
	// Remove dots at the beginning of names
	if len(name) > 1 && name[0] == '.' {
		name = name[1:]
	}
	return name
}

//-------------------------------------------------------------------------------------------------
// Web archive crawler implementation
//-------------------------------------------------------------------------------------------------

func crawl(service Service, base, domain, sub string) ([]string, error) {
	var results []string
	var filterMutex sync.Mutex
	filter := make(map[string]struct{})

	year := strconv.Itoa(time.Now().Year())
	mux := fetchbot.NewMux()
	links := make(chan string, 50)
	names := make(chan string, 50)
	linksFilter := make(map[string]struct{})

	mux.HandleErrors(fetchbot.HandlerFunc(func(ctx *fetchbot.Context, res *http.Response, err error) {
		//service.Config.Log.Printf("Crawler error: %s %s - %v", ctx.Cmd.Method(), ctx.Cmd.URL(), err)
	}))

	mux.Response().Method("GET").ContentType("text/html").Handler(fetchbot.HandlerFunc(
		func(ctx *fetchbot.Context, res *http.Response, err error) {
			filterMutex.Lock()
			defer filterMutex.Unlock()

			u := res.Request.URL.String()
			if _, found := filter[u]; found {
				return
			}
			filter[u] = struct{}{}

			linksAndNames(domain, ctx, res, links, names)
		}))

	f := fetchbot.New(fetchbot.HandlerFunc(func(ctx *fetchbot.Context, res *http.Response, err error) {
		mux.Handle(ctx, res, err)
	}))
	setFetcherConfig(f)

	q := f.Start()
	u := fmt.Sprintf("%s/%s/%s", base, year, sub)
	if _, err := q.SendStringGet(u); err != nil {
		return results, fmt.Errorf("Crawler error: GET %s - %v", u, err)
	}

	t := time.NewTimer(10 * time.Second)
loop:
	for {
		select {
		case l := <-links:
			if _, ok := linksFilter[l]; ok {
				continue
			}
			linksFilter[l] = struct{}{}
			q.SendStringGet(l)
		case n := <-names:
			results = utils.UniqueAppend(results, n)
		case <-t.C:
			go func() {
				q.Cancel()
			}()
		case <-q.Done():
			break loop
		case <-service.Quit():
			break loop
		}
	}
	return results, nil
}

func linksAndNames(domain string, ctx *fetchbot.Context, res *http.Response, links, names chan string) error {
	// Process the body to find the links
	doc, err := goquery.NewDocumentFromResponse(res)
	if err != nil {
		return fmt.Errorf("crawler error: %s %s - %s", ctx.Cmd.Method(), ctx.Cmd.URL(), err)
	}

	re := utils.SubdomainRegex(domain)
	doc.Find("a[href]").Each(func(i int, s *goquery.Selection) {
		val, _ := s.Attr("href")
		// Resolve address
		u, err := ctx.Cmd.URL().Parse(val)
		if err != nil {
			return
		}

		if sub := re.FindString(u.String()); sub != "" {
			names <- sub
			links <- u.String()
		}
	})
	return nil
}

func setFetcherConfig(f *fetchbot.Fetcher) {
	d := net.Dialer{}
	f.HttpClient = &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			DialContext:           d.DialContext,
			MaxIdleConns:          200,
			IdleConnTimeout:       5 * time.Second,
			TLSHandshakeTimeout:   5 * time.Second,
			ExpectContinueTimeout: 5 * time.Second,
		},
	}
	f.CrawlDelay = 1 * time.Second
	f.DisablePoliteness = true
	f.UserAgent = utils.UserAgent
}
