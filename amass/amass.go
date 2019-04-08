// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package amass

import (
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"strconv"
	"sync"
	"time"

	"github.com/OWASP/Amass/amass/core"
	"github.com/OWASP/Amass/amass/handlers"
	"github.com/OWASP/Amass/amass/sources"
	"github.com/OWASP/Amass/amass/utils"
	"github.com/fatih/color"
	"github.com/google/uuid"
)

var (
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
	Version = "2.9.4"

	// Author is used to display the founder of the amass package.
	Author = "Jeff Foley - @jeff_foley"
)

// Enumeration is the object type used to execute a DNS enumeration with Amass.
type Enumeration struct {
	Config *core.Config

	Bus *core.EventBus

	// Link graph that collects all the information gathered by the enumeration
	Graph handlers.DataHandler

	// The channel that will receive the results
	Output chan *core.Output

	// Broadcast channel that indicates no further writes to the output channel
	Done chan struct{}

	dataSources []core.Service
	bruteSrv    core.Service

	// Pause/Resume channels for halting the enumeration
	pause  chan struct{}
	resume chan struct{}

	filter      *utils.StringFilter
	outputQueue *utils.Queue

	metricsLock       sync.RWMutex
	dnsQueriesPerSec  int
	dnsNamesRemaining int
}

// NewEnumeration returns an initialized Enumeration that has not been started yet.
func NewEnumeration() *Enumeration {
	e := &Enumeration{
		Config: &core.Config{
			UUID:           uuid.New(),
			Log:            log.New(ioutil.Discard, "", 0),
			MaxDNSQueries:  1000,
			Alterations:    true,
			FlipWords:      true,
			FlipNumbers:    true,
			AddWords:       true,
			AddNumbers:     true,
			MinForWordFlip: 2,
			EditDistance:   1,
			Recursive:      true,
		},
		Bus:         core.NewEventBus(),
		Output:      make(chan *core.Output, 100),
		Done:        make(chan struct{}, 2),
		pause:       make(chan struct{}, 2),
		resume:      make(chan struct{}, 2),
		filter:      utils.NewStringFilter(),
		outputQueue: utils.NewQueue(),
	}
	e.dataSources = sources.GetAllSources(e.Config, e.Bus)
	return e
}

// Start begins the DNS enumeration process for the Amass Enumeration object.
func (e *Enumeration) Start() error {
	if e.Output == nil {
		return errors.New("The enumeration did not have an output channel")
	} else if e.Config.Passive && e.Config.DataOptsWriter != nil {
		return errors.New("Data operations cannot be saved without DNS resolution")
	} else if err := e.Config.CheckSettings(); err != nil {
		return err
	}
	// Select the graph that will store the enumeration findings
	if e.Config.GremlinURL != "" {
		gremlin := handlers.NewGremlin(e.Config.GremlinURL,
			e.Config.GremlinUser, e.Config.GremlinPass, e.Config.Log)
		e.Graph = gremlin
		defer gremlin.Close()
	} else {
		graph := handlers.NewGraph(e.Config.Dir)
		if graph == nil {
			return errors.New("Failed to create the graph")
		}
		e.Graph = graph
		defer graph.Close()
	}

	e.Bus.Subscribe(core.OutputTopic, e.sendOutput)

	if len(e.Config.DisabledDataSources) > 0 {
		e.dataSources = e.Config.ExcludeDisabledDataSources(e.dataSources)
	}

	// Select the correct services to be used in this enumeration
	var services []core.Service
	if !e.Config.Passive {
		dms := NewDataManagerService(e.Config, e.Bus)
		dms.AddDataHandler(e.Graph)
		if e.Config.DataOptsWriter != nil {
			dms.AddDataHandler(handlers.NewDataOptsHandler(e.Config.DataOptsWriter))
		}
		services = append(services, NewDNSService(e.Config, e.Bus),
			dms, NewActiveCertService(e.Config, e.Bus))
	}

	namesrv := NewNameService(e.Config, e.Bus)
	namesrv.RegisterGraph(e.Graph)
	services = append(services, namesrv, NewAddressService(e.Config, e.Bus))
	if !e.Config.Passive {
		e.bruteSrv = NewBruteForceService(e.Config, e.Bus)
		services = append(services, e.bruteSrv,
			NewMarkovService(e.Config, e.Bus), NewAlterationService(e.Config, e.Bus))
	}

	// Grab all the data sources
	services = append(services, e.dataSources...)
	for _, srv := range services {
		if err := srv.Start(); err != nil {
			return err
		}
	}

	// Use all previously discovered names that are in scope
	go e.submitKnownNames()
	// Start with the first domain name provided by the configuration
	var domainIdx int
	e.releaseDomainName(domainIdx)

	var wg sync.WaitGroup
	wg.Add(2)
	go e.checkForOutput(&wg)
	go e.processOutput(&wg)

	t := time.NewTicker(time.Duration(3) * time.Second)
	logTick := time.NewTicker(time.Minute)
	defer logTick.Stop()
loop:
	for {
		select {
		case <-e.Done:
			break loop
		case <-e.PauseChan():
			t.Stop()
		case <-e.ResumeChan():
			t = time.NewTicker(time.Duration(3) * time.Second)
		case <-logTick.C:
			if !e.Config.Passive {
				e.Config.Log.Printf("Average DNS queries performed: %d/sec, DNS names remaining: %d",
					e.DNSQueriesPerSec(), e.DNSNamesRemaining())
			}
		case <-t.C:
			done := true
			for _, srv := range services {
				if srv.IsActive() {
					done = false
					break
				}
			}
			if done {
				close(e.Done)
				continue loop
			}

			if !e.Config.Passive {
				e.processMetrics(services)
				psec := e.DNSQueriesPerSec()
				// Check if it's too soon to release the next domain name
				if psec > 0 && ((e.DNSNamesRemaining()*len(InitialQueryTypes))/psec) > 10 {
					continue loop
				}
				// Let the services know that the enumeration is ready for more names
				for _, srv := range services {
					go srv.LowNumberOfNames()
				}
			}
			// Check if the next domain should be sent to data sources/brute forcing
			domainIdx++
			e.releaseDomainName(domainIdx)
		}
	}
	t.Stop()
	for _, srv := range services {
		srv.Stop()
	}
	wg.Wait()
	return nil
}

func (e *Enumeration) releaseDomainName(idx int) {
	domains := e.Config.Domains()

	if idx >= len(domains) {
		return
	}

	for _, srv := range append(e.dataSources, e.bruteSrv) {
		if srv == nil {
			continue
		}

		srv.SendRequest(&core.Request{
			Name:   domains[idx],
			Domain: domains[idx],
		})
	}
}

func (e *Enumeration) submitKnownNames() {
	for _, enum := range e.Graph.EnumerationList() {
		var found bool

		for _, domain := range e.Graph.EnumerationDomains(enum) {
			if e.Config.IsDomainInScope(domain) {
				found = true
				break
			}
		}
		if !found {
			continue
		}

		for _, o := range e.Graph.GetOutput(enum, true) {
			if e.Config.IsDomainInScope(o.Name) {
				e.Bus.Publish(core.NewNameTopic, &core.Request{
					Name:   o.Name,
					Domain: o.Domain,
					Tag:    o.Tag,
					Source: o.Source,
				})
			}
		}
	}
}

// DNSQueriesPerSec returns the number of DNS queries the enumeration has performed per second.
func (e *Enumeration) DNSQueriesPerSec() int {
	e.metricsLock.RLock()
	defer e.metricsLock.RUnlock()

	return e.dnsQueriesPerSec
}

// DNSNamesRemaining returns the number of discovered DNS names yet to be handled by the enumeration.
func (e *Enumeration) DNSNamesRemaining() int {
	e.metricsLock.RLock()
	defer e.metricsLock.RUnlock()

	return e.dnsNamesRemaining
}

func (e *Enumeration) processMetrics(services []core.Service) {
	var total, remaining int
	for _, srv := range services {
		stats := srv.Stats()

		remaining += stats.NamesRemaining
		total += stats.DNSQueriesPerSec
	}

	e.metricsLock.Lock()
	e.dnsQueriesPerSec = total
	e.dnsNamesRemaining = remaining
	e.metricsLock.Unlock()
}

func (e *Enumeration) processOutput(wg *sync.WaitGroup) {
	defer wg.Done()

	curIdx := 0
	maxIdx := 7
	delays := []int{250, 500, 750, 1000, 1250, 1500, 1750, 2000}
loop:
	for {
		select {
		case <-e.Done:
			break loop
		default:
			element, ok := e.outputQueue.Next()
			if !ok {
				if curIdx < maxIdx {
					curIdx++
				}
				time.Sleep(time.Duration(delays[curIdx]) * time.Millisecond)
				continue
			}
			curIdx = 0
			output := element.(*core.Output)
			if !e.filter.Duplicate(output.Name) {
				e.Output <- output
			}
		}
	}
	time.Sleep(5 * time.Second)
	// Handle all remaining elements on the queue
	for {
		element, ok := e.outputQueue.Next()
		if !ok {
			break
		}
		output := element.(*core.Output)
		if !e.filter.Duplicate(output.Name) {
			e.Output <- output
		}
	}
	close(e.Output)
}

func (e *Enumeration) checkForOutput(wg *sync.WaitGroup) {
	t := time.NewTicker(5 * time.Second)
	defer t.Stop()
	defer wg.Done()
loop:
	for {
		select {
		case <-e.Done:
			break loop
		case <-t.C:
			out := e.Graph.GetOutput(e.Config.UUID.String(), false)
			for _, o := range out {
				if time.Now().Add(10 * time.Second).After(o.Timestamp) {
					e.Graph.MarkAsRead(&handlers.DataOptsParams{
						UUID:   e.Config.UUID.String(),
						Name:   o.Name,
						Domain: o.Domain,
					})

					if e.Config.IsDomainInScope(o.Name) {
						e.outputQueue.Append(o)
					}
				}
			}
		}
	}
	// Handle all remaining pieces of output
	out := e.Graph.GetOutput(e.Config.UUID.String(), false)
	for _, o := range out {
		if !e.filter.Duplicate(o.Name) {
			e.Graph.MarkAsRead(&handlers.DataOptsParams{
				UUID:   e.Config.UUID.String(),
				Name:   o.Name,
				Domain: o.Domain,
			})

			if e.Config.IsDomainInScope(o.Name) {
				e.outputQueue.Append(o)
			}
		}
	}
}

func (e *Enumeration) sendOutput(o *core.Output) {
	select {
	case <-e.Done:
		return
	default:
		if e.Config.IsDomainInScope(o.Name) {
			e.outputQueue.Append(o)
		}
	}
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

// TrustedTag returns true when the tag parameter is of a type that should be trusted even
// facing DNS wildcards.
func TrustedTag(tag string) bool {
	if tag == core.DNS || tag == core.CERT || tag == core.ARCHIVE || tag == core.AXFR {
		return true
	}
	return false
}

// GetAllSourceNames returns the names of all the available data sources.
func (e *Enumeration) GetAllSourceNames() []string {
	var names []string

	for _, source := range e.dataSources {
		names = append(names, source.String())
	}
	return names
}

// ASNSummaryData stores information related to discovered ASs and netblocks.
type ASNSummaryData struct {
	Name      string
	Netblocks map[string]int
}

// UpdateSummaryData updates the summary maps using the provided core.Output data
func UpdateSummaryData(output *core.Output, tags map[string]int, asns map[int]*ASNSummaryData) {
	tags[output.Tag]++

	for _, addr := range output.Addresses {
		data, found := asns[addr.ASN]
		if !found {
			asns[addr.ASN] = &ASNSummaryData{
				Name:      addr.Description,
				Netblocks: make(map[string]int),
			}
			data = asns[addr.ASN]
		}
		// Increment how many IPs were in this netblock
		data.Netblocks[addr.Netblock.String()]++
	}
}

// PrintEnumerationSummary outputs the summary information utilized by the command-line tools.
func PrintEnumerationSummary(total int, tags map[string]int, asns map[int]*ASNSummaryData) {
	pad := func(num int, chr string) {
		for i := 0; i < num; i++ {
			b.Fprint(color.Error, chr)
		}
	}

	fmt.Fprintln(color.Error)
	// Print the header information
	title := "OWASP Amass v"
	site := "https://github.com/OWASP/Amass"
	b.Fprint(color.Error, title+Version)
	num := 80 - (len(title) + len(Version) + len(site))
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

// PrintBanner outputs the Amass banner the same for all tools.
func PrintBanner() {
	y := color.New(color.FgHiYellow)
	r := color.New(color.FgHiRed)
	rightmost := 76
	version := "Version " + Version
	desc := "In-depth DNS Enumeration and Network Mapping"
	author := "Authored By " + Author

	pad := func(num int) {
		for i := 0; i < num; i++ {
			fmt.Fprint(color.Error, " ")
		}
	}
	r.Fprintln(color.Error, Banner)
	pad(rightmost - len(version))
	y.Fprintln(color.Error, version)
	pad(rightmost - len(author))
	y.Fprintln(color.Error, author)
	pad(rightmost - len(desc))
	y.Fprintf(color.Error, "%s\n\n\n", desc)
}

// OutputLineParts returns the parts of a line to be printed for a core.Output.
func OutputLineParts(out *core.Output, src, addrs bool) (source, name, ips string) {
	if src {
		source = fmt.Sprintf("%-18s", "["+out.Source+"] ")
	}
	if addrs {
		for i, a := range out.Addresses {
			if i != 0 {
				ips += ","
			}
			ips += a.Address.String()
		}
		if ips == "" {
			ips = "N/A"
		}
	}
	name = out.Name
	return
}
