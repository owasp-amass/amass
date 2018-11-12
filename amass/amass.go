// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package amass

import (
	"bufio"
	"errors"
	"io"
	"io/ioutil"
	"log"
	"net"
	"strings"
	"time"

	"github.com/OWASP/Amass/amass/core"
	"github.com/OWASP/Amass/amass/dnssrv"
	"github.com/OWASP/Amass/amass/utils"
	evbus "github.com/asaskevich/EventBus"
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
	Version = "2.8.3"

	// Author is used to display the developer of the amass package.
	Author = "https://github.com/OWASP/Amass"

	defaultWordlistURL = "https://raw.githubusercontent.com/OWASP/Amass/master/wordlists/namelist.txt"
)

// Enumeration is the object type used to execute a DNS enumeration with Amass.
type Enumeration struct {
	// The channel that will receive the results
	Output chan *core.AmassOutput

	// Broadcast channel that indicates no further writes to the output channel
	Done chan struct{}

	// Logger for error messages
	Log *log.Logger

	// The ASNs that the enumeration will target
	ASNs []int

	// The CIDRs that the enumeration will target
	CIDRs []*net.IPNet

	// The IPs that the enumeration will target
	IPs []net.IP

	// The ports that will be checked for certificates
	Ports []int

	// Will whois info be used to add additional domains?
	Whois bool

	// The list of words to use when generating names
	Wordlist []string

	// Will the enumeration including brute forcing techniques
	BruteForcing bool

	// Will recursive brute forcing be performed?
	Recursive bool

	// Minimum number of subdomain discoveries before performing recursive brute forcing
	MinForRecursive int

	// Will discovered subdomain name alterations be generated?
	Alterations bool

	// Indicates a speed band for the enumeration to execute within
	Timing core.EnumerationTiming

	// Only access the data sources for names and return results?
	Passive bool

	// Determines if active information gathering techniques will be used
	Active bool

	// A blacklist of subdomain names that will not be investigated
	Blacklist []string

	// The writer used to save the data operations performed
	DataOptsWriter io.Writer

	// The root domain names that the enumeration will target
	domains []string

	// Pause/Resume channels for halting the enumeration
	pause  chan struct{}
	resume chan struct{}
}

// NewEnumeration returns an initialized Enumeration that has not been started yet.
func NewEnumeration() *Enumeration {
	return &Enumeration{
		Output:          make(chan *core.AmassOutput, 100),
		Done:            make(chan struct{}),
		Log:             log.New(ioutil.Discard, "", 0),
		Ports:           []int{443},
		Recursive:       true,
		MinForRecursive: 1,
		Alterations:     true,
		Timing:          core.Normal,
		pause:           make(chan struct{}),
		resume:          make(chan struct{}),
	}
}

// AddDomain appends another DNS domain name to an Enumeration.
func (e *Enumeration) AddDomain(domain string) {
	e.domains = utils.UniqueAppend(e.domains, domain)
}

// Domains returns the current set of DNS domain names assigned to an Enumeration.
func (e *Enumeration) Domains() []string {
	return e.domains
}

func (e *Enumeration) generateAmassConfig() (*core.AmassConfig, error) {
	if e.Output == nil {
		return nil, errors.New("The configuration did not have an output channel")
	}

	if e.Passive && e.BruteForcing {
		return nil, errors.New("Brute forcing cannot be performed without DNS resolution")
	}

	if e.Passive && e.Active {
		return nil, errors.New("Active enumeration cannot be performed without DNS resolution")
	}

	if e.Passive && e.DataOptsWriter != nil {
		return nil, errors.New("Data operations cannot be saved without DNS resolution")
	}

	if len(e.Ports) == 0 {
		e.Ports = []int{443}
	}

	if e.BruteForcing && len(e.Wordlist) == 0 {
		e.Wordlist, _ = getDefaultWordlist()
	}

	config := &core.AmassConfig{
		Log:             e.Log,
		ASNs:            e.ASNs,
		CIDRs:           e.CIDRs,
		IPs:             e.IPs,
		Ports:           e.Ports,
		Whois:           e.Whois,
		Wordlist:        e.Wordlist,
		BruteForcing:    e.BruteForcing,
		Recursive:       e.Recursive,
		MinForRecursive: e.MinForRecursive,
		Alterations:     e.Alterations,
		Timing:          e.Timing,
		Passive:         e.Passive,
		Active:          e.Active,
		Blacklist:       e.Blacklist,
		DataOptsWriter:  e.DataOptsWriter,
	}
	config.SetGraph(core.NewGraph())
	config.MaxFlow = utils.NewSemaphore(core.TimingToMaxFlow(e.Timing))

	for _, domain := range e.Domains() {
		config.AddDomain(domain)
	}
	return config, nil
}

// Start begins the DNS enumeration process for the Amass Enumeration object.
func (e *Enumeration) Start() error {
	config, err := e.generateAmassConfig()
	if err != nil {
		return err
	}

	bus := evbus.New()
	bus.SubscribeAsync(core.OUTPUT, e.sendOutput, true)

	// Select the correct services to be used in this enumeration
	services := []core.AmassService{
		NewSubdomainService(config, bus),
		NewSourcesService(config, bus),
	}
	if !config.Passive {
		services = append(services,
			NewDataManagerService(config, bus),
			dnssrv.NewDNSService(config, bus),
			NewAlterationService(config, bus),
			NewBruteForceService(config, bus),
			NewActiveCertService(config, bus),
		)
	}

	for _, srv := range services {
		if err := srv.Start(); err != nil {
			return err
		}
	}
	// When done, we want to know if the enumeration completed
	var completed bool
	// Periodically check if all the services have finished
	t := time.NewTicker(3 * time.Second)
loop:
	for {
		select {
		case <-e.Done:
			break loop
		case <-e.pause:
			t.Stop()
		case <-e.resume:
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
				completed = true
				break loop
			}
		}
	}
	t.Stop()
	// Stop all the services
	for _, service := range services {
		service.Stop()
	}
	bus.Unsubscribe(core.OUTPUT, e.sendOutput)
	if completed {
		close(e.Done)
	}
	time.Sleep(2 * time.Second)
	close(e.Output)
	return nil
}

// Pause temporarily halts the DNS enumeration.
func (e *Enumeration) Pause() {
	e.pause <- struct{}{}
}

// Resume causes a previously paused enumeration to resume execution.
func (e *Enumeration) Resume() {
	e.resume <- struct{}{}
}

func (e *Enumeration) sendOutput(out *core.AmassOutput) {
	// Check if the output channel has been closed
	select {
	case <-e.Done:
		return
	default:
		e.Output <- out
	}
}

// ObtainAdditionalDomains discovers and appends DNS domain names related to the current set of names.
func (e *Enumeration) ObtainAdditionalDomains() {
	if e.Whois {
		for _, domain := range e.domains {
			more, err := ReverseWhois(domain)
			if err != nil {
				e.Log.Printf("ReverseWhois error: %v", err)
				continue
			}

			for _, domain := range more {
				e.AddDomain(domain)
			}
		}
	}
}

func getDefaultWordlist() ([]string, error) {
	var list []string
	var wordlist io.Reader

	page, err := utils.GetWebPage(defaultWordlistURL, nil)
	if err != nil {
		return list, err
	}
	wordlist = strings.NewReader(page)

	scanner := bufio.NewScanner(wordlist)
	// Once we have used all the words, we are finished
	for scanner.Scan() {
		// Get the next word in the list
		word := scanner.Text()
		if word != "" {
			// Add the word to the list
			list = append(list, word)
		}
	}
	return list, nil
}
