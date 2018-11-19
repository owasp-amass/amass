// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package amass

import (
	"bufio"
	"errors"
	"io"
	"io/ioutil"
	"log"
	"strings"
	"time"

	"github.com/OWASP/Amass/amass/core"
	"github.com/OWASP/Amass/amass/dnssrv"
	"github.com/OWASP/Amass/amass/sources"
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

	// Author is used to display the founder of the amass package.
	Author = "Jeff Foley - @jeff_foley"

	defaultWordlistURL = "https://raw.githubusercontent.com/OWASP/Amass/master/wordlists/namelist.txt"
)

// Enumeration is the object type used to execute a DNS enumeration with Amass.
type Enumeration struct {
	// The channel that will receive the results
	Output chan *core.AmassOutput

	// Broadcast channel that indicates no further writes to the output channel
	Done chan struct{}

	Config *core.AmassConfig

	// Pause/Resume channels for halting the enumeration
	pause  chan struct{}
	resume chan struct{}
}

// NewEnumeration returns an initialized Enumeration that has not been started yet.
func NewEnumeration() *Enumeration {
	enum := &Enumeration{
		Output: make(chan *core.AmassOutput, 100),
		Done:   make(chan struct{}),
		Config: &core.AmassConfig{
			Log:             log.New(ioutil.Discard, "", 0),
			Ports:           []int{443},
			Recursive:       true,
			MinForRecursive: 1,
			Alterations:     true,
			Timing:          core.Normal,
		},
		pause:  make(chan struct{}),
		resume: make(chan struct{}),
	}
	enum.Config.SetGraph(core.NewGraph())
	return enum
}

func (e *Enumeration) checkConfig() error {
	if e.Output == nil {
		return errors.New("The configuration did not have an output channel")
	}
	if e.Config.Passive && e.Config.BruteForcing {
		return errors.New("Brute forcing cannot be performed without DNS resolution")
	}
	if e.Config.Passive && e.Config.Active {
		return errors.New("Active enumeration cannot be performed without DNS resolution")
	}
	if e.Config.Passive && e.Config.DataOptsWriter != nil {
		return errors.New("Data operations cannot be saved without DNS resolution")
	}
	if len(e.Config.Ports) == 0 {
		e.Config.Ports = []int{443}
	}
	if e.Config.BruteForcing && len(e.Config.Wordlist) == 0 {
		e.Config.Wordlist, _ = getDefaultWordlist()
	}
	e.Config.MaxFlow = utils.NewSemaphore(core.TimingToMaxFlow(e.Config.Timing))
	return nil
}

// Start begins the DNS enumeration process for the Amass Enumeration object.
func (e *Enumeration) Start() error {
	if err := e.checkConfig(); err != nil {
		return err
	}

	bus := evbus.New()
	bus.SubscribeAsync(core.OUTPUT, e.sendOutput, true)
	// Select the correct services to be used in this enumeration
	services := []core.AmassService{
		NewNameService(bus, e.Config),
		NewAddressService(bus, e.Config),
	}
	if !e.Config.Passive {
		services = append(services,
			NewDataManagerService(bus, e.Config),
			dnssrv.NewDNSService(bus, e.Config),
			NewAlterationService(bus, e.Config),
			NewBruteForceService(bus, e.Config),
			NewActiveCertService(bus, e.Config),
		)
	}
	// Grab all the data sources
	services = append(services, sources.GetAllSources(bus, e.Config)...)

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
				break loop
			}
		}
	}
	t.Stop()
	for _, srv := range services {
		srv.Stop()
	}
	time.Sleep(time.Second)
	bus.Unsubscribe(core.OUTPUT, e.sendOutput)
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
	e.Output <- out
}

func getDefaultWordlist() ([]string, error) {
	var list []string
	var wordlist io.Reader

	page, err := utils.RequestWebPage(defaultWordlistURL, nil, nil, "", "")
	if err != nil {
		return list, err
	}
	wordlist = strings.NewReader(page)

	scanner := bufio.NewScanner(wordlist)
	// Once we have used all the words, we are finished
	for scanner.Scan() {
		// Get the next word in the list
		word := scanner.Text()
		if err := scanner.Err(); err == nil && word != "" {
			list = utils.UniqueAppend(list, word)
		}
	}
	return list, nil
}
