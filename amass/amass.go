// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package amass

import (
	"bufio"
	"io"
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

// Start begins the DNS enumeration process for the Amass Enumeration object.
func StartEnumeration(e *core.Enumeration) error {
	if err := e.CheckConfig(); err != nil {
		return err
	}
	if e.Config.BruteForcing && len(e.Config.Wordlist) == 0 {
		e.Config.Wordlist, _ = getDefaultWordlist()
	}

	bus := evbus.New()
	bus.SubscribeAsync(core.OUTPUT, e.SendOutput, true)
	// Select the correct services to be used in this enumeration
	services := []core.AmassService{
		NewNameService(e, bus, e.Config),
		NewAddressService(e, bus, e.Config),
	}
	if !e.Config.Passive {
		services = append(services,
			NewDataManagerService(e, bus, e.Config),
			dnssrv.NewDNSService(e, bus, e.Config),
			NewAlterationService(e, bus, e.Config),
			NewBruteForceService(e, bus, e.Config),
			NewActiveCertService(e, bus, e.Config),
		)
	}
	// Grab all the data sources
	services = append(services, sources.GetAllSources(e, bus, e.Config)...)

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
	time.Sleep(time.Second)
	bus.Unsubscribe(core.OUTPUT, e.SendOutput)
	time.Sleep(2 * time.Second)
	close(e.Output)
	return nil
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
