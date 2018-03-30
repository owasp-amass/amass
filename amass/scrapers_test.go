// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package amass

import (
	"testing"
)

const (
	testDomain string = "utica.edu"
	testIP     string = "72.237.4.113"
)

func TestScraperAsk(t *testing.T) {
	out := make(chan *AmassRequest, 2)
	finished := make(chan int, 2)
	config := DefaultConfig()
	config.Setup()

	s := AskSearch(out, config)

	go readOutput(out)
	s.Scrape(testDomain, finished)
	discovered := <-finished
	if discovered <= 0 {
		t.Errorf("AskSearch found %d subdomains", discovered)
	}
}

func TestScraperBaidu(t *testing.T) {
	out := make(chan *AmassRequest, 2)
	finished := make(chan int, 2)
	config := DefaultConfig()
	config.Setup()

	s := BaiduSearch(out, config)

	go readOutput(out)
	s.Scrape(testDomain, finished)
	discovered := <-finished
	if discovered <= 0 {
		t.Errorf("BaiduSearch found %d subdomains", discovered)
	}
}

func TestScraperBing(t *testing.T) {
	out := make(chan *AmassRequest, 2)
	finished := make(chan int, 2)
	config := DefaultConfig()
	config.Setup()

	s := BingSearch(out, config)

	go readOutput(out)
	s.Scrape(testDomain, finished)
	discovered := <-finished
	if discovered <= 0 {
		t.Errorf("BingSearch found %d subdomains", discovered)
	}
}

func TestScraperDogpile(t *testing.T) {
	out := make(chan *AmassRequest, 2)
	finished := make(chan int, 2)
	config := DefaultConfig()
	config.Setup()

	s := DogpileSearch(out, config)

	go readOutput(out)
	s.Scrape(testDomain, finished)
	discovered := <-finished
	if discovered <= 0 {
		t.Errorf("DogpileSearch found %d subdomains", discovered)
	}
}

func TestScraperGoogle(t *testing.T) {
	out := make(chan *AmassRequest, 2)
	finished := make(chan int, 2)
	config := DefaultConfig()
	config.Setup()

	s := GoogleSearch(out, config)

	go readOutput(out)
	s.Scrape(testDomain, finished)
	discovered := <-finished
	if discovered <= 0 {
		t.Errorf("GoogleSearch found %d subdomains", discovered)
	}
}

func TestScraperYahoo(t *testing.T) {
	out := make(chan *AmassRequest, 2)
	finished := make(chan int, 2)
	config := DefaultConfig()
	config.Setup()

	s := YahooSearch(out, config)

	go readOutput(out)
	s.Scrape(testDomain, finished)
	discovered := <-finished
	if discovered <= 0 {
		t.Errorf("YahooSearch found %d subdomains", discovered)
	}
}

func TestScraperCensys(t *testing.T) {
	out := make(chan *AmassRequest, 2)
	finished := make(chan int, 2)
	config := DefaultConfig()
	config.Setup()

	s := CensysSearch(out, config)

	go readOutput(out)
	s.Scrape(testDomain, finished)
	discovered := <-finished
	if discovered <= 0 {
		t.Errorf("CensysSearch found %d subdomains", discovered)
	}
}

func TestScraperCrtsh(t *testing.T) {
	out := make(chan *AmassRequest, 2)
	finished := make(chan int, 2)
	config := DefaultConfig()
	config.Setup()

	s := CrtshSearch(out, config)

	go readOutput(out)
	s.Scrape(testDomain, finished)
	discovered := <-finished
	if discovered <= 0 {
		t.Errorf("CrtshSearch found %d subdomains", discovered)
	}
}

func TestScraperNetcraft(t *testing.T) {
	out := make(chan *AmassRequest, 2)
	finished := make(chan int, 2)
	config := DefaultConfig()
	config.Setup()

	s := NetcraftSearch(out, config)

	go readOutput(out)
	s.Scrape(testDomain, finished)
	discovered := <-finished
	if discovered <= 0 {
		t.Errorf("NetcraftSearch found %d subdomains", discovered)
	}
}

func TestScraperRobtex(t *testing.T) {
	out := make(chan *AmassRequest, 2)
	finished := make(chan int, 2)
	config := DefaultConfig()
	config.Setup()

	s := RobtexSearch(out, config)

	go readOutput(out)
	s.Scrape(testDomain, finished)
	discovered := <-finished
	if discovered <= 0 {
		t.Errorf("RobtexSearch found %d subdomains", discovered)
	}
}

func TestScraperThreatCrowd(t *testing.T) {
	out := make(chan *AmassRequest, 2)
	finished := make(chan int, 2)
	config := DefaultConfig()
	config.Setup()

	s := ThreatCrowdSearch(out, config)

	go readOutput(out)
	s.Scrape(testDomain, finished)
	discovered := <-finished
	if discovered <= 0 {
		t.Errorf("ThreatCrowdSearch found %d subdomains", discovered)
	}
}

func TestScraperVirusTotal(t *testing.T) {
	out := make(chan *AmassRequest, 2)
	finished := make(chan int, 2)
	config := DefaultConfig()
	config.Setup()

	s := VirusTotalSearch(out, config)

	go readOutput(out)
	s.Scrape(testDomain, finished)
	discovered := <-finished
	if discovered <= 0 {
		t.Errorf("VirusTotalSearch found %d subdomains", discovered)
	}
}

func TestScraperDNSDumpster(t *testing.T) {
	out := make(chan *AmassRequest, 2)
	finished := make(chan int, 2)
	config := DefaultConfig()
	config.Setup()

	s := DNSDumpsterSearch(out, config)

	go readOutput(out)
	s.Scrape(testDomain, finished)
	discovered := <-finished
	if discovered <= 0 {
		t.Errorf("DNSDumpsterSearch found %d subdomains", discovered)
	}
}

func readOutput(out chan *AmassRequest) {
	for {
		<-out
	}
}
