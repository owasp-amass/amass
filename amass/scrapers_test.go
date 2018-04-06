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

	s := AskScrape(out, config)

	go readOutput(out)
	s.Scrape(testDomain, finished)
	discovered := <-finished
	if discovered <= 0 {
		t.Errorf("AskScrape found %d subdomains", discovered)
	}
}

func TestScraperBaidu(t *testing.T) {
	out := make(chan *AmassRequest, 2)
	finished := make(chan int, 2)
	config := DefaultConfig()
	config.Setup()

	s := BaiduScrape(out, config)

	go readOutput(out)
	s.Scrape(testDomain, finished)
	discovered := <-finished
	if discovered <= 0 {
		t.Errorf("BaiduScrape found %d subdomains", discovered)
	}
}

func TestScraperBing(t *testing.T) {
	out := make(chan *AmassRequest, 2)
	finished := make(chan int, 2)
	config := DefaultConfig()
	config.Setup()

	s := BingScrape(out, config)

	go readOutput(out)
	s.Scrape(testDomain, finished)
	discovered := <-finished
	if discovered <= 0 {
		t.Errorf("BingScrape found %d subdomains", discovered)
	}
}

func TestScraperDogpile(t *testing.T) {
	out := make(chan *AmassRequest, 2)
	finished := make(chan int, 2)
	config := DefaultConfig()
	config.Setup()

	s := DogpileScrape(out, config)

	go readOutput(out)
	s.Scrape(testDomain, finished)
	discovered := <-finished
	if discovered <= 0 {
		t.Errorf("DogpileScrape found %d subdomains", discovered)
	}
}

func TestScraperGoogle(t *testing.T) {
	out := make(chan *AmassRequest, 2)
	finished := make(chan int, 2)
	config := DefaultConfig()
	config.Setup()

	s := GoogleScrape(out, config)

	go readOutput(out)
	s.Scrape(testDomain, finished)
	discovered := <-finished
	if discovered <= 0 {
		t.Errorf("GoogleScrape found %d subdomains", discovered)
	}
}

func TestScraperYahoo(t *testing.T) {
	out := make(chan *AmassRequest, 2)
	finished := make(chan int, 2)
	config := DefaultConfig()
	config.Setup()

	s := YahooScrape(out, config)

	go readOutput(out)
	s.Scrape(testDomain, finished)
	discovered := <-finished
	if discovered <= 0 {
		t.Errorf("YahooScrape found %d subdomains", discovered)
	}
}

func TestScraperCensys(t *testing.T) {
	out := make(chan *AmassRequest, 2)
	finished := make(chan int, 2)
	config := DefaultConfig()
	config.Setup()

	s := CensysScrape(out, config)

	go readOutput(out)
	s.Scrape(testDomain, finished)
	discovered := <-finished
	if discovered <= 0 {
		t.Errorf("CensysScrape found %d subdomains", discovered)
	}
}

func TestScraperCertDB(t *testing.T) {
	out := make(chan *AmassRequest, 2)
	finished := make(chan int, 2)
	config := DefaultConfig()
	config.Setup()

	s := CertDBScrape(out, config)

	go readOutput(out)
	s.Scrape(testDomain, finished)
	discovered := <-finished
	if discovered <= 0 {
		t.Errorf("CertDBScrape found %d subdomains", discovered)
	}
}

func TestScraperFindSubDomains(t *testing.T) {
	out := make(chan *AmassRequest, 2)
	finished := make(chan int, 2)
	config := DefaultConfig()
	config.Setup()

	s := FindSubDomainsScrape(out, config)

	go readOutput(out)
	s.Scrape(testDomain, finished)
	discovered := <-finished
	if discovered <= 0 {
		t.Errorf("FindSubDomainsScrape found %d subdomains", discovered)
	}
}

func TestScraperHackerTarget(t *testing.T) {
	out := make(chan *AmassRequest, 2)
	finished := make(chan int, 2)
	config := DefaultConfig()
	config.Setup()

	s := HackerTargetScrape(out, config)

	go readOutput(out)
	s.Scrape(testDomain, finished)
	discovered := <-finished
	if discovered <= 0 {
		t.Errorf("HackerTargetScrape found %d subdomains", discovered)
	}
}

func TestScraperCrtsh(t *testing.T) {
	out := make(chan *AmassRequest, 2)
	finished := make(chan int, 2)
	config := DefaultConfig()
	config.Setup()

	s := CrtshScrape(out, config)

	go readOutput(out)
	s.Scrape(testDomain, finished)
	discovered := <-finished
	if discovered <= 0 {
		t.Errorf("CrtshScrape found %d subdomains", discovered)
	}
}

func TestScraperNetcraft(t *testing.T) {
	out := make(chan *AmassRequest, 2)
	finished := make(chan int, 2)
	config := DefaultConfig()
	config.Setup()

	s := NetcraftScrape(out, config)

	go readOutput(out)
	s.Scrape(testDomain, finished)
	discovered := <-finished
	if discovered <= 0 {
		t.Errorf("NetcraftScrape found %d subdomains", discovered)
	}
}

func TestScraperPTRArchive(t *testing.T) {
	out := make(chan *AmassRequest, 2)
	finished := make(chan int, 2)
	config := DefaultConfig()
	config.Setup()

	s := PTRArchiveScrape(out, config)

	go readOutput(out)
	s.Scrape(testDomain, finished)
	discovered := <-finished
	if discovered <= 0 {
		t.Errorf("PTRArchiveScrape found %d subdomains", discovered)
	}
}

func TestScraperRobtex(t *testing.T) {
	out := make(chan *AmassRequest, 2)
	finished := make(chan int, 2)
	config := DefaultConfig()
	config.Setup()

	s := RobtexScrape(out, config)

	go readOutput(out)
	s.Scrape(testDomain, finished)
	discovered := <-finished
	if discovered <= 0 {
		t.Errorf("RobtexScrape found %d subdomains", discovered)
	}
}

func TestScraperThreatCrowd(t *testing.T) {
	out := make(chan *AmassRequest, 2)
	finished := make(chan int, 2)
	config := DefaultConfig()
	config.Setup()

	s := ThreatCrowdScrape(out, config)

	go readOutput(out)
	s.Scrape(testDomain, finished)
	discovered := <-finished
	if discovered <= 0 {
		t.Errorf("ThreatCrowdScrape found %d subdomains", discovered)
	}
}

func TestScraperVirusTotal(t *testing.T) {
	out := make(chan *AmassRequest, 2)
	finished := make(chan int, 2)
	config := DefaultConfig()
	config.Setup()

	s := VirusTotalScrape(out, config)

	go readOutput(out)
	s.Scrape(testDomain, finished)
	discovered := <-finished
	if discovered <= 0 {
		t.Errorf("VirusTotalScrape found %d subdomains", discovered)
	}
}

func TestScraperDNSDumpster(t *testing.T) {
	out := make(chan *AmassRequest, 2)
	finished := make(chan int, 2)
	config := DefaultConfig()
	config.Setup()

	s := DNSDumpsterScrape(out, config)

	go readOutput(out)
	s.Scrape(testDomain, finished)
	discovered := <-finished
	if discovered <= 0 {
		t.Errorf("DNSDumpsterScrape found %d subdomains", discovered)
	}
}

func readOutput(out chan *AmassRequest) {
	for {
		<-out
	}
}
