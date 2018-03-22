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

func TestSearchAsk(t *testing.T) {
	out := make(chan *AmassRequest, 2)
	finished := make(chan int, 2)
	s := AskSearch(out)

	go readOutput(out)
	s.Search(testDomain, finished)
	discovered := <-finished
	if discovered <= 0 {
		t.Errorf("AskSearch found %d subdomains", discovered)
	}
}

func TestSearchBaidu(t *testing.T) {
	out := make(chan *AmassRequest, 2)
	finished := make(chan int, 2)
	s := BaiduSearch(out)

	go readOutput(out)
	s.Search(testDomain, finished)
	discovered := <-finished
	if discovered <= 0 {
		t.Errorf("BaiduSearch found %d subdomains", discovered)
	}
}

func TestSearchBing(t *testing.T) {
	out := make(chan *AmassRequest, 2)
	finished := make(chan int, 2)
	s := BingSearch(out)

	go readOutput(out)
	s.Search(testDomain, finished)
	discovered := <-finished
	if discovered <= 0 {
		t.Errorf("BingSearch found %d subdomains", discovered)
	}
}

func TestSearchDogpile(t *testing.T) {
	out := make(chan *AmassRequest, 2)
	finished := make(chan int, 2)
	s := DogpileSearch(out)

	go readOutput(out)
	s.Search(testDomain, finished)
	discovered := <-finished
	if discovered <= 0 {
		t.Errorf("DogpileSearch found %d subdomains", discovered)
	}
}

func TestSearchGoogle(t *testing.T) {
	out := make(chan *AmassRequest, 2)
	finished := make(chan int, 2)
	s := GoogleSearch(out)

	go readOutput(out)
	s.Search(testDomain, finished)
	discovered := <-finished
	if discovered <= 0 {
		t.Errorf("GoogleSearch found %d subdomains", discovered)
	}
}

func TestSearchYahoo(t *testing.T) {
	out := make(chan *AmassRequest, 2)
	finished := make(chan int, 2)
	s := YahooSearch(out)

	go readOutput(out)
	s.Search(testDomain, finished)
	discovered := <-finished
	if discovered <= 0 {
		t.Errorf("YahooSearch found %d subdomains", discovered)
	}
}

func TestSearchCensys(t *testing.T) {
	out := make(chan *AmassRequest, 2)
	finished := make(chan int, 2)
	s := CensysSearch(out)

	go readOutput(out)
	s.Search(testDomain, finished)
	discovered := <-finished
	if discovered <= 0 {
		t.Errorf("CensysSearch found %d subdomains", discovered)
	}
}

func TestSearchCrtsh(t *testing.T) {
	out := make(chan *AmassRequest, 2)
	finished := make(chan int, 2)
	s := CrtshSearch(out)

	go readOutput(out)
	s.Search(testDomain, finished)
	discovered := <-finished
	if discovered <= 0 {
		t.Errorf("CrtshSearch found %d subdomains", discovered)
	}
}

func TestSearchNetcraft(t *testing.T) {
	out := make(chan *AmassRequest, 2)
	finished := make(chan int, 2)
	s := NetcraftSearch(out)

	go readOutput(out)
	s.Search(testDomain, finished)
	discovered := <-finished
	if discovered <= 0 {
		t.Errorf("NetcraftSearch found %d subdomains", discovered)
	}
}

func TestSearchRobtex(t *testing.T) {
	out := make(chan *AmassRequest, 2)
	finished := make(chan int, 2)
	s := RobtexSearch(out)

	go readOutput(out)
	s.Search(testDomain, finished)
	discovered := <-finished
	if discovered <= 0 {
		t.Errorf("RobtexSearch found %d subdomains", discovered)
	}
}

func TestSearchThreatCrowd(t *testing.T) {
	out := make(chan *AmassRequest, 2)
	finished := make(chan int, 2)
	s := ThreatCrowdSearch(out)

	go readOutput(out)
	s.Search(testDomain, finished)
	discovered := <-finished
	if discovered <= 0 {
		t.Errorf("ThreatCrowdSearch found %d subdomains", discovered)
	}
}

func TestSearchVirusTotal(t *testing.T) {
	out := make(chan *AmassRequest, 2)
	finished := make(chan int, 2)
	s := VirusTotalSearch(out)

	go readOutput(out)
	s.Search(testDomain, finished)
	discovered := <-finished
	if discovered <= 0 {
		t.Errorf("VirusTotalSearch found %d subdomains", discovered)
	}
}

func TestSearchDNSDumpster(t *testing.T) {
	out := make(chan *AmassRequest, 2)
	finished := make(chan int, 2)
	s := DNSDumpsterSearch(out)

	go readOutput(out)
	s.Search(testDomain, finished)
	discovered := <-finished
	if discovered <= 0 {
		t.Errorf("DNSDumpsterSearch found %d subdomains", discovered)
	}
}
