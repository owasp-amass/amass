// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package amass

import (
	"testing"
)

const testDomain string = "google.com"

func TestAskSearch(t *testing.T) {
	a := NewAmass()
	s := a.AskSearch()
	finished := make(chan int, 2)

	s.Search(testDomain, finished)
	discovered := <-finished
	if discovered <= 0 {
		t.Errorf("AskSearch found %d subdomains", discovered)
	}
}

func TestBingSearch(t *testing.T) {
	a := NewAmass()
	s := a.BingSearch()
	finished := make(chan int, 2)

	s.Search(testDomain, finished)
	discovered := <-finished
	if discovered <= 0 {
		t.Errorf("BingSearch found %d subdomains", discovered)
	}
}

func TestDogpileSearch(t *testing.T) {
	a := NewAmass()
	s := a.DogpileSearch()
	finished := make(chan int, 2)

	s.Search(testDomain, finished)
	discovered := <-finished
	if discovered <= 0 {
		t.Errorf("DogpileSearch found %d subdomains", discovered)
	}
}

func TestYahooSearch(t *testing.T) {
	a := NewAmass()
	s := a.YahooSearch()
	finished := make(chan int, 2)

	s.Search(testDomain, finished)
	discovered := <-finished
	if discovered <= 0 {
		t.Errorf("YahooSearch found %d subdomains", discovered)
	}
}

func TestCensysSearch(t *testing.T) {
	a := NewAmass()
	s := a.CensysSearch()
	finished := make(chan int, 2)

	s.Search(testDomain, finished)
	discovered := <-finished
	if discovered <= 0 {
		t.Errorf("CensysSearch found %d subdomains", discovered)
	}
}

func TestNetcraftSearch(t *testing.T) {
	a := NewAmass()
	s := a.NetcraftSearch()
	finished := make(chan int, 2)

	s.Search(testDomain, finished)
	discovered := <-finished
	if discovered <= 0 {
		t.Errorf("NetcraftSearch found %d subdomains", discovered)
	}
}

func TestRobtexSearch(t *testing.T) {
	a := NewAmass()
	s := a.RobtexSearch()
	finished := make(chan int, 2)

	s.Search(testDomain, finished)
	discovered := <-finished
	if discovered <= 0 {
		t.Errorf("RobtexSearch found %d subdomains", discovered)
	}
}

func TestVirusTotalSearch(t *testing.T) {
	a := NewAmass()
	s := a.VirusTotalSearch()
	finished := make(chan int, 2)

	s.Search(testDomain, finished)
	discovered := <-finished
	if discovered <= 0 {
		t.Errorf("VirusTotalSearch found %d subdomains", discovered)
	}
}

func TestCrtshSearch(t *testing.T) {
	a := NewAmass()
	s := a.CrtshSearch()
	finished := make(chan int, 2)

	s.Search(testDomain, finished)
	discovered := <-finished
	if discovered <= 0 {
		t.Errorf("CrtshSearch found %d subdomains", discovered)
	}
}
