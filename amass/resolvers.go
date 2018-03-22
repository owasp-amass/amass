// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package amass

import (
	"math/rand"
	"sync"

	"github.com/caffix/recon"
)

// Public & free DNS servers
var knownPublicServers = []string{
	"8.8.8.8:53",        // Google
	"64.6.64.6:53",      // Verisign
	"208.67.222.222:53", // OpenDNS Home
	"198.101.242.72:53", // Alternate DNS
	"77.88.8.8:53",      // Yandex.DNS
	"74.82.42.42:53",    // Hurricane Electric
	"8.8.4.4:53",        // Google Secondary
	"208.67.220.220:53", // OpenDNS Home Secondary
	"77.88.8.1:53",      // Yandex.DNS Secondary
	"37.235.1.174:53",   // FreeDNS
	"37.235.1.177:53",   // FreeDNS Secondary
	"23.253.163.53:53",  // Alternate DNS Secondary
	"64.6.65.6:53",      // Verisign Secondary
	//"9.9.9.9:53",         // Quad9
	//"149.112.112.112:53", // Quad9 Secondary
	//"84.200.69.80:53",    // DNS.WATCH
	//"84.200.70.40:53",    // DNS.WATCH Secondary
	//"8.26.56.26:53",      // Comodo Secure DNS
	//"8.20.247.20:53",     // Comodo Secure DNS Secondary
	//"195.46.39.39:53",    // SafeDNS
	//"195.46.39.40:53",    // SafeDNS Secondary
	//"69.195.152.204:53",  // OpenNIC
	//"216.146.35.35:53",   // Dyn
	//"216.146.36.36:53",   // Dyn Secondary
	//"156.154.70.1:53",    // Neustar
	//"156.154.71.1:53",   // Neustar Secondary
	//"91.239.100.100:53", // UncensoredDNS
	//"89.233.43.71:53",   // UncensoredDNS Secondary
}

var Resolvers *PublicDNSMonitor

type serverStats struct {
	Responding  bool
	NumRequests int
}

func init() {
	Resolvers = NewPublicDNSMonitor()
}

// Checks in real-time if the public DNS servers have become unusable
type PublicDNSMonitor struct {
	sync.Mutex

	// List of servers that we know about
	knownServers []string

	// Tracking for which servers continue to be usable
	usableServers map[string]*serverStats

	// Requests for a server from the queue come here
	nextServer chan chan string
}

func NewPublicDNSMonitor() *PublicDNSMonitor {
	pdm := &PublicDNSMonitor{
		knownServers:  knownPublicServers,
		usableServers: make(map[string]*serverStats),
		nextServer:    make(chan chan string, 100),
	}
	pdm.testAllServers()
	go pdm.processServerQueue()
	return pdm
}

func (pdm *PublicDNSMonitor) testAllServers() {
	for _, server := range pdm.knownServers {
		pdm.testServer(server)
	}
}

func (pdm *PublicDNSMonitor) testServer(server string) bool {
	var resp bool

	_, err := recon.ResolveDNS(pickRandomTestName(), server, "A")
	if err == nil {
		resp = true
	}

	if _, found := pdm.usableServers[server]; !found {
		pdm.usableServers[server] = new(serverStats)
	}

	pdm.usableServers[server].NumRequests = 0
	pdm.usableServers[server].Responding = resp
	return resp
}

func pickRandomTestName() string {
	num := rand.Int()
	names := []string{"google.com", "twitter.com", "linkedin.com",
		"facebook.com", "amazon.com", "github.com", "apple.com"}

	sel := num % len(names)
	return names[sel]
}

func (pdm *PublicDNSMonitor) processServerQueue() {
	var queue []string

	for {
		select {
		case resp := <-pdm.nextServer:
			if len(queue) == 0 {
				queue = pdm.getServerList()
			}
			resp <- queue[0]

			if len(queue) == 1 {
				queue = []string{}
			} else if len(queue) > 1 {
				queue = queue[1:]
			}
		}
	}
}

func (pdm *PublicDNSMonitor) getServerList() []string {
	pdm.Lock()
	defer pdm.Unlock()

	// Check for servers that need to be tested
	for svr, stats := range pdm.usableServers {
		if !stats.Responding {
			continue
		}

		stats.NumRequests++
		if stats.NumRequests%50 == 0 {
			pdm.testServer(svr)
		}
	}

	var servers []string
	// Build the slice of responding servers
	for svr, stats := range pdm.usableServers {
		if stats.Responding {
			servers = append(servers, svr)
		}
	}
	return servers
}

// NextNameserver - Requests the next server
func (pdm *PublicDNSMonitor) NextNameserver() string {
	ans := make(chan string, 2)

	pdm.nextServer <- ans
	return <-ans
}
