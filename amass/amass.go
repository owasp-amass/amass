// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package amass

import (
	"io"
	"io/ioutil"
	"log"
	"net"
	"os"
	"sync"
	"time"
	"bufio"
	"errors"
	"strings"

	"github.com/OWASP/Amass/amass/core"
	"github.com/OWASP/Amass/amass/dnssrv"
	"github.com/OWASP/Amass/amass/handlers"
	"github.com/OWASP/Amass/amass/utils"
	"github.com/OWASP/Amass/amass/utils/viz"
	evbus "github.com/asaskevich/EventBus"
)

const (
	Version string = "v2.5.0"
	Author  string = "Jeff Foley (@jeff_foley)"

	DefaultFrequency time.Duration = 10 * time.Millisecond
	defaultWordlistURL = "https://raw.githubusercontent.com/OWASP/Amass/master/wordlists/namelist.txt"
)

type AmassAddressInfo struct {
	Address     net.IP
	Netblock    *net.IPNet
	ASN         int
	Description string
}

type AmassOutput struct {
	Name      string
	Domain    string
	Addresses []AmassAddressInfo
	Tag       string
	Source    string
	Type      int
}

type Enumeration struct {
	// The channel that will receive the results
	Output chan *AmassOutput

	// Graph built from the data collected
	Graph *handlers.Graph

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

	// Only access the data sources for names and return results?
	NoDNS bool

	// Determines if active information gathering techniques will be used
	Active bool

	// A blacklist of subdomain names that will not be investigated
	Blacklist []string

	// Sets the maximum number of DNS queries per minute
	Frequency time.Duration

	// Preferred DNS resolvers identified by the user
	Resolvers []string

	// The Neo4j URL used by the bolt driver to connect with the database
	Neo4jPath string

	// The root domain names that the enumeration will target
	domains []string
}

func NewEnumeration() *Enumeration {
	return &Enumeration{
		Output:          make(chan *AmassOutput, 100),
		Log:             log.New(ioutil.Discard, "", 0),
		Ports:           []int{80, 443},
		Recursive:       true,
		Alterations:     true,
		Frequency:       10 * time.Millisecond,
		MinForRecursive: 1,
	}
}

func (e *Enumeration) AddDomain(domain string) {
	e.domains = utils.UniqueAppend(e.domains, domain)
}

func (e *Enumeration) Domains() []string {
	return e.domains
}

func (e *Enumeration) generateAmassConfig() (*core.AmassConfig, error) {
	if e.Output == nil {
		return nil, errors.New("The configuration did not have an output channel")
	}

	if e.NoDNS && e.BruteForcing {
		return nil, errors.New("Brute forcing cannot be performed without DNS resolution")
	}

	if e.NoDNS && e.Active {
		return nil, errors.New("Active enumeration cannot be performed without DNS resolution")
	}

	if e.Frequency < DefaultFrequency {
		return nil, errors.New("The configuration contains a invalid frequency")
	}

	if e.NoDNS && e.Neo4jPath != "" {
		return nil, errors.New("Data cannot be provided to Neo4j without DNS resolution")
	}

	if len(e.Ports) == 0 {
		e.Ports = []int{80, 443}
	}

	if e.BruteForcing && len(e.Wordlist) == 0 {
		e.Wordlist, _ = getDefaultWordlist()
	}

	config := &core.AmassConfig{
		Log: e.Log,
		ASNs: e.ASNs,
		CIDRs: e.CIDRs,
		IPs: e.IPs,
		Ports: e.Ports,
		Whois: e.Whois,
		Wordlist: e.Wordlist,
		BruteForcing: e.BruteForcing,
		Recursive: e.Recursive,
		MinForRecursive: e.MinForRecursive,
		Alterations: e.Alterations,
		NoDNS: e.NoDNS,
		Active: e.Active,
		Blacklist: e.Blacklist,
		Frequency: e.Frequency,
		Resolvers: e.Resolvers,
		Neo4jPath: e.Neo4jPath,
	}

	for _, domain := range e.Domains() {
		config.AddDomain(domain)
	}
	return config, nil
}

func (e *Enumeration) Start() error {
	var services []core.AmassService
	var filterMutex sync.Mutex
	filter := make(map[string]struct{})

	config, err := e.generateAmassConfig()
	if err != nil {
		return err
	}
	utils.SetDialContext(dnssrv.DialContext)

	bus := evbus.New()
	bus.SubscribeAsync(core.OUTPUT, func(out *AmassOutput) {
		filterMutex.Lock()
		defer filterMutex.Unlock()

		if _, found := filter[out.Name]; !found {
			filter[out.Name] = struct{}{}
			e.Output <- out
		}
	}, false)

	services = append(services, NewSourcesService(config, bus))
	var data *DataManagerService
	if !config.NoDNS {
		data = NewDataManagerService(config, bus)

		services = append(services,
			data,
			dnssrv.NewDNSService(config, bus),
			NewAlterationService(config, bus),
			NewBruteForceService(config, bus),
		)
	}

	for _, service := range services {
		if err := service.Start(); err != nil {
			return err
		}
	}

	if data != nil {
		e.Graph = data.Graph
	}

	// Periodically check if all the services have finished
	t := time.NewTicker(1 * time.Second)
	defer t.Stop()
	for range t.C {
		done := true

		for _, service := range services {
			if service.IsActive() {
				done = false
				break
			}
		}

		if done {
			break
		}
	}
	// Stop all the services
	for _, service := range services {
		service.Stop()
	}
	close(e.Output)
	return nil
}

func (e *Enumeration) WriteVisjsFile(path string) {
	if e.Graph == nil || path == "" {
		return
	}

	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE, 0644)
	if err != nil {
		return
	}
	defer f.Close()

	nodes, edges := e.Graph.VizData()
	viz.WriteVisjsData(nodes, edges, f)
	f.Sync()
}

func (e *Enumeration) WriteGraphistryFile(path string) {
	if e.Graph == nil || path == "" {
		return
	}

	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE, 0644)
	if err != nil {
		return
	}
	defer f.Close()

	nodes, edges := e.Graph.VizData()
	viz.WriteGraphistryData(nodes, edges, f)
	f.Sync()
}

func (e *Enumeration) WriteGEXFFile(path string) {
	if e.Graph == nil || path == "" {
		return
	}

	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE, 0644)
	if err != nil {
		return
	}
	defer f.Close()

	nodes, edges := e.Graph.VizData()
	viz.WriteGEXFData(nodes, edges, f)
	f.Sync()
}

func (e *Enumeration) WriteD3File(path string) {
	if e.Graph == nil || path == "" {
		return
	}

	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE, 0644)
	if err != nil {
		return
	}
	defer f.Close()

	nodes, edges := e.Graph.VizData()
	viz.WriteD3Data(nodes, edges, f)
	f.Sync()
}

func (e *Enumeration) ObtainAdditionalDomains() {
	ips := e.allIPsInConfig()

	if len(ips) > 0 {
		e.pullAllCertificates(ips)
	}

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

func (e *Enumeration) allIPsInConfig() []net.IP {
	var ips []net.IP

	ips = append(ips, e.IPs...)

	for _, cidr := range e.CIDRs {
		ips = append(ips, utils.NetHosts(cidr)...)
	}

	for _, asn := range e.ASNs {
		record, err := ASNRequest(asn)
		if err != nil {
			e.Log.Printf("%v", err)
			continue
		}

		for _, cidr := range record.Netblocks {
			_, ipnet, err := net.ParseCIDR(cidr)
			if err != nil {
				continue
			}

			ips = append(ips, utils.NetHosts(ipnet)...)
		}
	}
	return ips
}

func (e *Enumeration) pullAllCertificates(ips []net.IP) {
	var running int
	done := make(chan struct{}, 100)

	t := time.NewTicker(100 * time.Millisecond)
	defer t.Stop()
loop:
	for {
		select {
		case <-t.C:
			if running >= 100 || len(ips) <= 0 {
				break
			}

			running++

			addr := ips[0]
			if len(ips) == 1 {
				ips = []net.IP{}
			} else {
				ips = ips[1:]
			}

			go e.executeActiveCert(addr.String(), done)
		case <-done:
			running--
			if running == 0 && len(ips) <= 0 {
				break loop
			}
		}
	}
}

func (e *Enumeration) executeActiveCert(addr string, done chan struct{}) {
	var domains []string

	for _, r := range PullCertificateNames(addr, e.Ports) {
		domains = utils.UniqueAppend(domains, r.Domain)
	}

	for _, domain := range domains {
		e.AddDomain(domain)
	}
	done <- struct{}{}
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
