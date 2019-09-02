// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package sources

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/OWASP/Amass/config"
	eb "github.com/OWASP/Amass/eventbus"
	"github.com/OWASP/Amass/net/http"
	"github.com/OWASP/Amass/requests"
	"github.com/OWASP/Amass/resolvers"
	"github.com/OWASP/Amass/services"
	"github.com/OWASP/Amass/stringset"
)

const (
	// radbWhoisURL is the URL for the RADb whois server.
	radbWhoisURL = "whois.radb.net"
)

var (
	// radbRegistries are all the registries that have RADb servers
	radbRegistries = []string{"arin", "ripencc", "apnic", "lacnic", "afrinic"}
)

// RADb is the Service that handles access to the RADb data source.
type RADb struct {
	services.BaseService

	SourceType string
	RateLimit  time.Duration

	addr string
}

// NewRADb returns he object initialized, but not yet started.
func NewRADb(cfg *config.Config, bus *eb.EventBus, pool *resolvers.ResolverPool) *RADb {
	r := &RADb{
		SourceType: requests.API,
		RateLimit:  time.Second,
	}

	r.BaseService = *services.NewBaseService(r, "RADb", cfg, bus, pool)
	return r
}

// OnStart implements the Service interface
func (r *RADb) OnStart() error {
	r.BaseService.OnStart()

	if answers, err := r.Pool().Resolve(radbWhoisURL, "A", resolvers.PriorityHigh); err == nil {
		ip := answers[0].Data
		if ip != "" {
			r.addr = ip
		}
	}

	r.Bus().Subscribe(requests.IPToASNTopic, r.SendASNRequest)
	go r.processRequests()
	return nil
}

func (r *RADb) processRequests() {
	last := time.Now().Truncate(10 * time.Minute)
loop:
	for {
		select {
		case <-r.Quit():
			return
		case <-r.DNSRequestChan():
		case req := <-r.ASNRequestChan():
			if req.Address == "" && req.ASN == 0 {
				continue loop
			}
			if time.Now().Sub(last) < r.RateLimit {
				time.Sleep(r.RateLimit)
			}
			last = time.Now()
			if req.Address != "" {
				r.executeASNAddrQuery(req.Address)
			} else {
				r.executeASNQuery(req.ASN, "")
			}
			last = time.Now()
		case <-r.AddrRequestChan():
		case <-r.WhoisRequestChan():
		}
	}
}

func (r *RADb) registryRADbURL(registry string) string {
	var url string

	switch registry {
	case "arin":
		url = "https://rdap.arin.net/registry/"
	case "ripencc":
		url = "https://rdap.db.ripe.net/"
	case "apnic":
		url = "https://rdap.apnic.net/"
	case "lacnic":
		url = "https://rdap.lacnic.net/rdap/"
	case "afrinic":
		url = "https://rdap.afrinic.net/rdap/"
	}
	return url
}

func (r *RADb) executeASNAddrQuery(addr string) {
	r.SetActive()
	url := r.getIPURL("arin", addr)
	headers := map[string]string{"Content-Type": "application/json"}
	page, err := http.RequestWebPage(url, nil, headers, "", "")
	if err != nil {
		r.Bus().Publish(requests.LogTopic, fmt.Sprintf("%s: %s: %v", r.String(), url, err))
		return
	}

	var m struct {
		Version   string `json:"ipVersion"`
		ClassName string `json:"objectClassName"` // should be 'ip network'
		CIDRs     []struct {
			V4Prefix string `json:"v4prefix"`
			V6Prefix string `json:"v6prefix"`
			Length   int    `json:"length"`
		} `json:"cidr0_cidrs"`
	}
	if err := json.Unmarshal([]byte(page), &m); err != nil {
		r.Bus().Publish(requests.LogTopic, fmt.Sprintf("%s: %s: %v", r.String(), url, err))
		return
	} else if m.ClassName != "ip network" || len(m.CIDRs) == 0 {
		r.Bus().Publish(requests.LogTopic,
			fmt.Sprintf("%s: %s: The request returned zero results", r.String(), url),
		)
		return
	}

	var prefix string
	switch m.Version {
	case "v4":
		prefix = m.CIDRs[0].V4Prefix
	case "v6":
		prefix = m.CIDRs[0].V6Prefix
	}
	if prefix == "" {
		return
	}

	cidr := prefix + "/" + strconv.Itoa(m.CIDRs[0].Length)
	if asn := r.ipToASN(cidr); asn != 0 {
		r.SetActive()
		time.Sleep(r.RateLimit)
		r.executeASNQuery(asn, cidr)
	}
}

func (r *RADb) getIPURL(registry, addr string) string {
	format := r.registryRADbURL(registry) + "ip/%s"

	return fmt.Sprintf(format, addr)
}

func (r *RADb) executeASNQuery(asn int, prefix string) {
	if asn == 0 {
		return
	}

	r.SetActive()
	url := r.getASNURL("arin", strconv.Itoa(asn))
	headers := map[string]string{"Content-Type": "application/json"}
	page, err := http.RequestWebPage(url, nil, headers, "", "")
	if err != nil {
		r.Bus().Publish(requests.LogTopic, fmt.Sprintf("%s: %s: %v", r.String(), url, err))
		return
	}

	var m struct {
		ClassName   string `json:"objectClassName"` // interested in "autnum"
		Description string `json:"name"`
		Dates       []struct {
			Action string `json:"eventAction"` // interested in "registration"
			Date   string `json:"eventDate"`
		}
	}
	if err := json.Unmarshal([]byte(page), &m); err != nil {
		r.Bus().Publish(requests.LogTopic, fmt.Sprintf("%s: %s: %v", r.String(), url, err))
		return
	} else if m.ClassName != "autnum" {
		r.Bus().Publish(requests.LogTopic,
			fmt.Sprintf("%s: %s: The query returned incorrect results", r.String(), url),
		)
		return
	}

	var registration string
	for _, event := range m.Dates {
		if event.Action == "registration" {
			registration = event.Date
			break
		}
	}

	var at time.Time
	if registration != "" {
		d, err := time.Parse(time.RFC3339, registration)
		if err == nil {
			at = d
		}
	}

	r.SetActive()
	time.Sleep(r.RateLimit)

	blocks := stringset.New()
	if prefix != "" {
		blocks.Insert(prefix)
	}
	blocks.Union(r.netblocks(asn))

	if len(blocks) == 0 {
		r.Bus().Publish(requests.LogTopic,
			fmt.Sprintf("%s: %s: The query returned zero netblocks", r.String(), url),
		)
		return
	}

	r.Bus().Publish(requests.NewASNTopic, &requests.ASNRequest{
		ASN:            asn,
		Prefix:         prefix,
		AllocationDate: at,
		Description:    m.Description,
		Netblocks:      blocks,
		Tag:            r.SourceType,
		Source:         r.String(),
	})
}

func (r *RADb) getASNURL(registry, asn string) string {
	format := r.registryRADbURL(registry) + "autnum/%s"

	return fmt.Sprintf(format, asn)
}

func (r *RADb) netblocks(asn int) stringset.Set {
	netblocks := stringset.New()

	r.SetActive()
	url := r.getNetblocksURL(strconv.Itoa(asn))
	headers := map[string]string{"Content-Type": "application/json"}
	page, err := http.RequestWebPage(url, nil, headers, "", "")
	if err != nil {
		r.Bus().Publish(requests.LogTopic, fmt.Sprintf("%s: %s: %v", r.String(), url, err))
		return netblocks
	}

	var m struct {
		Results []struct {
			Version   string `json:"ipVersion"`
			ClassName string `json:"objectClassName"` // should be 'ip network'
			CIDRs     []struct {
				V4Prefix string `json:"v4prefix"`
				V6Prefix string `json:"v6prefix"`
				Length   int    `json:"length"`
			} `json:"cidr0_cidrs"`
		} `json:"arin_originas0_networkSearchResults"`
	}
	if err := json.Unmarshal([]byte(page), &m); err != nil {
		r.Bus().Publish(requests.LogTopic, fmt.Sprintf("%s: %s: %v", r.String(), url, err))
		return netblocks
	}

	for _, block := range m.Results {
		if block.ClassName != "ip network" {
			continue
		}

		for _, cidr := range block.CIDRs {
			var prefix string

			switch block.Version {
			case "v4":
				prefix = cidr.V4Prefix
			case "v6":
				prefix = cidr.V6Prefix
			}

			if prefix != "" {
				l := strconv.Itoa(cidr.Length)

				netblocks.Insert(prefix + "/" + l)
			}
		}
	}

	if len(netblocks) == 0 {
		r.Bus().Publish(requests.LogTopic,
			fmt.Sprintf("%s: Failed to acquire netblocks for ASN %d", r.String(), asn),
		)
	}
	return netblocks
}

func (r *RADb) getNetblocksURL(asn string) string {
	format := "https://rdap.arin.net/registry/arin_originas0_networksbyoriginas/%s"

	return fmt.Sprintf(format, asn)
}

func (r *RADb) ipToASN(cidr string) int {
	r.SetActive()
	if r.addr == "" {
		answers, err := r.Pool().Resolve(radbWhoisURL, "A", resolvers.PriorityHigh)
		if err != nil {
			r.Bus().Publish(requests.LogTopic, fmt.Sprintf("%s: %s: %v", r.String(), radbWhoisURL, err))
			return 0
		}

		ip := answers[0].Data
		if ip == "" {
			r.Bus().Publish(requests.LogTopic,
				fmt.Sprintf("%s: Failed to resolve %s", r.String(), radbWhoisURL),
			)
			return 0
		}
		r.addr = ip
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	d := net.Dialer{}
	conn, err := d.DialContext(ctx, "tcp", r.addr+":43")
	if err != nil {
		r.Bus().Publish(requests.LogTopic, fmt.Sprintf("%s: %v", r.String(), err))
		return 0
	}
	defer conn.Close()

	fmt.Fprintf(conn, "!r%s,o\n", cidr)

	var asn int
	scanner := bufio.NewScanner(conn)
	for scanner.Scan() {
		line := scanner.Text()

		if err := scanner.Err(); err != nil {
			continue
		}

		if !strings.HasPrefix(line, "AS") {
			continue
		}

		line2 := strings.ReplaceAll(line, "AS", "")
		nums := strings.Split(strings.TrimSpace(line2), " ")
		n := strings.TrimSpace(nums[len(nums)-1])
		if n == "" {
			continue
		}
		asn, err = strconv.Atoi(n)
		if err != nil {
			asn = 0
		}
	}
	return asn
}
