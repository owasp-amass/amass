// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package sources

import (
	"flag"
	"log"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/OWASP/Amass/config"
	eb "github.com/OWASP/Amass/eventbus"
	"github.com/OWASP/Amass/requests"
	"github.com/OWASP/Amass/services"
)

var (
	networkTest  = flag.Bool("network", false, "Run tests that require connectivity (take more time)")
	configPath   = flag.String("config", "", "Path to the INI configuration file. Additional details below")
	outputDir    = flag.String("dir", "", "Path to the directory containing the output files")
	domainTest   = "owasp.org"
	expectedTest = 1
	timeoutTest  = time.Second * 30
)

// TestMain will parse the test flags and setup for integration tests.
func TestMain(m *testing.M) {
	flag.Parse()

	result := m.Run()

	os.Exit(result)
}

func TestCleanName(t *testing.T) {
	tests := []struct {
		name     string
		domain   string
		expected string
	}{
		{"Test 1: Domain", " .owasp.org", "owasp.org"},
		{"Test 2: Subdomain", ".sub.owasp.org", "sub.owasp.org"},
	}

	for _, tt := range tests {
		result := cleanName(tt.domain)
		if result != tt.expected {
			t.Errorf("Failed %s: got %s expected %s", tt.name, result, tt.expected)
		}
	}
}

func setupConfig(domain string) *config.Config {
	cfg := &config.Config{}

	config.AcquireConfig(*outputDir, *configPath, cfg)

	cfg.AddDomain(domain)
	buf := new(strings.Builder)
	cfg.Log = log.New(buf, "", log.Lmicroseconds)

	return cfg
}

func setupEventBus(subscription string) (*eb.EventBus, chan *requests.DNSRequest) {
	out := make(chan *requests.DNSRequest)
	bus := eb.NewEventBus()
	bus.Subscribe(subscription, func(req *requests.DNSRequest) {
		out <- req
	})

	return bus, out
}

func testService(srv services.Service, out chan *requests.DNSRequest) int {
	srv.Start()
	defer srv.Stop()

	srv.SendDNSRequest(&requests.DNSRequest{
		Name:   domainTest,
		Domain: domainTest,
	})

	count := 0
	doneTimer := time.After(timeoutTest)

loop:
	for {
		select {
		case <-out:
			count++
			if count == expectedTest {
				break loop
			}
		case <-doneTimer:
			break loop
		}
	}

	return count
}
