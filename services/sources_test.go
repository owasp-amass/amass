// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package services

import (
	"context"
	"flag"
	"log"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/OWASP/Amass/v3/config"
	eb "github.com/OWASP/Amass/v3/eventbus"
	"github.com/OWASP/Amass/v3/requests"
)

var (
	networkTest  = flag.Bool("network", false, "Run tests that require connectivity (take more time)")
	configPath   = flag.String("config", "", "Path to the INI configuration file. Additional details below")
	outputDir    = flag.String("dir", "", "Path to the directory containing the output files")
	domainTest   = "owasp.org"
	testConfig   *config.Config
	testSystem   System
	expectedTest = 1
	timeoutTest  = time.Second * 30
)

// TestMain will parse the test flags and setup for integration tests.
func TestMain(m *testing.M) {
	flag.Parse()

	testConfig = setupConfig(domainTest)
	if testConfig == nil {
		return
	}

	var err error
	testSystem, err = NewLocalSystem(testConfig)
	if err != nil {
		return
	}

	os.Exit(m.Run())
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
	cfg := config.NewConfig()

	config.AcquireConfig(*outputDir, *configPath, cfg)

	cfg.AddDomain(domain)
	buf := new(strings.Builder)
	cfg.Log = log.New(buf, "", log.Lmicroseconds)

	return cfg
}

func testDNSRequest(srvName string) int {
	out := make(chan *requests.DNSRequest)

	bus := eb.NewEventBus()
	defer bus.Stop()

	fn := func(req *requests.DNSRequest) {
		out <- req
	}

	bus.Subscribe(requests.NewNameTopic, fn)
	defer bus.Unsubscribe(requests.NewNameTopic, fn)

	var srv Service
	for _, s := range testSystem.DataSources() {
		if s.String() == srvName {
			srv = s
			break
		}
	}
	if srv == nil {
		return 0
	}

	ctx := context.WithValue(context.Background(), requests.ContextConfig, testConfig)
	ctx = context.WithValue(ctx, requests.ContextEventBus, bus)

	srv.DNSRequest(ctx, &requests.DNSRequest{
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
