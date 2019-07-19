// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// +build dns

package services

import (
	"bufio"
	"io"
	"log"
	"regexp"
	"testing"
	"time"

	"github.com/OWASP/Amass/config"
	eb "github.com/OWASP/Amass/eventbus"
	"github.com/OWASP/Amass/resolvers"
)

func TestDNSStaticWildcard(t *testing.T) {
	resolveReq := &DNSRequest{
		Name:   "random.wildcard.owasp-amass.com",
		Domain: "wildcard.owasp-amass.com",
	}

	c := &config.Config{}

	rLog, wLog := io.Pipe()
	c.Log = log.New(wLog, "", log.Lmicroseconds)

	bus := eb.NewEventBus()
	defer bus.Stop()

	srv := NewDNSService(c, bus, resolvers.NewResolverPool(nil))
	srv.Start()
	defer srv.Stop()

	// Use dnssrv to resolve the request
	bus.Publish(ResolveNameTopic, resolveReq)

	timeout := time.After(time.Second * 30)
	success := make(chan struct{})

	go func(success chan struct{}, rLog *io.PipeReader) {
		wildcard := regexp.MustCompile("static DNS wildcard")
		scanner := bufio.NewScanner(rLog)
		for scanner.Scan() {
			line := scanner.Text()

			if err := scanner.Err(); err != nil {
				break
			}

			if wildcard.MatchString(line) {
				success <- struct{}{}
				break
			}
		}
	}(success, rLog)

	select {
	case <-timeout:
		t.Errorf("Wildcard detection failed")
	case <-success:
	}
}
