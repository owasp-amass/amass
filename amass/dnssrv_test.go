// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package amass

import (
	"bufio"
	"io"
	"log"
	"regexp"
	"testing"
	"time"

	"github.com/OWASP/Amass/amass/core"
)

func TestDNSStaticWildcard(t *testing.T) {
	if *network == false {
		t.Skip()
	}

	resolveReq := &core.Request{
		Name:   "random.wildcard.owasp-amass.com",
		Domain: "wildcard.owasp-amass.com",
	}

	config := &core.Config{}

	rLog, wLog := io.Pipe()
	config.Log = log.New(wLog, "", log.Lmicroseconds)

	bus := core.NewEventBus()
	defer bus.Stop()

	srv := NewDNSService(config, bus)
	srv.Start()
	defer srv.Stop()

	// Use dnssrv to resolve the request
	bus.Publish(core.ResolveNameTopic, resolveReq)

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
