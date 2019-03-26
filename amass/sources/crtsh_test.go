package sources

import (
	"log"
	"strings"
	"testing"

	"github.com/OWASP/Amass/amass/core"
)

func TestCrtsh(t *testing.T) {
	if *networkTest == false {
		return
	}
	config := &core.Config{}
	config.AddDomain(domainTest)
	buf := new(strings.Builder)
	config.Log = log.New(buf, "", log.Lmicroseconds)

	out := make(chan *core.Request)
	bus := core.NewEventBus()
	bus.Subscribe(core.NewNameTopic, func(req *core.Request) {
		out <- req
	})
	defer bus.Stop()

	srv := NewCrtsh(config, bus)
	srv.Start()
	defer srv.Stop()
	srv.SendRequest(&core.Request{
		Name:   domainTest,
		Domain: domainTest,
	})

	results := make(map[string]int)

loop:
	for {
		select {
		case req := <-out:
			results[req.Name]++
		case <-doneTest:
			break loop
		}
	}

	if expectedTest > len(results) {
		t.Errorf("Found %d names, expected %d instead", len(results), expectedTest)
	}
}
