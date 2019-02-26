// +build datasources

package sources

import (
	"log"
	"strings"
	"testing"
	"time"

	"github.com/OWASP/Amass/amass/core"
)

func TestBing(t *testing.T) {
	config := &core.Config{}
	config.AddDomain("google.com")
	buf := new(strings.Builder)
	config.Log = log.New(buf, "", log.Lmicroseconds)

	out := make(chan *core.Request)
	bus := core.NewEventBus()
	bus.Subscribe(core.NewNameTopic, func(req *core.Request) {
		out <- req
	})
	defer bus.Stop()

	srv := NewBing(config, bus)
	srv.Start()
	defer srv.Stop()

	count := 0
	expected := 10
	done := time.After(time.Second * 30)

loop:
	for {
		select {
		case <-out:
			count++
			if count == expected {
				return
			}
		case <-done:
			break loop
		}
	}

	if count < expected {
		t.Errorf("Found %d names, expected at least %d instead", count, expected)
	}
}
