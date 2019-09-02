// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package services

import (
	"time"

	"github.com/OWASP/Amass/config"
	eb "github.com/OWASP/Amass/eventbus"
	"github.com/OWASP/Amass/queue"
	"github.com/OWASP/Amass/requests"
	"github.com/OWASP/Amass/resolvers"
)

// LogService is the Service that performs logging for the architecture.
type LogService struct {
	BaseService

	queue *queue.Queue
}

// NewLogService returns he object initialized, but not yet started.
func NewLogService(cfg *config.Config, bus *eb.EventBus, pool *resolvers.ResolverPool) *LogService {
	l := &LogService{queue: new(queue.Queue)}

	l.BaseService = *NewBaseService(l, "Log Service", cfg, bus, pool)
	return l
}

// OnStart implements the Service interface.
func (l *LogService) OnStart() error {
	l.BaseService.OnStart()

	l.Bus().Subscribe(requests.LogTopic, l.queue.Append)
	go l.processRequests()
	return nil
}

func (l *LogService) processRequests() {
	t := time.NewTicker(2 * time.Second)
	defer t.Stop()

	for {
		select {
		case <-l.PauseChan():
			<-l.ResumeChan()
		case <-l.Quit():
			return
		case <-t.C:
			if !l.queue.Empty() {
				l.writeLogs()
			}
		case <-l.DNSRequestChan():
		case <-l.AddrRequestChan():
		case <-l.ASNRequestChan():
		case <-l.WhoisRequestChan():
		}
	}
}

func (l *LogService) writeLogs() {
	for {
		msg, ok := l.queue.Next()
		if !ok {
			break
		}

		l.Config().Log.Print(msg.(string))
	}
}
