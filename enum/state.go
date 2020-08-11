// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package enum

import (
	"time"

	"github.com/OWASP/Amass/v3/queue"
	"github.com/OWASP/Amass/v3/requests"
	"github.com/OWASP/Amass/v3/resolvers"
)

type enumStateChans struct {
	GetLastActive chan chan time.Time
	UpdateLast    *queue.Queue
	GetSeqZeros   chan chan int64
	IncSeqZeros   chan struct{}
	ClearSeqZeros chan struct{}
	GetPerSec     chan chan *getPerSec
	IncPerSec     *queue.Queue
	ClearPerSec   chan struct{}
}

type getPerSec struct {
	PerSec  int64
	Retries int64
}

type incPerSec struct {
	T     time.Time
	Rcode int
}

func (e *Enumeration) manageEnumState(chs *enumStateChans) {
	var perSec int64
	var retries int64
	var numSeqZeros int64 = 1
	last := time.Now()
	perSecFirst := time.Now()
	perSecLast := time.Now()

	perSecCallback := func(element interface{}) {
		inc := element.(*incPerSec)

		if inc.T.After(perSecFirst) {
			perSec++

			for _, rc := range resolvers.RetryCodes {
				if rc == inc.Rcode {
					retries++
					break
				}
			}

			if inc.T.After(perSecLast) {
				perSecLast = inc.T
			}
		}
	}
	updateLastCallback := func(element interface{}) {
		srv := element.(string)
		// Only update active for core services once we run out of new FQDNs
		if numSeqZeros >= 3 && !e.Config.Passive {
			var found bool
			for _, s := range []requests.Service{e.dnsMgr, e.dataMgr} {
				if srv == s.String() {
					found = true
					break
				}
			}
			if !found {
				return
			}
		}
		// Update the last time activity was seen
		last = time.Now()
	}

	for {
		select {
		case <-e.done:
			return
		case get := <-chs.GetLastActive:
			get <- last
		case <-chs.UpdateLast.Signal:
			chs.UpdateLast.Process(updateLastCallback)
		case seq := <-chs.GetSeqZeros:
			seq <- numSeqZeros
		case <-chs.IncSeqZeros:
			numSeqZeros++
		case <-chs.ClearSeqZeros:
			numSeqZeros = 0
		case gsec := <-chs.GetPerSec:
			var psec, ret int64
			if perSecLast.After(perSecFirst) {
				if sec := perSecLast.Sub(perSecFirst).Seconds(); sec > 0 {
					div := int64(sec + 1.0)

					psec = perSec / div
					ret = retries / div
				}
			}
			gsec <- &getPerSec{
				PerSec:  psec,
				Retries: ret,
			}
		case <-chs.IncPerSec.Signal:
			chs.IncPerSec.Process(perSecCallback)
		case <-chs.ClearPerSec:
			perSec = 0
			retries = 0
			perSecFirst = time.Now()
		}
	}
}

func (e *Enumeration) lastActive() time.Time {
	ch := make(chan time.Time, 2)

	e.enumStateChannels.GetLastActive <- ch
	return <-ch
}

func (e *Enumeration) updateLastActive(srv string) {
	e.enumStateChannels.UpdateLast.Append(srv)
}

func (e *Enumeration) getNumSeqZeros() int64 {
	ch := make(chan int64, 2)

	e.enumStateChannels.GetSeqZeros <- ch
	return <-ch
}

func (e *Enumeration) incNumSeqZeros() {
	e.enumStateChannels.IncSeqZeros <- struct{}{}
}

func (e *Enumeration) clearNumSeqZeros() {
	e.enumStateChannels.ClearSeqZeros <- struct{}{}
}

func (e *Enumeration) dnsQueriesPerSec() (int64, int64) {
	ch := make(chan *getPerSec, 2)

	e.enumStateChannels.GetPerSec <- ch
	r := <-ch
	return r.PerSec, r.Retries
}

func (e *Enumeration) incQueriesPerSec(t time.Time, rcode int) {
	e.enumStateChannels.IncPerSec.Append(&incPerSec{
		T:     t,
		Rcode: rcode,
	})
}

func (e *Enumeration) clearPerSec() {
	e.enumStateChannels.ClearPerSec <- struct{}{}
}
