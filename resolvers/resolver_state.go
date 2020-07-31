// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package resolvers

import (
	"net"
	"time"

	"github.com/miekg/dns"
)

// Index values into the stats map.
const (
	QueryAttempts    = 64
	QueryTimeouts    = 65
	QueryRTT         = 66
	QueryCompletions = 67
)

const defaultConnRotation = 30 * time.Second

type resolverStopped struct {
	Stopped chan bool
}

type updateResolverStat struct {
	Stat   int
	Amount int64
}

type getResolverStat struct {
	Stat int
	Ch   chan int64
}

type allResolverStats struct {
	MapCh chan map[int]int64
}

type resolverStateChans struct {
	Done         chan struct{}
	StopResolver chan struct{}
	StoppedState chan *resolverStopped
	UpdateRTT    chan time.Duration
	AddToStat    chan *updateResolverStat
	GetStat      chan *getResolverStat
	SetStat      chan *updateResolverStat
	AllStats     chan *allResolverStats
	ClearStats   chan struct{}
}

func initStateManagement() *resolverStateChans {
	stateChs := &resolverStateChans{
		Done:         make(chan struct{}, 2),
		StopResolver: make(chan struct{}, 2),
		StoppedState: make(chan *resolverStopped, 10),
		UpdateRTT:    make(chan time.Duration, 10),
		AddToStat:    make(chan *updateResolverStat, 10),
		GetStat:      make(chan *getResolverStat, 10),
		SetStat:      make(chan *updateResolverStat),
		AllStats:     make(chan *allResolverStats, 10),
		ClearStats:   make(chan struct{}, 10),
	}

	go manageResolverState(stateChs)
	return stateChs
}

func manageResolverState(chs *resolverStateChans) {
	var stopped bool
	var numrtt int64
	stats := make(map[int]int64)

	for {
		select {
		case <-chs.Done:
			return
		case <-chs.StopResolver:
			stopped = true
		case isst := <-chs.StoppedState:
			isst.Stopped <- stopped
		case rtt := <-chs.UpdateRTT:
			numrtt++
			avg := stats[QueryRTT]
			stats[QueryRTT] = avg + ((int64(rtt) - avg) / numrtt)
		case add := <-chs.AddToStat:
			stats[add.Stat] = stats[add.Stat] + add.Amount
		case get := <-chs.GetStat:
			get.Ch <- stats[get.Stat]
		case set := <-chs.SetStat:
			stats[set.Stat] = set.Amount
		case all := <-chs.AllStats:
			c := make(map[int]int64)
			for k, v := range stats {
				c[k] = v
			}
			all.MapCh <- c
		case <-chs.ClearStats:
			numrtt = 0
			for k := range stats {
				stats[k] = 0
			}
		}
	}
}

// IsStopped implements the Resolver interface.
func (r *BaseResolver) IsStopped() bool {
	ch := make(chan bool, 2)

	r.stateChannels.StoppedState <- &resolverStopped{Stopped: ch}
	return <-ch
}

// Stop causes the Resolver to stop sending DNS queries and closes the network connection.
func (r *BaseResolver) Stop() error {
	if r.IsStopped() {
		return nil
	}

	r.stateChannels.StopResolver <- struct{}{}

	close(r.Done)
	close(r.stateChannels.Done)
	close(r.xchgsChannels.Done)
	return nil
}

func (r *BaseResolver) updateTimeouts(t int) {
	r.stateChannels.AddToStat <- &updateResolverStat{
		Stat:   QueryTimeouts,
		Amount: int64(t),
	}
}

func (r *BaseResolver) updateAttempts() {
	r.stateChannels.AddToStat <- &updateResolverStat{
		Stat:   QueryAttempts,
		Amount: 1,
	}
}

func (r *BaseResolver) updateRTT(rtt time.Duration) {
	r.stateChannels.UpdateRTT <- rtt
}

func (r *BaseResolver) updateStat(rcode int, value int64) {
	r.stateChannels.AddToStat <- &updateResolverStat{
		Stat:   rcode,
		Amount: value,
	}
}

func (r *BaseResolver) getStat(stat int) int64 {
	ch := make(chan int64, 2)

	r.stateChannels.GetStat <- &getResolverStat{
		Stat: stat,
		Ch:   ch,
	}
	return <-ch
}

// Stats returns performance counters.
func (r *BaseResolver) Stats() map[int]int64 {
	ch := make(chan map[int]int64, 2)

	r.stateChannels.AllStats <- &allResolverStats{MapCh: ch}
	return <-ch
}

// WipeStats clears the performance counters.
func (r *BaseResolver) WipeStats() {
	r.stateChannels.ClearStats <- struct{}{}
}

type pullRequestMsg struct {
	ID      uint16
	Timeout time.Duration
	Ch      chan *resolveRequest
}

type updateTimeoutMsg struct {
	ID      uint16
	Timeout time.Time
}

type xchgsChans struct {
	Done          chan struct{}
	GetID         chan chan uint16
	AddTimeout    chan uint16
	DelTimeout    chan uint16
	UpdateTimeout chan *updateTimeoutMsg
	AllTimeoutIDs chan chan []uint16
	AddRequest    chan *resolveRequest
	PullRequest   chan *pullRequestMsg
}

func initXchgsManagement() *xchgsChans {
	xchgsChs := &xchgsChans{
		Done:          make(chan struct{}, 2),
		GetID:         make(chan chan uint16, 10),
		AddTimeout:    make(chan uint16, 10),
		DelTimeout:    make(chan uint16, 10),
		UpdateTimeout: make(chan *updateTimeoutMsg, 10),
		AllTimeoutIDs: make(chan chan []uint16, 10),
		AddRequest:    make(chan *resolveRequest, 10),
		PullRequest:   make(chan *pullRequestMsg, 10),
	}

	go manageXchgState(xchgsChs)
	return xchgsChs
}

func manageXchgState(chs *xchgsChans) {
	var timeouts []uint16
	xchgs := make(map[uint16]*resolveRequest)

	for {
		select {
		case <-chs.Done:
			return
		case c := <-chs.GetID:
			var id uint16
			for {
				id = dns.Id()
				if _, found := xchgs[id]; !found {
					xchgs[id] = &resolveRequest{Timestamp: time.Now()}
					break
				}
			}
			c <- id
		case addTimeout := <-chs.AddTimeout:
			timeouts = append(timeouts, addTimeout)
		case delTimeout := <-chs.DelTimeout:
			var n int
			// Remove the element identified by id
			for _, i := range timeouts {
				if i != delTimeout {
					timeouts[n] = i
					n++
				}
			}
			timeouts = timeouts[:n]
		case ut := <-chs.UpdateTimeout:
			if req, found := xchgs[ut.ID]; found {
				req.Timestamp = ut.Timeout
			}
		case all := <-chs.AllTimeoutIDs:
			var ids []uint16
			for _, id := range timeouts {
				ids = append(ids, id)
			}
			all <- ids
		case addReq := <-chs.AddRequest:
			xchgs[addReq.ID] = addReq
		case pReq := <-chs.PullRequest:
			tPassed := true
			r, found := xchgs[pReq.ID]

			if found && pReq.Timeout != 0 && time.Now().Before(r.Timestamp.Add(pReq.Timeout)) {
				tPassed = false
			}

			if found && tPassed {
				delete(xchgs, pReq.ID)
				pReq.Ch <- r
			} else {
				pReq.Ch <- nil
			}
		}
	}
}

func (r *BaseResolver) addTimeout(id uint16) {
	r.xchgsChannels.AddTimeout <- id
}

func (r *BaseResolver) delTimeout(id uint16) {
	r.xchgsChannels.DelTimeout <- id
}

func (r *BaseResolver) allTimeoutIDs() []uint16 {
	ch := make(chan []uint16, 2)

	r.xchgsChannels.AllTimeoutIDs <- ch
	return <-ch
}

func (r *BaseResolver) getID() uint16 {
	ch := make(chan uint16, 2)

	r.xchgsChannels.GetID <- ch
	return <-ch
}

func (r *BaseResolver) queueRequest(id uint16, req *resolveRequest) {
	req.ID = id
	req.Timestamp = time.Now()

	r.xchgsChannels.AddRequest <- req
	r.addTimeout(id)
}

func (r *BaseResolver) pullRequest(id uint16) *resolveRequest {
	ch := make(chan *resolveRequest, 2)

	r.delTimeout(id)
	r.xchgsChannels.PullRequest <- &pullRequestMsg{
		ID: id,
		Ch: ch,
	}

	return <-ch
}

func (r *BaseResolver) pullRequestAfterTimeout(id uint16, timeout time.Duration) *resolveRequest {
	ch := make(chan *resolveRequest, 2)

	r.xchgsChannels.PullRequest <- &pullRequestMsg{
		ID:      id,
		Timeout: timeout,
		Ch:      ch,
	}

	req := <-ch
	if req != nil {
		r.delTimeout(id)
	}
	return req
}

func (r *BaseResolver) updateRequestTimeout(id uint16, timeout time.Time) {
	r.delTimeout(id)
	r.xchgsChannels.UpdateTimeout <- &updateTimeoutMsg{
		ID:      id,
		Timeout: timeout,
	}
	r.addTimeout(id)
}

type rotationChans struct {
	Rotate  chan struct{}
	Current chan chan *dns.Conn
	Last    chan chan *dns.Conn
}

func initRotationChans() *rotationChans {
	return &rotationChans{
		Rotate:  make(chan struct{}, 10),
		Current: make(chan chan *dns.Conn, 10),
		Last:    make(chan chan *dns.Conn, 10),
	}
}

func (r *BaseResolver) periodicRotations(chs *rotationChans) {
	var current, last net.Conn
	t := time.NewTicker(defaultConnRotation)
	defer t.Stop()

	for {
		select {
		case <-r.Done:
			if current != nil {
				current.Close()
			}
			if last != nil {
				last.Close()
			}
			return
		case <-t.C:
			go r.rotateConnections()
		case lch := <-chs.Last:
			if last == nil {
				lch <- nil
			} else {
				lch <- &dns.Conn{Conn: last}
			}
		case cch := <-chs.Current:
			if current == nil {
				cch <- nil
			} else {
				cch <- &dns.Conn{Conn: current}
			}
		case <-chs.Rotate:
			if last != nil {
				last.Close()
			}
			last = current

			var err error
			for {
				d := &net.Dialer{}

				current, err = d.Dial("udp", r.address+":"+r.port)
				if err == nil {
					break
				}
				time.Sleep(time.Duration(randomInt(1, 10)) * time.Millisecond)
			}
		}
	}
}

func (r *BaseResolver) rotateConnections() {
	r.rotationChannels.Rotate <- struct{}{}
}

func (r *BaseResolver) currentConnection() *dns.Conn {
	ch := make(chan *dns.Conn, 2)

	r.rotationChannels.Current <- ch
	return <-ch
}

func (r *BaseResolver) lastConnection() *dns.Conn {
	ch := make(chan *dns.Conn, 2)

	r.rotationChannels.Last <- ch
	return <-ch
}
