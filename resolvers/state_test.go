// Copyright 2021 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package resolvers

import (
	"strings"
	"testing"
	"time"

	"github.com/caffix/stringset"
	"github.com/miekg/dns"
)

func TestXchgAddRemove(t *testing.T) {
	name := "owasp.org"
	xchg := newXchgManager()
	msg := QueryMsg(name, dns.TypeA)

	if err := xchg.add(&resolveRequest{
		ID:    msg.Id,
		Name:  name,
		Qtype: dns.TypeA,
		Msg:   msg,
	}); err != nil {
		t.Errorf("Failed to add the request")
	}

	req := xchg.remove(msg.Id, msg.Question[0].Name)
	if req == nil || req.Msg == nil || name != strings.ToLower(RemoveLastDot(req.Msg.Question[0].Name)) {
		t.Errorf("Did not find and remove the message from the data structure")
	}
}

func TestXchgUpdateTimestamp(t *testing.T) {
	name := "owasp.org"
	xchg := newXchgManager()
	msg := QueryMsg(name, dns.TypeA)

	req := &resolveRequest{
		ID:    msg.Id,
		Name:  name,
		Qtype: dns.TypeA,
		Msg:   msg,
	}

	if !req.Timestamp.IsZero() {
		t.Errorf("Expected the new request to have a zero value timestamp")
	}

	if err := xchg.add(req); err != nil {
		t.Errorf("Failed to add the request")
	}
	xchg.updateTimestamp(msg.Id, name)

	req = xchg.remove(msg.Id, msg.Question[0].Name)
	if req == nil || req.Timestamp.IsZero() {
		t.Errorf("Expected the updated request to not have a zero value timestamp")
	}
}

func TestXchgRemoveExpired(t *testing.T) {
	xchg := newXchgManager()
	names := []string{"owasp.org", "www.owasp.org", "blog.owasp.org"}

	QueryTimeout = time.Second
	for _, name := range names {
		msg := QueryMsg(name, dns.TypeA)
		if err := xchg.add(&resolveRequest{
			ID:        msg.Id,
			Name:      name,
			Qtype:     dns.TypeA,
			Msg:       msg,
			Timestamp: time.Now(),
		}); err != nil {
			t.Errorf("Failed to add the request")
		}
	}

	// Add one request that should not be removed with the others
	name := "vpn.owasp.org"
	msg := QueryMsg(name, dns.TypeA)
	if err := xchg.add(&resolveRequest{
		ID:        msg.Id,
		Name:      name,
		Qtype:     dns.TypeA,
		Msg:       msg,
		Timestamp: time.Now().Add(3 * time.Second),
	}); err != nil {
		t.Errorf("Failed to add the request")
	}

	if len(xchg.removeExpired()) > 0 {
		t.Errorf("The removeExpired method returned requests too early")
	}

	time.Sleep(1500 * time.Millisecond)
	set := stringset.New(names...)
	for _, req := range xchg.removeExpired() {
		set.Remove(req.Name)
	}

	if set.Len() > 0 {
		t.Errorf("Not all expected requests were returned by removeExpired")
	}
}

func TestXchgRemoveAll(t *testing.T) {
	xchg := newXchgManager()
	names := []string{"owasp.org", "www.owasp.org", "blog.owasp.org"}

	QueryTimeout = time.Second
	for _, name := range names {
		msg := QueryMsg(name, dns.TypeA)
		if err := xchg.add(&resolveRequest{
			ID:    msg.Id,
			Name:  name,
			Qtype: dns.TypeA,
			Msg:   msg,
		}); err != nil {
			t.Errorf("Failed to add the request")
		}
	}

	set := stringset.New(names...)
	for _, req := range xchg.removeAll() {
		set.Remove(req.Name)
	}

	if set.Len() > 0 {
		t.Errorf("Not all expected requests were returned by removeAll")
	}
}
