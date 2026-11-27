// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package rdap

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/netip"
	"slices"
	"testing"
	"time"

	"github.com/openrdap/rdap"
	"github.com/openrdap/rdap/bootstrap"
	"github.com/owasp-amass/amass/v5/engine/plugins/plugintest"
	et "github.com/owasp-amass/amass/v5/engine/types"
	dbt "github.com/owasp-amass/asset-db/types"
	oam "github.com/owasp-amass/open-asset-model"
	oamdns "github.com/owasp-amass/open-asset-model/dns"
	"github.com/owasp-amass/open-asset-model/network"
	oamreg "github.com/owasp-amass/open-asset-model/registration"
	"golang.org/x/time/rate"
)

const (
	rdapEvents = `"events":[{"eventAction":"registration","eventDate":"2001-02-03T04:05:06Z"},` +
		`{"eventAction":"last changed","eventDate":"2024-06-01T12:00:00Z"}]`
	rdapOrg = `{"objectClassName":"entity","handle":"EXNET-ORG","roles":["registrant"],` +
		`"links":[{"rel":"self","href":"https://rdap.example.net/entity/EXNET-ORG","type":"application/rdap+json"}],` +
		`"vcardArray":["vcard",[["version",{},"text","4.0"],["fn",{},"text","Example Networks Inc"],` +
		`["kind",{},"text","org"],["email",{},"text","noc@example.net"]]]}`
	rdapAbuse = `{"objectClassName":"entity","handle":"EXNET-ABUSE","roles":["abuse"],` +
		`"links":[{"rel":"self","href":"https://rdap.example.net/entity/EXNET-ABUSE","type":"application/rdap+json"}],` +
		`"vcardArray":["vcard",[["version",{},"text","4.0"],["fn",{},"text","Abuse Desk"],` +
		`["kind",{},"text","group"],["email",{},"text","abuse@example.net"]]]}`
)

// newTestRDAP returns the plugin and a session whose fake web serves the IANA
// bootstrap files and one registry's RDAP server.
func newTestRDAP(t *testing.T) (*rdapPlugin, *plugintest.Session) {
	t.Helper()

	sess := plugintest.NewSession(t)
	sess.TTL(60)
	sess.Scope().AddDomain("example.net")

	web := sess.Web()
	server := `["https://rdap.example.net/"]`
	web.Reply("GET data.iana.org/rdap/asn.json", http.StatusOK,
		`{"version":"1.0","services":[[["64496-64511"],`+server+`]]}`)
	web.Reply("GET data.iana.org/rdap/ipv4.json", http.StatusOK,
		`{"version":"1.0","services":[[["192.0.2.0/24"],`+server+`]]}`)
	web.Reply("GET data.iana.org/rdap/dns.json", http.StatusOK,
		`{"version":"1.0","services":[[["net"],`+server+`]]}`)
	web.Reply("GET rdap.example.net/autnum/", http.StatusOK, `{"objectClassName":"autnum","handle":"AS64500",`+
		`"startAutnum":64500,"endAutnum":64500,"name":"EXAMPLE-NET","port43":"whois.example.net",`+
		`"links":[{"rel":"self","href":"https://rdap.example.net/autnum/64500","type":"application/rdap+json"}],`+
		rdapEvents+`,"entities":[`+rdapOrg+`]}`)
	web.Reply("GET rdap.example.net/ip/", http.StatusOK, `{"objectClassName":"ip network","handle":"NET-192-0-2-0-1",`+
		`"startAddress":"192.0.2.0","endAddress":"192.0.2.255","ipVersion":"v4","name":"TEST-NET-1",`+
		`"type":"DIRECT ALLOCATION","country":"US","port43":"whois.example.net",`+rdapEvents+
		`,"entities":[`+rdapAbuse+`]}`)
	web.Reply("GET rdap.example.net/domain/", http.StatusOK, `{"objectClassName":"domain","handle":"EXAMPLE-NET-DOM",`+
		`"ldhName":"example.net","port43":"whois.registrar.test","status":["active"],`+
		`"nameservers":[{"objectClassName":"nameserver","ldhName":"NS1.EXAMPLE.NET"}],`+rdapEvents+`}`)

	rd := NewRDAP().(*rdapPlugin)
	rd.rlimit = rate.NewLimiter(rate.Inf, 1)
	rd.log = slog.New(slog.NewTextHandler(io.Discard, nil))
	rd.client = &rdap.Client{HTTP: sess.Clients().General, Bootstrap: &bootstrap.Client{HTTP: sess.Clients().General}}
	rd.autsys = &autsys{name: rd.name + "-Autsys-Handler", plugin: rd}
	rd.netblock = &netblock{name: rd.name + "-Netblock-Handler", plugin: rd}
	rd.domain = &domain{name: rd.name + "-Domain-Handler", plugin: rd}
	rd.autnum = newRecordDetail(rd, oam.AutnumRecord)
	rd.ipnet = newRecordDetail(rd, oam.IPNetRecord)
	rd.domrec = newRecordDetail(rd, oam.DomainRecord)
	return rd, sess
}

// registration runs a query handler on the asset and returns the one record
// event it dispatched.
func registration(t *testing.T, sess *plugintest.Session, check func(*et.Event) error, asset *dbt.Entity) *et.Event {
	t.Helper()

	d := &plugintest.Dispatcher{}
	if err := check(&et.Event{Entity: asset, Session: sess, Dispatcher: d}); err != nil {
		t.Fatal(err)
	}
	evs := d.Events()
	if len(evs) != 1 {
		t.Fatalf("dispatched %v; requests %v", d.Names(), sess.Web().Requests())
	}
	return evs[0]
}

// detail runs a record detail handler on a record event and returns what it
// dispatched.
func detail(t *testing.T, sess *plugintest.Session, r *recordDetail, ev *et.Event) *plugintest.Dispatcher {
	t.Helper()

	d := &plugintest.Dispatcher{}
	if err := r.check(&et.Event{Name: ev.Name, Meta: ev.Meta, Entity: ev.Entity, Session: sess, Dispatcher: d}); err != nil {
		t.Fatal(err)
	}
	return d
}

func outgoing(t *testing.T, sess *plugintest.Session, from *dbt.Entity, label string) []*dbt.Entity {
	t.Helper()

	ctx := context.Background()
	edges, err := sess.DB().OutgoingEdges(ctx, from, time.Time{}, label)
	if err != nil {
		return nil
	}
	var out []*dbt.Entity
	for _, edge := range edges {
		if a, err := sess.DB().FindEntityById(ctx, edge.ToEntity.ID); err == nil {
			out = append(out, a)
		}
	}
	return out
}

func TestAutonomousSystemRegistration(t *testing.T) {
	rd, sess := newTestRDAP(t)
	as := sess.Asset(t, &network.AutonomousSystem{Number: 64500})

	ev := registration(t, sess, rd.autsys.check, as)
	rec, ok := ev.Entity.Asset.(*oamreg.AutnumRecord)
	if !ok || rec.Handle != "AS64500" || rec.Name != "EXAMPLE-NET" || rec.CreatedDate == "" || rec.UpdatedDate == "" {
		t.Fatalf("record = %+v", ev.Entity.Asset)
	}
	if ev.Name != "AutnumRecord: AS64500" {
		t.Errorf("event name = %q", ev.Name)
	}

	// The detail handler stores what the response carries.
	d := detail(t, sess, rd.autnum, ev)
	if len(outgoing(t, sess, ev.Entity, "rdap_url")) != 1 || len(outgoing(t, sess, ev.Entity, "whois_server")) != 1 {
		t.Error("the RDAP URL or the in-scope WHOIS server was not linked")
	}
	contacts := outgoing(t, sess, ev.Entity, "registrant")
	if len(contacts) != 1 {
		t.Fatalf("registrant contacts = %v", contacts)
	}
	if orgs := outgoing(t, sess, contacts[0], "organization"); len(orgs) != 1 {
		t.Errorf("the registrant organization = %v", orgs)
	}
	if !slices.ContainsFunc(d.Events(), func(e *et.Event) bool { return e.Entity.Asset.AssetType() == oam.Organization }) {
		t.Errorf("the organization was not dispatched: %v", d.Names())
	}

	// Within the TTL the record is found again in the database, with no RDAP
	// response, and its detail comes from the stored edges.
	sent := len(sess.Web().Requests())
	again := registration(t, sess, rd.autsys.check, as)
	if again.Entity.ID != ev.Entity.ID || again.Meta != nil {
		t.Errorf("the TTL path dispatched %v with %v", again.Entity.Asset, again.Meta)
	}
	if len(sess.Web().Requests()) != sent {
		t.Errorf("RDAP was asked again within the TTL: %v", sess.Web().Requests()[sent:])
	}
	if d := detail(t, sess, rd.autnum, again); len(d.Events()) == 0 {
		t.Error("the stored detail was not dispatched within the TTL")
	}
}

func TestNetblockRegistration(t *testing.T) {
	rd, sess := newTestRDAP(t)
	block := sess.Asset(t, &network.Netblock{CIDR: netip.MustParsePrefix("192.0.2.0/24"), Type: "IPv4"})

	ev := registration(t, sess, rd.netblock.check, block)
	if rec, ok := ev.Entity.Asset.(*oamreg.IPNetRecord); !ok || rec.Handle != "NET-192-0-2-0-1" || rec.Country != "US" {
		t.Fatalf("record = %+v", ev.Entity.Asset)
	}

	detail(t, sess, rd.ipnet, ev)
	if abuse := outgoing(t, sess, ev.Entity, "abuse_contact"); len(abuse) != 1 {
		t.Errorf("abuse contacts = %v", abuse)
	}
}

func TestDomainRegistration(t *testing.T) {
	rd, sess := newTestRDAP(t)
	fqdn := sess.Asset(t, &oamdns.FQDN{Name: "example.net"})

	// A name below the registered domain has no record of its own.
	sub := sess.Asset(t, &oamdns.FQDN{Name: "www.example.net"})
	d := &plugintest.Dispatcher{}
	if err := rd.domain.check(&et.Event{Entity: sub, Session: sess, Dispatcher: d}); err != nil || len(d.Events()) != 0 {
		t.Fatalf("a subdomain was looked up: %v, %v", d.Names(), err)
	}

	ev := registration(t, sess, rd.domain.check, fqdn)
	if rec, ok := ev.Entity.Asset.(*oamreg.DomainRecord); !ok || rec.ID != "EXAMPLE-NET-DOM" || rec.WhoisServer != "whois.registrar.test" {
		t.Fatalf("record = %+v", ev.Entity.Asset)
	}

	detail(t, sess, rd.domrec, ev)
	ns := outgoing(t, sess, ev.Entity, "name_server")
	if len(ns) != 1 || ns[0].Asset.(*oamdns.FQDN).Name != "ns1.example.net" {
		t.Errorf("name servers = %v", ns)
	}
	// The registrar's WHOIS server is out of scope, so it is not linked.
	if ws := outgoing(t, sess, ev.Entity, "whois_server"); len(ws) != 0 {
		t.Errorf("an out-of-scope WHOIS server was linked: %v", ws)
	}
}

func TestRecordDetailRejectsAnotherRecordType(t *testing.T) {
	rd, sess := newTestRDAP(t)
	rec := sess.Asset(t, &oamreg.DomainRecord{Domain: "example.net"})
	if err := rd.autnum.check(&et.Event{Entity: rec, Session: sess, Dispatcher: &plugintest.Dispatcher{}}); err == nil {
		t.Error("the AutnumRecord handler accepted a DomainRecord")
	}
}
