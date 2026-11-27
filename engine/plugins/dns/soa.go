// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package dns

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/miekg/dns"
	"github.com/owasp-amass/amass/v5/engine/plugins/support"
	et "github.com/owasp-amass/amass/v5/engine/types"
	dbt "github.com/owasp-amass/asset-db/types"
	oamdns "github.com/owasp-amass/open-asset-model/dns"
	"github.com/owasp-amass/open-asset-model/general"
)

// relSOARName links a zone apex to its administrator's mailbox.
const relSOARName = "soa_rname"

// querySOA asks for the apex's SOA record (RFC 1035 section 3.3.13) and
// stores what it names: the zone's primary name server (MNAME), as a DNS
// record to that name, dispatched when it is in scope (a hidden primary is
// often found nowhere else), and the zone administrator's mailbox (RNAME), as
// an email Identifier the apex links to.
func (d *dnsSubs) querySOA(e *et.Event, apex *dbt.Entity, name string) {
	if apex == nil {
		return
	}
	rr, err := support.PerformQuery(e.Session.Ctx(), name, dns.TypeSOA)
	if err != nil {
		return
	}
	for _, record := range rr {
		if soa, ok := record.(*dns.SOA); ok {
			d.storeSOA(e, apex, name, soa)
			return
		}
	}
}

func (d *dnsSubs) storeSOA(e *et.Event, apex *dbt.Entity, name string, soa *dns.SOA) {
	ctx, cancel := context.WithTimeout(e.Session.Ctx(), 30*time.Second)
	defer cancel()

	if mname := strings.ToLower(strings.TrimSuffix(soa.Ns, ".")); strings.Contains(mname, ".") {
		ns, err := e.Session.DB().CreateAsset(ctx, &oamdns.FQDN{Name: mname})
		if err == nil && ns != nil {
			_, _ = support.Relate(ctx, e.Session, apex, &oamdns.BasicDNSRelation{
				Name: "dns_record",
				Header: oamdns.RRHeader{
					RRType: int(dns.TypeSOA),
					Class:  int(soa.Header().Class),
					TTL:    int(soa.Header().Ttl),
				},
			}, ns, d.plugin.source)
			if _, conf := e.Session.Scope().IsAssetInScope(&oamdns.FQDN{Name: mname}, 0); conf > 0 {
				_ = e.Dispatcher.DispatchEvent(&et.Event{Name: mname, Entity: ns, Session: e.Session})
			}
		}
	}

	if mbox := soaMailbox(soa.Mbox); mbox != "" {
		id, err := e.Session.DB().CreateAsset(ctx, &general.Identifier{
			UniqueID: fmt.Sprintf("%s:%s", general.EmailAddress, mbox), ID: mbox, Type: general.EmailAddress,
		})
		if err == nil && id != nil {
			_, _ = support.Relate(ctx, e.Session, apex, &general.SimpleRelation{Name: relSOARName}, id, d.plugin.source)
		}
	}

	e.Session.Log().Info("SOA record discovered", "fqdn", name, "mname", soa.Ns, "rname", soa.Mbox,
		slog.Group("plugin", "name", d.plugin.name, "handler", d.name))
}

// soaMailbox turns an SOA RNAME into an email address: its first label is
// the local part, unless a backslash escapes that dot (john\.doe.example.com
// is john.doe@example.com). It returns "" for a value that is no address.
func soaMailbox(rname string) string {
	rname = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(rname), "."))
	var local strings.Builder
	for i := 0; i < len(rname); i++ {
		c := rname[i]
		switch {
		case c == '\\' && i+1 < len(rname):
			i++
			local.WriteByte(rname[i])
		case c == '.':
			domain := rname[i+1:]
			if local.Len() == 0 || !strings.Contains(domain, ".") {
				return ""
			}
			return local.String() + "@" + domain
		default:
			local.WriteByte(c)
		}
	}
	return ""
}
