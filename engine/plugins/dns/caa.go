// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package dns

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/miekg/dns"
	"github.com/owasp-amass/amass/v5/engine/plugins/support"
	et "github.com/owasp-amass/amass/v5/engine/types"
	dbt "github.com/owasp-amass/asset-db/types"
	oamdns "github.com/owasp-amass/open-asset-model/dns"
)

// queryCAA asks for the apex's CAA records and stores each as a DNS record
// property. CAA lists the certificate authorities allowed to issue for the
// domain, so the certificates lens can report which CAs may issue and flag a
// domain that authorizes any CA (no CAA policy).
func (d *dnsSubs) queryCAA(e *et.Event, apex *dbt.Entity, name string) {
	if apex == nil {
		return
	}

	rr, err := support.PerformQuery(e.Session.Ctx(), name, dns.TypeCAA)
	if err != nil || len(rr) == 0 {
		return
	}
	d.storeCAA(e, apex, name, rr)
}

func (d *dnsSubs) storeCAA(e *et.Event, apex *dbt.Entity, name string, rr []dns.RR) {
	ctx, cancel := context.WithTimeout(e.Session.Ctx(), 30*time.Second)
	defer cancel()

	for _, record := range rr {
		caa, ok := record.(*dns.CAA)
		if !ok {
			continue
		}

		if _, err := e.Session.DB().CreateEntityProperty(ctx, apex, &oamdns.DNSRecordProperty{
			PropertyName: "dns_record",
			Header: oamdns.RRHeader{
				RRType: int(dns.TypeCAA),
				Class:  int(record.Header().Class),
				TTL:    int(record.Header().Ttl),
			},
			Data: caaData(caa),
		}); err != nil {
			e.Session.Log().Error("failed to store the CAA record", "fqdn", name, "error", err.Error(),
				slog.Group("plugin", "name", d.plugin.name, "handler", d.name))
		} else {
			e.Session.Log().Info("CAA record discovered", "fqdn", name, "caa", caaData(caa),
				slog.Group("plugin", "name", d.plugin.name, "handler", d.name))
		}
	}
}

// caaData renders a CAA record's rdata as `<flags> <tag> "<value>"`, such as
// `0 issue "letsencrypt.org"`.
func caaData(caa *dns.CAA) string {
	return fmt.Sprintf("%d %s %q", caa.Flag, caa.Tag, caa.Value)
}
