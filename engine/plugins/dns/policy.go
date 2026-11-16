// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package dns

import (
	"context"
	"log/slog"
	"time"

	"github.com/miekg/dns"
	"github.com/owasp-amass/amass/v5/engine/plugins/support"
	et "github.com/owasp-amass/amass/v5/engine/types"
	dbt "github.com/owasp-amass/asset-db/types"
	oamdns "github.com/owasp-amass/open-asset-model/dns"
	"github.com/owasp-amass/open-asset-model/general"
)

// PolicyName is a name below a zone apex where a domain publishes a mail
// or security policy, or a key, as TXT records. These names are not found
// by brute forcing or scraping, so they are asked for at every apex.
type PolicyName struct {
	Label   string // the labels below the apex, such as "_dmarc"
	Purpose string // what the TXT records there say
	Source  string // the standard or the vendor documentation that names it
}

// PolicyNames are the policy names asked for at each zone apex. A DKIM
// selector is chosen by the sender, so only the selectors vendors document
// as fixed for every customer are listed.
var PolicyNames = []PolicyName{
	{Label: "_dmarc", Purpose: "DMARC policy", Source: "https://www.rfc-editor.org/rfc/rfc7489#section-6.1"},
	{Label: "_mta-sts", Purpose: "MTA-STS policy", Source: "https://www.rfc-editor.org/rfc/rfc8461#section-3.1"},
	{
		Label:   "_smtp._tls",
		Purpose: "SMTP TLS reporting policy",
		Source:  "https://www.rfc-editor.org/rfc/rfc8460#section-3",
	},
	{Label: "selector1._domainkey", Purpose: "DKIM key (Microsoft 365)",
		Source: "https://learn.microsoft.com/en-us/defender-office-365/email-authentication-dkim-configure"},
	{Label: "selector2._domainkey", Purpose: "DKIM key (Microsoft 365)",
		Source: "https://learn.microsoft.com/en-us/defender-office-365/email-authentication-dkim-configure"},
	{Label: "google._domainkey", Purpose: "DKIM key (Google Workspace default selector)",
		Source: "https://knowledge.workspace.google.com/admin/security/set-up-dkim"},
	{Label: "s1._domainkey", Purpose: "DKIM key (Twilio SendGrid)",
		Source: "https://www.twilio.com/docs/sendgrid/ui/account-and-settings/how-to-set-up-domain-authentication"},
	{Label: "s2._domainkey", Purpose: "DKIM key (Twilio SendGrid)",
		Source: "https://www.twilio.com/docs/sendgrid/ui/account-and-settings/how-to-set-up-domain-authentication"},
	{Label: "mte1._domainkey", Purpose: "DKIM key (Mailchimp Transactional)",
		Source: "https://mailchimp.com/developer/transactional/docs/authentication-delivery/"},
	{Label: "mte2._domainkey", Purpose: "DKIM key (Mailchimp Transactional)",
		Source: "https://mailchimp.com/developer/transactional/docs/authentication-delivery/"},
	{Label: "protonmail._domainkey", Purpose: "DKIM key (Proton Mail)",
		Source: "https://proton.me/support/anti-spoofing-custom-domain"},
	{Label: "protonmail2._domainkey", Purpose: "DKIM key (Proton Mail)",
		Source: "https://proton.me/support/anti-spoofing-custom-domain"},
	{Label: "protonmail3._domainkey", Purpose: "DKIM key (Proton Mail)",
		Source: "https://proton.me/support/anti-spoofing-custom-domain"},
	{Label: "fm1._domainkey", Purpose: "DKIM key (Fastmail)",
		Source: "https://www.fastmail.help/hc/en-us/articles/360060591153"},
	{Label: "fm2._domainkey", Purpose: "DKIM key (Fastmail)",
		Source: "https://www.fastmail.help/hc/en-us/articles/360060591153"},
	{Label: "fm3._domainkey", Purpose: "DKIM key (Fastmail)",
		Source: "https://www.fastmail.help/hc/en-us/articles/360060591153"},
}

// queryPolicies asks for the TXT records of each policy name below apex and
// stores those that answer as names below it, with their TXT records.
func (d *dnsSubs) queryPolicies(e *et.Event, apex *dbt.Entity, subdomain string) {
	type answer struct {
		name string
		rr   []dns.RR
	}

	ch := make(chan answer, len(PolicyNames))
	for _, p := range PolicyNames {
		go func(n string) {
			var txt []dns.RR
			if rr, err := support.PerformQuery(e.Session.Ctx(), n, dns.TypeTXT); err == nil {
				for _, r := range rr {
					if r.Header().Rrtype == dns.TypeTXT {
						txt = append(txt, r)
					}
				}
			} else if err == support.ErrFailedMaxDNSAttempts {
				e.Session.Log().Warn(err.Error(), "fqdn", n,
					slog.Group("plugin", "name", d.plugin.name, "handler", d.name))
			}

			ch <- answer{name: n, rr: txt}
		}(p.Label + "." + subdomain)
	}

	for range len(PolicyNames) {
		a := <-ch
		if len(a.rr) == 0 {
			continue
		}

		ctx, cancel := context.WithTimeout(e.Session.Ctx(), 5*time.Second)
		fqdn, err := e.Session.DB().CreateAsset(ctx, &oamdns.FQDN{Name: a.name})
		cancel()
		if err != nil || fqdn == nil {
			continue
		}

		d.plugin.txt.store(e, fqdn, a.rr)
		support.MarkAssetMonitored(e.Session, fqdn, d.plugin.txt.source)
		d.linkBelow(e, apex, fqdn)
		for _, r := range a.rr {
			e.Session.Log().Info("TXT record discovered", "fqdn", a.name, "txt", txtData(r.(*dns.TXT)),
				slog.Group("plugin", "name", d.plugin.name, "handler", d.name))
		}
	}
}

// linkBelow records that name is a node of the zone apex, as the apex
// handler does for names that resolve.
func (d *dnsSubs) linkBelow(e *et.Event, apex, name *dbt.Entity) {
	if apex == nil || name == nil || apex.ID == name.ID {
		return
	}

	ctx, cancel := context.WithTimeout(e.Session.Ctx(), 3*time.Second)
	defer cancel()

	_, _ = e.Session.DB().CreateEdge(ctx, &dbt.Edge{
		Relation:   &general.SimpleRelation{Name: "node"},
		FromEntity: apex,
		ToEntity:   name,
	})
}
