// Copyright © by Jeff Foley 2017-2024. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package dns

import (
	"errors"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/caffix/stringset"
	"github.com/miekg/dns"
	dbt "github.com/owasp-amass/asset-db/types"
	"github.com/owasp-amass/engine/plugins/support"
	et "github.com/owasp-amass/engine/types"
	"github.com/owasp-amass/open-asset-model/domain"
	"github.com/owasp-amass/resolve"
	"golang.org/x/net/publicsuffix"
)

type subsQtypes struct {
	Qtype uint16
	Rtype string
}

type subsSession struct {
	session et.Session
	strset  *stringset.Set
}

type dnsSubs struct {
	sync.Mutex
	name      string
	types     []subsQtypes
	done      chan struct{}
	sessNames map[string]*subsSession
	plugin    *dnsPlugin
}

type relSubs struct {
	rtype  string
	alias  *dbt.Asset
	target *dbt.Asset
}

func NewSubs(p *dnsPlugin) *dnsSubs {
	return &dnsSubs{
		name: p.name + "-Subdomains",
		types: []subsQtypes{
			{Qtype: dns.TypeNS, Rtype: "ns_record"},
			{Qtype: dns.TypeMX, Rtype: "mx_record"},
			//{Qtype: dns.TypeSOA, Rtype: "soa_record"},
			//{Qtype: dns.TypeSPF, Rtype: "spf_record"},
		},
		done:      make(chan struct{}),
		sessNames: make(map[string]*subsSession),
		plugin:    p,
	}
}

func (d *dnsSubs) check(e *et.Event) error {
	fqdn, ok := e.Asset.Asset.(*domain.FQDN)
	if !ok {
		return errors.New("failed to extract the FQDN asset")
	}

	if !support.NameResolved(e.Session, fqdn) {
		return nil
	}

	dom := d.registered(e, fqdn.Name)
	if dom == "" {
		return nil
	}

	src := support.GetSource(e.Session, d.plugin.source)
	if src == nil {
		return errors.New("failed to obtain the plugin source information")
	}

	since, err := support.TTLStartTime(e.Session.Config(), "FQDN", "FQDN", d.plugin.name)
	if err != nil {
		return err
	}

	if names := d.traverse(e, dom, e.Asset, src, since); len(names) > 0 {
		d.process(e, names, src)
	}
	return nil
}

func (d *dnsSubs) registered(e *et.Event, name string) string {
	if a, conf := e.Session.Scope().IsAssetInScope(&domain.FQDN{Name: name}, 0); conf > 0 && a != nil {
		if fqdn, ok := a.(*domain.FQDN); ok {
			return fqdn.Name
		}
	}

	fqdn, hit := e.Session.Cache().GetAsset(&domain.FQDN{Name: name})
	if !hit || fqdn == nil {
		return ""
	}

	now := time.Now()
	var rels []*dbt.Relation
	// allow name servers and mail servers to be investigated like in-scope assets
	for _, rtype := range []string{"ns_record", "mx_record"} {
		if r, hit := e.Session.Cache().GetRelations(&dbt.Relation{
			Type:      rtype,
			CreatedAt: now,
			LastSeen:  now,
			ToAsset:   fqdn,
		}); hit && len(r) > 0 {
			rels = append(rels, r...)
		}
	}

	var inscope bool
	for _, r := range rels {
		if from, ok := r.FromAsset.Asset.(*domain.FQDN); ok && from != nil {
			if _, conf := e.Session.Scope().IsAssetInScope(from, 0); conf > 0 {
				inscope = true
				break
			}
		}
	}
	if inscope {
		if dom, err := publicsuffix.EffectiveTLDPlusOne(name); err == nil {
			return dom
		}
	}
	return ""
}

func (d *dnsSubs) traverse(e *et.Event, dom string, fqdn, src *dbt.Asset, since time.Time) []*relSubs {
	var alias []*relSubs

	dlabels := strings.Split(dom, ".")
	dlen := len(dlabels)
	if dlen < 2 {
		return alias
	}

	sub := fqdn.Asset.Key()
	for labels := strings.Split(sub, "."); dlen <= len(labels); labels = labels[1:] {
		sub = strings.TrimSpace(strings.Join(labels, "."))

		// no need to check subdomains already evaluated
		if d.fqdnAvailable(e, sub) {
			results := d.lookup(e, sub, since)
			if len(results) == 0 {
				results = d.query(e, sub, src)
			}
			alias = append(alias, results...)
		}
	}

	return alias
}

func (d *dnsSubs) lookup(e *et.Event, subdomain string, since time.Time) []*relSubs {
	var alias []*relSubs

	done := make(chan *dbt.Asset, 1)
	defer close(done)

	support.AppendToDBQueue(func() {
		if e.Session.Done() {
			done <- nil
			return
		}

		fqdns, err := e.Session.DB().FindByContent(&domain.FQDN{Name: subdomain}, time.Time{})
		if err != nil || len(fqdns) == 0 {
			done <- nil
			return
		}

		var id string
		for _, name := range fqdns {
			if n, ok := name.Asset.(*domain.FQDN); ok && n.Name == subdomain {
				id = name.ID
				break
			}
		}
		if id == "" {
			done <- nil
			return
		}

		fqdn, _ := e.Session.DB().FindById(id, time.Time{})
		done <- fqdn
	})

	fqdn := <-done
	if fqdn == nil {
		return alias
	}

	n := fqdn.Asset.Key()
	if assets := d.plugin.lookupWithinTTL(e.Session, n, "FQDN", since, "ns_record"); len(assets) > 0 {
		for _, a := range assets {
			alias = append(alias, &relSubs{rtype: "ns_record", alias: fqdn, target: a})
		}
	}
	if assets := d.plugin.lookupWithinTTL(e.Session, n, "FQDN", since, "mx_record"); len(assets) > 0 {
		for _, a := range assets {
			alias = append(alias, &relSubs{rtype: "mx_record", alias: fqdn, target: a})
		}
	}
	return alias
}

func (d *dnsSubs) query(e *et.Event, subdomain string, src *dbt.Asset) []*relSubs {
	apex := true
	var alias []*relSubs

	for i, t := range d.types {
		if rr, err := support.PerformQuery(subdomain, t.Qtype); err == nil && len(rr) > 0 {
			if records := d.store(e, subdomain, src, rr); len(records) > 0 {
				alias = append(alias, records...)
			}
		} else if i == 0 {
			// do not continue if we failed to obtain the NS record
			apex = false
			break
		}
	}

	if !apex {
		return alias
	}

	rch := make(chan []*relSubs, len(srvNames))
	defer close(rch)

	for _, name := range srvNames {
		go func(label, sub string, ch chan []*relSubs) {
			n := name + "." + subdomain

			var results []*relSubs
			if rr, err := support.PerformQuery(n, dns.TypeSRV); err == nil && len(rr) > 0 {
				if records := d.store(e, n, src, rr); len(records) > 0 {
					results = append(results, records...)
				}
			}
			ch <- results
		}(name, subdomain, rch)
	}

	for i := 0; i < len(srvNames); i++ {
		answers := <-rch
		alias = append(alias, answers...)
	}

	return alias
}

func (d *dnsSubs) store(e *et.Event, name string, src *dbt.Asset, rr []*resolve.ExtractedAnswer) []*relSubs {
	var alias []*relSubs

	done := make(chan struct{}, 1)
	support.AppendToDBQueue(func() {
		defer func() { done <- struct{}{} }()

		if e.Session.Done() {
			return
		}

		fqdn, err := e.Session.DB().Create(nil, "", &domain.FQDN{Name: name})
		if err != nil || fqdn == nil {
			return
		}

		for _, record := range rr {
			var relation string

			if record.Type == dns.TypeNS {
				relation = "ns_record"
			} else if record.Type == dns.TypeMX {
				relation = "mx_record"
			} else {
				continue
			}

			if a, err := e.Session.DB().Create(fqdn, relation, &domain.FQDN{Name: record.Data}); err == nil {
				if a != nil {
					_, _ = e.Session.DB().Link(a, "source", src)
					alias = append(alias, &relSubs{rtype: relation, alias: fqdn, target: a})
				}
			} else {
				e.Session.Log().Error(err.Error(), slog.Group("plugin", "name", d.plugin.name, "handler", d.name))
			}
		}
	})
	<-done
	close(done)
	return alias
}

func (d *dnsSubs) process(e *et.Event, results []*relSubs, src *dbt.Asset) {
	for _, finding := range results {
		fname, ok := finding.alias.Asset.(*domain.FQDN)
		if !ok || fname == nil {
			continue
		}

		_ = e.Dispatcher.DispatchEvent(&et.Event{
			Name:    fname.Name,
			Asset:   finding.alias,
			Session: e.Session,
		})

		tname, ok := finding.target.Asset.(*domain.FQDN)
		if !ok || tname == nil {
			continue
		}

		_ = e.Dispatcher.DispatchEvent(&et.Event{
			Name:    tname.Name,
			Asset:   finding.target,
			Session: e.Session,
		})

		if from, hit := e.Session.Cache().GetAsset(finding.alias.Asset); hit && from != nil {
			if to, hit := e.Session.Cache().GetAsset(finding.target.Asset); hit && to != nil {
				now := time.Now()

				e.Session.Cache().SetRelation(&dbt.Relation{
					Type:      finding.rtype,
					CreatedAt: now,
					LastSeen:  now,
					FromAsset: from,
					ToAsset:   to,
				})

				e.Session.Cache().SetRelation(&dbt.Relation{
					Type:      "source",
					CreatedAt: now,
					LastSeen:  now,
					FromAsset: to,
					ToAsset:   src,
				})

				e.Session.Log().Info("relationship discovered", "from",
					fname.Name, "relation", finding.rtype, "to", tname.Name,
					slog.Group("plugin", "name", d.plugin.name, "handler", d.name))
			}
		}
	}
}

func (d *dnsSubs) fqdnAvailable(e *et.Event, fqdn string) bool {
	d.Lock()
	defer d.Unlock()

	id := e.Session.ID().String()
	if _, found := d.sessNames[id]; !found {
		d.sessNames[id] = &subsSession{
			session: e.Session,
			strset:  stringset.New(),
		}
	}

	var avail bool
	if !d.sessNames[id].strset.Has(fqdn) {
		avail = true
		d.sessNames[id].strset.Insert(fqdn)
	}
	return avail
}

func (d *dnsSubs) releaseSessions() {
	t := time.NewTicker(time.Minute)
	defer t.Stop()
loop:
	for {
		select {
		case <-d.done:
			break loop
		case <-t.C:
			d.Lock()
			var ids []string
			for id, s := range d.sessNames {
				if s.session.Done() {
					ids = append(ids, id)
					s.strset.Close()
				}
			}
			for _, id := range ids {
				delete(d.sessNames, id)
			}
			d.Unlock()
		}
	}

	d.Lock()
	for _, sess := range d.sessNames {
		sess.strset.Close()
	}
	d.Unlock()
}

var srvNames = []string{
	"_afs3-kaserver._tcp",
	"_afs3-kaserver._tcp",
	"_afs3-kaserver._udp",
	"_afs3-prserver._tcp",
	"_afs3-prserver._udp",
	"_afs3-vlserver._tcp",
	"_afs3-vlserver._udp",
	"_amt._udp",
	"_autodiscover._tcp",
	"_autotunnel._udp",
	"_avatars-sec._tcp",
	"_avatars._tcp",
	"_bittorrent-tracker._tcp",
	"_caldav._tcp",
	"_caldavs._tcp",
	"_carddav._tcp",
	"_carddavs._tcp",
	"_ceph-mon._tcp",
	"_ceph._tcp",
	"_certificates._tcp",
	"_chat._udp",
	"_citrixreceiver._tcp",
	"_collab-edge._tls",
	"_crls._tcp",
	"_daap._tcp",
	"_diameters._tcp",
	"_diameter._tcp",
	"_diameter._tls",
	"_dns-llq._tcp",
	"_dns-llq-tls._tcp",
	"_dns-llq-tls._udp",
	"_dns-llq._udp",
	"_dns-push-tls._tcp",
	"_dns-sd._udp",
	"_dns._udp",
	"_dns-update._tcp",
	"_dns-update-tls._tcp",
	"_dns-update._udp",
	"_dots-call-home._tcp",
	"_dots-call-home._udp",
	"_dots-data._tcp",
	"_dots-signal._tcp",
	"_dots-signal._udp",
	"_dvbservdsc._tcp",
	"_dvbservdsc._udp",
	"_ftp._tcp",
	"_gc._tcp",
	"_hip-nat-t._udp",
	"_http._tcp",
	"_hybrid-pop._tcp",
	"_hybrid-pop._udp",
	"_imap3._tcp",
	"_imap3._udp",
	"_imaps._tcp",
	"_imaps._udp",
	"_imap._tcp",
	"_imap._udp",
	"_imps-server._tcp",
	"_ipp._tcp",
	"_jabber._tcp",
	"_jmap._tcp",
	"_kca._udp",
	"_kerberos-adm._tcp",
	"_kerberos-adm._udp",
	"_kerberos-master._tcp",
	"_kerberos-master._udp",
	"_kerberos._tcp",
	"_kerberos-tls._tcp",
	"_kerberos._udp",
	"_kerneros-iv._udp",
	"_kftp-data._tcp",
	"_kftp-data._udp",
	"_kftp._tcp",
	"_kftp._udp",
	"_kpasswd._tcp",
	"_kpasswd._udp",
	"_ktelnet._tcp",
	"_ktelnet._udp",
	"_ldap-admin._tcp",
	"_ldap-admin._udp",
	"_ldaps._tcp",
	"_ldaps._udp",
	"_ldap._tcp",
	"_ldap._udp",
	"_matrix._tcp",
	"_matrix-vnet._tcp",
	"_MIHIS._tcp",
	"_MIHIS._udp",
	"_minecraft._tcp",
	"_msft-gc-ssl._tcp",
	"_msft-gc-ssl._udp",
	"_msrps._tcp",
	"_mtqp._tcp",
	"_nfs-domainroot._tcp",
	"_nicname._tcp",
	"_nicname._udp",
	"_ntp._udp",
	"_pop2._tcp",
	"_pop2._udp",
	"_pop3s._tcp",
	"_pop3s._udp",
	"_pop3._tcp",
	"_pop3._udp",
	"_presence._tcp",
	"_presence._udp",
	"_puppet._tcp",
	"_radiusdtls._udp",
	"_radiustls._tcp",
	"_radiustls._udp",
	"_radsec._tcp",
	"_rwhois._tcp",
	"_rwhois._udp",
	"_sieve._tcp",
	"_sips._tcp",
	"_sips._udp",
	"_sip._tcp",
	"_sip._udp",
	"_slpda._tcp",
	"_slpda._udp",
	"_slp._tcp",
	"_slp._udp",
	"_smtp._tcp",
	"_smtp._tls",
	"_smtp._udp",
	"_soap-beep._tcp",
	"_ssh._tcp",
	"_stun-behaviors._tcp",
	"_stun-behaviors._udp",
	"_stun-behavior._tcp",
	"_stun-behavior._udp",
	"_stun-p1._tcp",
	"_stun-p1._udp",
	"_stun-p2._tcp",
	"_stun-p2._udp",
	"_stun-p3._tcp",
	"_stun-p3._udp",
	"_stun-port._tcp",
	"_stun-port._udp",
	"_stuns._tcp",
	"_stuns._udp",
	"_stun._tcp",
	"_stun._udp",
	"_submissions._tcp",
	"_submission._tcp",
	"_submission._udp",
	"_sztp._tcp",
	"_telnet._tcp",
	"_timezones._tcp",
	"_timezone._tcp",
	"_ts3._udp",
	"_tsdns._tcp",
	"_tunnel._tcp",
	"_turns._tcp",
	"_turns._udp",
	"_turn._tcp",
	"_turn._udp",
	"_whoispp._tcp",
	"_whoispp._udp",
	"_www-http._tcp",
	"_www-ldap-gw._tcp",
	"_www-ldap-gw._udp",
	"_www._tcp",
	"_xmlrpc-beep._tcp",
	"_xmpp-bosh._tcp",
	"_xmpp-client._tcp",
	"_xmpp-client._udp",
	"_xmpp-server._tcp",
	"_xmpp-server._udp",
	"_xmpp._tcp",
	"_x-puppet._tcp",
}
