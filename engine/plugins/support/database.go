// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package support

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	amassdb "github.com/owasp-amass/amass/v5/internal/db"
	"log/slog"
	"strings"
	"time"

	et "github.com/owasp-amass/amass/v5/engine/types"
	dbt "github.com/owasp-amass/asset-db/types"
	oam "github.com/owasp-amass/open-asset-model"
	oamcert "github.com/owasp-amass/open-asset-model/certificate"
	oamdns "github.com/owasp-amass/open-asset-model/dns"
	oamgen "github.com/owasp-amass/open-asset-model/general"
	oamnet "github.com/owasp-amass/open-asset-model/network"
	oamplat "github.com/owasp-amass/open-asset-model/platform"
)

func StoreFQDNsWithSource(session et.Session, names []string, src *et.Source, plugin, handler string) []*dbt.Entity {
	var results []*dbt.Entity

	if len(names) == 0 || src == nil {
		return results
	}

	ctx, cancel := context.WithTimeout(session.Ctx(), 30*time.Second)
	defer cancel()

	for _, name := range names {
		if a, err := session.DB().CreateAsset(ctx, &oamdns.FQDN{Name: name}); err == nil && a != nil {
			results = append(results, a)
			_, _ = session.DB().CreateEntityProperty(ctx, a, &oamgen.SourceProperty{
				Source:     src.Name,
				Confidence: src.Confidence,
			})
		} else {
			session.Log().Error(err.Error(), slog.Group("plugin", "name", plugin, "handler", handler))
		}
	}

	return results
}

func StoreEmailsWithSource(session et.Session, emails []string, src *et.Source, plugin, handler string) []*dbt.Entity {
	var results []*dbt.Entity

	if len(emails) == 0 || src == nil {
		return results
	}

	ctx, cancel := context.WithTimeout(session.Ctx(), 30*time.Second)
	defer cancel()

	for _, e := range emails {
		email := strings.ToLower(e)

		if a, err := session.DB().CreateAsset(ctx, &oamgen.Identifier{
			UniqueID: fmt.Sprintf("%s:%s", oamgen.EmailAddress, email),
			ID:       email,
			Type:     oamgen.EmailAddress,
		}); err == nil && a != nil {
			results = append(results, a)
			_, _ = session.DB().CreateEntityProperty(ctx, a, &oamgen.SourceProperty{
				Source:     src.Name,
				Confidence: src.Confidence,
			})
		} else {
			session.Log().Error(err.Error(), slog.Group("plugin", "name", plugin, "handler", handler))
		}
	}

	return results
}

func CreateServiceAsset(session et.Session, src *dbt.Entity, rel oam.Relation, serv *oamplat.Service, cert *oamcert.TLSCertificate) (*dbt.Entity, error) {
	var srvs []*dbt.Entity

	ctx, cancel := context.WithTimeout(session.Ctx(), 30*time.Second)
	defer cancel()

	if rport, ok := rel.(*oamgen.PortRelation); ok && src != nil && serv != nil {
		srcs := []*dbt.Entity{src}

		if _, ok := src.Asset.(*oamdns.FQDN); ok {
			// check for IP assresses associated with the FQDN
			if edges, err := session.DB().OutgoingEdges(ctx, src, time.Time{}, "dns_record"); err == nil && len(edges) > 0 {
				ends := amassdb.EdgeEnds(ctx, session.DB(), edges, false)
				for _, edge := range edges {
					if to, ok := ends[edge.ToEntity.ID]; ok {
						if _, ok := to.Asset.(*oamnet.IPAddress); ok {
							srcs = append(srcs, to)
						}
					}
				}
			}
		}

		// go though the hosts that could have previously associated with the service
		for _, s := range srcs {
			if edges, err := session.DB().OutgoingEdges(ctx, s, time.Time{}); err == nil && len(edges) > 0 {
				var ports []*dbt.Edge
				for _, edge := range edges {
					if eport, ok := edge.Relation.(*oamgen.PortRelation); ok &&
						eport.PortNumber == rport.PortNumber && strings.EqualFold(eport.Protocol, rport.Protocol) {
						ports = append(ports, edge)
					}
				}

				ends := amassdb.EdgeEnds(ctx, session.DB(), ports, false)
				for _, edge := range ports {
					if to, ok := ends[edge.ToEntity.ID]; ok {
						if srv, ok := to.Asset.(*oamplat.Service); ok && srv.OutputLen != 0 && srv.OutputLen == serv.OutputLen {
							srvs = append(srvs, to)
						}
					}
				}
			}
		}
	}

	var match *dbt.Entity
	for _, srv := range srvs {
		var num int

		s, valid := srv.Asset.(*oamplat.Service)
		if !valid {
			continue
		}

		// compare some of the service attributes to find a match; a header
		// may be stored with no values
		for _, key := range []string{"Server", "X-Powered-By"} {
			if server1 := serv.Attributes[key]; len(server1) > 0 && server1[0] != "" {
				if server2 := s.Attributes[key]; len(server2) > 0 && server1[0] == server2[0] {
					num++
				} else {
					num--
				}
			}
		}

		if cert != nil {
			if edges, err := session.DB().OutgoingEdges(ctx, srv, time.Time{}, "certificate"); err == nil && len(edges) > 0 {
				var found bool

				ends := amassdb.EdgeEnds(ctx, session.DB(), edges, false)
				for _, edge := range edges {
					if t, ok := ends[edge.ToEntity.ID]; ok {
						if c, ok := t.Asset.(*oamcert.TLSCertificate); ok && SameCertificate(c, cert) {
							found = true
							break
						}
					}
				}

				if found {
					num++
				} else {
					continue
				}
			}
		}

		if num > 0 {
			match = srv
			break
		}
	}

	if match == nil {
		if a, err := session.DB().CreateAsset(ctx, serv); err == nil && a != nil {
			match = a
		} else {
			return nil, errors.New("failed to create the OAM Service asset")
		}
	}

	_, err := session.DB().CreateEdge(ctx, &dbt.Edge{
		Relation:   rel,
		FromEntity: src,
		ToEntity:   match,
	})
	return match, err
}

// CreateCertificateChain stores the certificates a server presented, leaf
// first, and returns the leaf's entity and certificate with the findings
// that link each certificate to its issuer's.
func CreateCertificateChain(sess et.Session, certs []*x509.Certificate) (*dbt.Entity, *x509.Certificate, []*Finding) {
	if len(certs) == 0 {
		return nil, nil, nil
	}

	dur := time.Duration(len(certs)*3) * time.Second
	ctx, cancel := context.WithTimeout(sess.Ctx(), dur)
	defer cancel()

	var findings []*Finding
	var prev, firstAsset *dbt.Entity
	var firstCert *x509.Certificate
	for _, cert := range certs {
		c := X509ToOAMTLSCertificate(cert)
		if c == nil {
			break
		}

		a, err := sess.DB().CreateAsset(ctx, c)
		if err != nil {
			break
		}

		if prev == nil {
			firstAsset = a
			firstCert = cert
		} else if tls, valid := prev.Asset.(*oamcert.TLSCertificate); valid {
			findings = append(findings, &Finding{
				From:     prev,
				FromName: tls.SerialNumber,
				To:       a,
				ToName:   c.SerialNumber,
				ToMeta:   cert,
				Rel:      &oamgen.SimpleRelation{Name: "issuing_certificate"},
			})
		}
		prev = a
	}

	return firstAsset, firstCert, findings
}

// SameCertificate reports whether two certificates are one: the same serial
// number from the same issuer (RFC 5280 makes serial numbers unique per issuer
// only), with the same key, as the Asset Database identifies a certificate.
func SameCertificate(a, b *oamcert.TLSCertificate) bool {
	if a == nil || b == nil {
		return false
	}

	return a.SerialNumber == b.SerialNumber && strings.EqualFold(a.IssuerCommonName, b.IssuerCommonName) &&
		strings.EqualFold(a.AuthorityKeyID, b.AuthorityKeyID) && strings.EqualFold(a.SubjectKeyID, b.SubjectKeyID)
}
