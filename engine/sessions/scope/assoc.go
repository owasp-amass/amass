// Copyright © by Jeff Foley 2017-2025. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package scope

import (
	"errors"
	"fmt"
	"net/netip"
	"strings"

	"github.com/adrg/strutil"
	"github.com/adrg/strutil/metrics"
	"github.com/caffix/stringset"
	"github.com/owasp-amass/asset-db/cache"
	dbt "github.com/owasp-amass/asset-db/types"
	oam "github.com/owasp-amass/open-asset-model"
	oamcert "github.com/owasp-amass/open-asset-model/certificate"
	"github.com/owasp-amass/open-asset-model/contact"
	"github.com/owasp-amass/open-asset-model/dns"
	oamnet "github.com/owasp-amass/open-asset-model/network"
	"github.com/owasp-amass/open-asset-model/org"
	oamreg "github.com/owasp-amass/open-asset-model/registration"
	oamurl "github.com/owasp-amass/open-asset-model/url"
	"golang.org/x/net/publicsuffix"
)

type Association struct {
	Submission     *dbt.Entity
	Match          *dbt.Entity
	Rationale      string
	Confidence     int
	ScopeChange    bool
	ImpactedAssets []*dbt.Entity
}

func (s *Scope) IsAssociated(c *cache.Cache, req *Association) ([]*Association, error) {
	if req == nil || req.Submission == nil || req.Submission.Asset == nil || req.Confidence < 0 || req.Confidence > 100 {
		return nil, errors.New("invalid request")
	}
	if atype := req.Submission.Asset.AssetType(); atype != oam.FQDN &&
		atype != oam.Identifier && atype != oam.Organization && atype != oam.Location {
		return nil, errors.New("the request included a submission with an unsupported asset type")
	}

	// related assets that provide association matching value
	assocs := s.AssetsWithAssociation(c, req.Submission)
	// are any of these assets in the current session scope?
	results := s.checkRelatedAssetsforAssoc(c, req, assocs)

	if req.ScopeChange {
		// add all assets related to the asset found to be associated
		for _, result := range results {
			var impacted []*dbt.Entity

			for _, im := range append(result.ImpactedAssets, result.Match) {
				if s.Add(im.Asset) {
					impacted = append(impacted, im)
				}
			}
			// review all previously seen assets that provide association for scope changes
			for size := len(impacted); size > 0; {
				added := s.reviewAndUpdate(c, req)

				size = len(added)
				impacted = append(impacted, added...)
			}

			result.ImpactedAssets = impacted
			if len(result.ImpactedAssets) > 0 {
				result.ScopeChange = true
				s.addScopeChangesToRationale(result)
			}
		}
	}

	if len(results) == 0 {
		return nil, errors.New("the submission is not associated with assets in the session scope")
	}
	return results, nil
}

func (s *Scope) addScopeChangesToRationale(result *Association) {
	var changes []string

	for _, im := range result.ImpactedAssets {
		changes = append(changes, fmt.Sprintf("[%s: %s]", im.Asset.AssetType(), im.Asset.Key()))
	}

	result.Rationale += ". The following assets were added to the session scope: " + strings.Join(changes, ", ")
}

func (s *Scope) reviewAndUpdate(c *cache.Cache, req *Association) []*dbt.Entity {
	var assocs []*dbt.Entity

	if drs, err := c.FindEntitiesByType(oam.DomainRecord, c.StartTime()); err == nil && len(drs) > 0 {
		assocs = append(assocs, drs...)
	}
	if iprecs, err := c.FindEntitiesByType(oam.IPNetRecord, c.StartTime()); err == nil && len(iprecs) > 0 {
		assocs = append(assocs, iprecs...)
	}
	if autnums, err := c.FindEntitiesByType(oam.AutnumRecord, c.StartTime()); err == nil && len(autnums) > 0 {
		assocs = append(assocs, autnums...)
	}
	if certs, err := c.FindEntitiesByType(oam.TLSCertificate, c.StartTime()); err == nil && len(certs) > 0 {
		assocs = append(assocs, certs...)
	}

	var impacted []*dbt.Entity
	for _, assoc := range s.checkRelatedAssetsforAssoc(c, req, assocs) {
		for _, a := range append(assoc.ImpactedAssets, assoc.Match) {
			if s.Add(a.Asset) {
				impacted = append(impacted, a)
			}
		}
	}
	return impacted
}

func (s *Scope) checkRelatedAssetsforAssoc(c *cache.Cache, req *Association, assocs []*dbt.Entity) []*Association {
	var results []*Association

	for _, assoc := range assocs {
		var best int
		var msg string

		var impacted []*dbt.Entity
		for _, asset := range append(s.assetsRelatedToAssetWithAssoc(c, assoc), assoc) {
			if req.ScopeChange {
				impacted = append(impacted, asset)
			}
			if match, conf := s.IsAssetInScope(asset.Asset, req.Confidence); conf > 0 {
				if conf > best {
					best = conf

					aa := assoc.Asset
					sa := req.Submission.Asset
					msg = fmt.Sprintf("[%s: %s] is related to an asset with associative value [%s: %s], ", sa.AssetType(), sa.Key(), aa.AssetType(), aa.Key())
					msg += fmt.Sprintf("which has a related asset [%s: %s] that was determined associated with [%s: %s] at a confidence of %d out of 100",
						asset.Asset.AssetType(), asset.Asset.Key(), match.AssetType(), match.Key(), conf)
				}
			}
		}

		if best > 0 {
			results = append(results, &Association{
				Submission:     req.Submission,
				Match:          assoc,
				Rationale:      msg,
				Confidence:     best,
				ImpactedAssets: impacted,
			})
		}
	}
	return results
}

func (s *Scope) assetsRelatedToAssetWithAssoc(c *cache.Cache, assoc *dbt.Entity) []*dbt.Entity {
	set := stringset.New(assoc.ID)
	defer set.Close()

	var results []*dbt.Entity
	for findings := []*dbt.Entity{assoc}; len(findings) > 0; {
		assets := findings
		findings = []*dbt.Entity{}

		for _, a := range assets {
			var found bool

			switch v := a.Asset.(type) {
			case *org.Organization:
				found = true
				if cert, ok := assoc.Asset.(*oamcert.TLSCertificate); !ok || s.orgNameSimilarToCommon(v, cert) {
					results = append(results, a)
				}
			case *contact.Location:
				found = true
				results = append(results, a)
			}

			if !found {
				if f, err := s.awayFromAssetsWithAssociation(c, a); err == nil && len(f) > 0 {
					for _, finding := range f {
						if !set.Has(finding.ID) {
							set.Insert(finding.ID)
							findings = append(findings, finding)
						}
					}
				}
			}
		}
	}
	return results
}

func (s *Scope) AssetsWithAssociation(c *cache.Cache, asset *dbt.Entity) []*dbt.Entity {
	set := stringset.New(asset.ID)
	defer set.Close()

	var results []*dbt.Entity
	for findings := []*dbt.Entity{asset}; len(findings) > 0; {
		assets := findings
		findings = []*dbt.Entity{}

		for _, a := range assets {
			var found bool

			switch a.Asset.(type) {
			case *oamreg.DomainRecord:
				found = true
				results = append(results, a)
			case *oamreg.IPNetRecord:
				found = true
				results = append(results, a)
			case *oamreg.AutnumRecord:
				found = true
				results = append(results, a)
			case *oamcert.TLSCertificate:
				found = true
				// only certificates directly used by the services are considered
				if _, err := c.IncomingEdges(a, c.StartTime(), "certificate"); err == nil {
					results = append(results, a)
				}
			}

			if !found {
				if f, err := s.towardsAssetsWithAssociation(c, a); err == nil && len(f) > 0 {
					for _, finding := range f {
						if !set.Has(finding.ID) {
							set.Insert(finding.ID)
							findings = append(findings, finding)
						}
					}
				}
			}
		}
	}
	return results
}

func (s *Scope) awayFromAssetsWithAssociation(c *cache.Cache, assoc *dbt.Entity) ([]*dbt.Entity, error) {
	var results []*dbt.Entity
	// Determine relationship directions to follow on the graph
	var out, in bool
	var outRels, inRels []string
	switch assoc.Asset.AssetType() {
	case oam.FQDN:
		out = true
		outRels = append(outRels, "port")
	case oam.IPAddress:
		out = true
		outRels = append(outRels, "port")
		in = true
		inRels = append(inRels, "dns_record")
	case oam.Netblock:
		out = true
		outRels = append(outRels, "contains")
	case oam.AutonomousSystem:
		out = true
		outRels = append(outRels, "announces")
	case oam.DomainRecord:
		out = true
		outRels = append(outRels, "registrant_contact")
	case oam.IPNetRecord:
		out = true
		outRels = append(outRels, "registrant")
		in = true
		inRels = append(inRels, "registration")
	case oam.AutnumRecord:
		out = true
		outRels = append(outRels, "registrant")
		in = true
		inRels = append(inRels, "registration")
	case oam.TLSCertificate:
		out = true
		outRels = append(outRels, "subject_contact")
	case oam.ContactRecord:
		out = true
		outRels = append(outRels, "organization", "location")
	}
	if out {
		if edges, err := c.OutgoingEdges(assoc, c.StartTime(), outRels...); err == nil && len(edges) > 0 {
			for _, edge := range edges {
				if entity, err := c.FindEntityById(edge.ToEntity.ID); err == nil && entity != nil {
					results = append(results, entity)
				}
			}
		}
	}
	if in {
		if edges, err := c.IncomingEdges(assoc, c.StartTime(), inRels...); err == nil && len(edges) > 0 {
			for _, edge := range edges {
				if entity, err := c.FindEntityById(edge.FromEntity.ID); err == nil && entity != nil {
					results = append(results, entity)
				}
			}
		}
	}
	if len(results) == 0 {
		return nil, errors.New("zero assets were found in-scope one hop forward from the provided asset")
	}
	return results, nil
}

func (s *Scope) towardsAssetsWithAssociation(c *cache.Cache, asset *dbt.Entity) ([]*dbt.Entity, error) {
	var results []*dbt.Entity
	// Determine relationship directions to follow on the graph
	var out, in bool
	var outRels, inRels []string
	switch asset.Asset.AssetType() {
	case oam.FQDN:
		out = true
		outRels = append(outRels, "registration")
		in = true
		inRels = append(inRels, "node")
	case oam.IPAddress:
		in = true
		inRels = append(inRels, "contains")
	case oam.Netblock:
		out = true
		outRels = append(outRels, "registration")
	case oam.AutonomousSystem:
		out = true
		outRels = append(outRels, "registration")
	case oam.Organization:
		in = true
		inRels = append(inRels, "organization")
	case oam.Location:
		in = true
		inRels = append(inRels, "location")
	case oam.ContactRecord:
		in = true
		inRels = append(inRels, "registrant", "registrant_contact", "subject_contact")
	case oam.Service:
		in = true
		inRels = append(inRels, "port")
	}
	if out {
		if edges, err := c.OutgoingEdges(asset, c.StartTime(), outRels...); err == nil && len(edges) > 0 {
			for _, edge := range edges {
				if entity, err := c.FindEntityById(edge.ToEntity.ID); err == nil && entity != nil {
					results = append(results, entity)
				}
			}
		}
	}
	if in {
		if edges, err := c.IncomingEdges(asset, c.StartTime(), inRels...); err == nil && len(edges) > 0 {
			for _, edge := range edges {
				if entity, err := c.FindEntityById(edge.FromEntity.ID); err == nil && entity != nil {
					results = append(results, entity)
				}
			}
		}
	}
	if len(results) == 0 {
		return nil, errors.New("zero assets were found in-scope one hop forward from the provided asset")
	}
	return results, nil
}

func (s *Scope) IsAddressInScope(c *cache.Cache, ip *oamnet.IPAddress) bool {
	if _, conf := s.IsAssetInScope(ip, 0); conf > 0 {
		return true
	}

	addrs, err := c.FindEntitiesByContent(ip, c.StartTime())
	if err != nil || len(addrs) != 1 {
		return false
	}
	addr := addrs[0]

	rtype := 1
	if ip.Type == "IPv6" {
		rtype = 28
	}

	if edges, err := c.IncomingEdges(addr, c.StartTime(), "dns_record"); err == nil && len(edges) > 0 {
		for _, edge := range edges {
			if rec, ok := edge.Relation.(*dns.BasicDNSRelation); ok && rec.Header.RRType == rtype {
				from, err := c.FindEntityById(edge.FromEntity.ID)
				if err != nil {
					continue
				}
				if _, conf := s.IsAssetInScope(from.Asset, 0); conf > 0 {
					return true
				}
			}
		}
	}
	return false
}

func (s *Scope) IsURLInScope(c *cache.Cache, u *oamurl.URL) bool {
	if ip, err := netip.ParseAddr(u.Host); err == nil {
		ntype := "IPv4"
		if ip.Is6() {
			ntype = "IPv6"
		}

		return s.IsAddressInScope(c, &oamnet.IPAddress{
			Address: ip,
			Type:    ntype,
		})
	}

	_, conf := s.IsAssetInScope(u, 0)
	return conf > 0
}

func (s *Scope) orgNameSimilarToCommon(o *org.Organization, cert *oamcert.TLSCertificate) bool {
	swg := metrics.NewSmithWatermanGotoh()
	swg.CaseSensitive = false
	swg.GapPenalty = -0.1
	swg.Substitution = metrics.MatchMismatch{
		Match:    1,
		Mismatch: -0.5,
	}

	dom, err := publicsuffix.EffectiveTLDPlusOne(cert.SubjectCommonName)
	if err != nil {
		return false
	}

	labels := strings.Split(dom, ".")
	if len(labels) < 2 {
		return false
	}

	common := labels[0]
	if sim := strutil.Similarity(o.Name, common, swg); sim >= 0.5 {
		return true
	}
	return false
}
