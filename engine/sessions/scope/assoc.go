// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package scope

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/caffix/stringset"
	"github.com/owasp-amass/amass/v5/config"
	et "github.com/owasp-amass/amass/v5/engine/types"
	amassdns "github.com/owasp-amass/amass/v5/internal/net/dns"
	"github.com/owasp-amass/amass/v5/internal/semantics"
	dbt "github.com/owasp-amass/asset-db/types"
	oam "github.com/owasp-amass/open-asset-model"
	oamcert "github.com/owasp-amass/open-asset-model/certificate"
	oamcon "github.com/owasp-amass/open-asset-model/contact"
	oamdns "github.com/owasp-amass/open-asset-model/dns"
	oamorg "github.com/owasp-amass/open-asset-model/org"
	oamreg "github.com/owasp-amass/open-asset-model/registration"
	"golang.org/x/net/publicsuffix"
)

// IsAssociated reports the in-scope assets the submission is associated with
// (through a registrant, a certificate subject or a location), best match
// first among each association's evidence. It never changes the scope: a
// caller that wants the submission in scope sends the association to Admit
// as evidence (et.SignalAssociation).
func (s *Scope) IsAssociated(req *et.Association) ([]*et.Association, error) {
	if req == nil || req.Submission == nil || req.Submission.Asset == nil {
		return nil, errors.New("invalid request")
	}

	// related assets that provide association matching value
	assocs := s.AssetsWithAssociation(req.Submission)
	// are any of these assets in the current session scope?
	results := s.checkRelatedAssetsforAssoc(req, assocs)
	if len(results) == 0 {
		return nil, errors.New("the submission is not associated with assets in the session scope")
	}
	return results, nil
}

func (s *Scope) checkRelatedAssetsforAssoc(req *et.Association, assocs []*dbt.Entity) []*et.Association {
	var results []*et.Association

	for _, assoc := range assocs {
		var best int
		var msg string
		var match oam.Asset

		var evidence []*dbt.Entity
		for _, asset := range append(s.assetsRelatedToAssetWithAssoc(assoc), assoc) {
			atype := asset.Asset.AssetType()
			rconf := s.confidence(atype, atype)

			if m, conf := s.IsAssetInScope(asset.Asset, rconf); conf >= rconf {
				evidence = append(evidence, asset)

				if conf > best {
					match = m
					best = conf

					aa := assoc.Asset
					sa := req.Submission.Asset
					msg = fmt.Sprintf("[%s: %s] is related to an asset with associative value [%s: %s], ", sa.AssetType(), sa.Key(), aa.AssetType(), aa.Key())
					msg += fmt.Sprintf("which has a related asset [%s: %s] that is in scope: matches [%s: %s] at a confidence of %d out of 100",
						asset.Asset.AssetType(), asset.Asset.Key(), m.AssetType(), m.Key(), conf)
				}
			}
		}

		if best > 0 {
			if ment, err := s.getMatchEntity(match); err == nil && ment != nil {
				results = append(results, &et.Association{
					Submission: req.Submission,
					BestMatch:  ment,
					Evidence:   evidence,
					Rationale:  msg,
					Confidence: best,
				})
			}
		}
	}
	return results
}

func (s *Scope) getMatchEntity(masset oam.Asset) (*dbt.Entity, error) {
	since := s.ttlStartTime(masset.AssetType(), masset.AssetType())

	ctx, cancel := context.WithTimeout(s.Session.Ctx(), 5*time.Second)
	defer cancel()

	filters := make(dbt.ContentFilters)
	switch masset.AssetType() {
	case oam.FQDN:
		filters["name"] = masset.Key()
	case oam.StreetAddress:
		filters["address"] = masset.Key()
	case oam.Organization:
		filters["unique_id"] = masset.Key()
	}

	ents, err := s.Session.DB().FindEntitiesByContent(ctx, masset.AssetType(), since, 1, filters)
	if err != nil || len(ents) != 1 {
		return nil, err
	}
	return ents[0], nil
}

func (s *Scope) assetsRelatedToAssetWithAssoc(assoc *dbt.Entity) []*dbt.Entity {
	set := stringset.New(assoc.ID)
	defer set.Close()

	var results []*dbt.Entity
	for findings := []*dbt.Entity{assoc}; len(findings) > 0; {
		assets := findings
		findings = []*dbt.Entity{}

		for _, a := range assets {
			var found bool

			switch v := a.Asset.(type) {
			case *oamdns.FQDN:
				found = true
				results = append(results, a)
			case *oamorg.Organization:
				found = true
				if cert, found := assoc.Asset.(*oamcert.TLSCertificate); !found || s.orgNameSimilarToCommon(v, cert) {
					results = append(results, a)
				}
			case *oamcon.StreetAddress:
				found = true
				results = append(results, a)
			}

			if !found {
				if f, err := s.awayFromAssetsWithAssociation(a); err == nil && len(f) > 0 {
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

func (s *Scope) AssetsWithAssociation(asset *dbt.Entity) []*dbt.Entity {
	set := stringset.New(asset.ID)
	defer set.Close()

	var results []*dbt.Entity
	since := s.ttlStartTime(oam.TLSCertificate, oam.Service)
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
				ctx, cancel := context.WithTimeout(s.Session.Ctx(), 10*time.Second)
				defer cancel()

				// only certificates directly used by the services are considered
				if _, err := s.Session.DB().IncomingEdges(ctx, a, since, "certificate"); err == nil {
					results = append(results, a)
				}
			}

			if !found {
				if f, err := s.towardsAssetsWithAssociation(a); err == nil && len(f) > 0 {
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

func (s *Scope) awayFromAssetsWithAssociation(assoc *dbt.Entity) ([]*dbt.Entity, error) {
	var results []*dbt.Entity
	// Determine relationship directions to follow on the graph
	var out, in bool
	var outRels, inRels []string
	var outSince, inSince time.Time
	switch assoc.Asset.AssetType() {
	case oam.DomainRecord:
		out = true
		outRels = append(outRels, "registrant_contact")
		outSince = s.ttlStartTime(oam.DomainRecord, oam.ContactRecord)
	case oam.IPNetRecord:
		out = true
		outRels = append(outRels, "registrant")
		outSince = s.ttlStartTime(oam.IPNetRecord, oam.ContactRecord)
	case oam.AutnumRecord:
		out = true
		outRels = append(outRels, "registrant")
		outSince = s.ttlStartTime(oam.AutnumRecord, oam.ContactRecord)
	case oam.TLSCertificate:
		out = true
		outRels = append(outRels, "common_name", "subject_contact")
		since1 := s.ttlStartTime(oam.TLSCertificate, oam.FQDN)
		outSince = s.ttlStartTime(oam.TLSCertificate, oam.ContactRecord)
		if !since1.IsZero() && since1.Before(outSince) {
			outSince = since1
		}
	case oam.ContactRecord:
		out = true
		outRels = append(outRels, "organization", "street_address")
		since1 := s.ttlStartTime(oam.ContactRecord, oam.Organization)
		outSince = s.ttlStartTime(oam.ContactRecord, oam.StreetAddress)
		if !since1.IsZero() && since1.Before(outSince) {
			outSince = since1
		}
	}
	if out {
		ctx, cancel := context.WithTimeout(s.Session.Ctx(), 10*time.Second)
		defer cancel()

		if edges, err := s.Session.DB().OutgoingEdges(ctx, assoc, outSince, outRels...); err == nil && len(edges) > 0 {
			for _, edge := range edges {
				if entity, err := s.Session.DB().FindEntityById(ctx, edge.ToEntity.ID); err == nil && entity != nil {
					results = append(results, entity)
				}
			}
		}
	}
	if in {
		ctx, cancel := context.WithTimeout(s.Session.Ctx(), 10*time.Second)
		defer cancel()

		if edges, err := s.Session.DB().IncomingEdges(ctx, assoc, inSince, inRels...); err == nil && len(edges) > 0 {
			for _, edge := range edges {
				if entity, err := s.Session.DB().FindEntityById(ctx, edge.FromEntity.ID); err == nil && entity != nil {
					results = append(results, entity)
				}
			}
		}
	}
	if len(results) == 0 {
		return nil, errors.New("zero assets were found in-scope one hop away from the provided asset")
	}
	return results, nil
}

func (s *Scope) towardsAssetsWithAssociation(asset *dbt.Entity) ([]*dbt.Entity, error) {
	var results []*dbt.Entity
	// Determine relationship directions to follow on the graph
	var out, in bool
	var outRels, inRels []string
	var outSince, inSince time.Time
	switch asset.Asset.AssetType() {
	case oam.FQDN:
		out = true
		outRels = append(outRels, "registration")
		outSince = s.ttlStartTime(oam.FQDN, oam.DomainRecord)
		in = true
		inRels = append(inRels, "node", "common_name")
		inSince = s.ttlStartTime(oam.FQDN, oam.FQDN)
		if since := s.ttlStartTime(oam.FQDN,
			oam.TLSCertificate); !since.IsZero() && since.Before(inSince) {
			inSince = since
		}
	case oam.IPAddress:
		in = true
		inRels = append(inRels, "contains")
		inSince = s.ttlStartTime(oam.IPAddress, oam.Netblock)
		if since := s.ttlStartTime(oam.IPAddress,
			oam.TLSCertificate); !since.IsZero() && since.Before(inSince) {
			inSince = since
		}
	case oam.Netblock:
		out = true
		outRels = append(outRels, "registration")
		outSince = s.ttlStartTime(oam.Netblock, oam.IPNetRecord)
	case oam.AutonomousSystem:
		out = true
		outRels = append(outRels, "registration")
		outSince = s.ttlStartTime(oam.AutonomousSystem, oam.AutnumRecord)
	case oam.Organization:
		in = true
		inRels = append(inRels, "organization")
		inSince = s.ttlStartTime(oam.Organization, oam.ContactRecord)
	case oam.StreetAddress:
		in = true
		inRels = append(inRels, "street_address")
		inSince = s.ttlStartTime(oam.StreetAddress, oam.ContactRecord)
	case oam.ContactRecord:
		in = true
		inRels = append(inRels, "registrant", "registrant_contact")
		since1 := s.ttlStartTime(oam.ContactRecord, oam.DomainRecord)
		since2 := s.ttlStartTime(oam.ContactRecord, oam.IPNetRecord)
		inSince = s.ttlStartTime(oam.ContactRecord, oam.AutnumRecord)
		if !since1.IsZero() && since1.Before(inSince) {
			inSince = since1
		}
		if !since2.IsZero() && since2.Before(inSince) {
			inSince = since2
		}
	case oam.Service:
		out = true
		outRels = append(outRels, "certificate")
		outSince = s.ttlStartTime(oam.Service, oam.TLSCertificate)
	}
	if out {
		ctx, cancel := context.WithTimeout(s.Session.Ctx(), 10*time.Second)
		defer cancel()

		if edges, err := s.Session.DB().OutgoingEdges(ctx, asset, outSince, outRels...); err == nil && len(edges) > 0 {
			for _, edge := range edges {
				if entity, err := s.Session.DB().FindEntityById(ctx, edge.ToEntity.ID); err == nil && entity != nil {
					results = append(results, entity)
				}
			}
		}
	}
	if in {
		ctx, cancel := context.WithTimeout(s.Session.Ctx(), 10*time.Second)
		defer cancel()

		if edges, err := s.Session.DB().IncomingEdges(ctx, asset, inSince, inRels...); err == nil && len(edges) > 0 {
			for _, edge := range edges {
				if entity, err := s.Session.DB().FindEntityById(ctx, edge.FromEntity.ID); err == nil && entity != nil {
					results = append(results, entity)
				}
			}
		}
	}
	if len(results) == 0 {
		return nil, errors.New("zero assets were found in-scope one hop toward the provided asset")
	}
	return results, nil
}

func (s *Scope) ttlStartTime(from, to oam.AssetType) time.Time {
	if matches, err := s.Session.Config().CheckTransformations(string(from), string(to)); err == nil && matches != nil {
		if ttl := matches.TTL(string(to)); ttl >= 0 {
			return time.Now().Add(time.Duration(-ttl) * time.Minute)
		}
	}
	return time.Time{}
}

func (s *Scope) confidence(from, to oam.AssetType) int {
	if matches, err := s.Session.Config().CheckTransformations(string(from), string(to)); err == nil && matches != nil {
		if conf := matches.Confidence(string(to)); conf >= 0 {
			return config.MatchConfidence(conf)
		}
	}
	return -1
}

// orgNameSimilarToCommon reports whether the certificate's subject domain is
// named for the organization: its registered domain's label spells one of
// the organization's names (semantics.OrgNameMatchesLabel).
func (s *Scope) orgNameSimilarToCommon(o *oamorg.Organization, cert *oamcert.TLSCertificate) bool {
	if re := amassdns.AnySubdomainRegex(); !re.MatchString(cert.SubjectCommonName) {
		return false
	}

	dom, err := publicsuffix.EffectiveTLDPlusOne(strings.ToLower(cert.SubjectCommonName))
	if err != nil {
		return false
	}

	label, _, _ := strings.Cut(dom, ".")
	for _, key := range orgNameKeys(o) {
		if semantics.OrgNameMatchesLabel(strings.Fields(key), label) {
			return true
		}
	}
	return false
}
