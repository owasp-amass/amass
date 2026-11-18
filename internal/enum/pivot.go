// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package enum

import (
	"context"
	"io"
	"strings"
	"time"

	"github.com/owasp-amass/amass/v5/config"
	"github.com/owasp-amass/amass/v5/internal/afmt"
	"github.com/owasp-amass/amass/v5/internal/graph"
	"github.com/owasp-amass/amass/v5/internal/graph/oamrepo"
	"github.com/owasp-amass/amass/v5/internal/lens"
	"github.com/owasp-amass/amass/v5/internal/tools"
)

// pivotSeedDomains resolves a -phone or -address seed to the registered domains
// of the organizations tied to it and adds them to the scope, so a normal
// enumeration follows. It reads the database only and reports what it resolved
// to out. It returns true when the run should proceed: there was no pivot, or a
// pivot resolved domains to enumerate. It returns false, and the run stops,
// when a pivot was requested but cannot proceed — no such phone or address in
// the database, a shared or registered-agent address, or organizations with no
// registered domains — so the pivot never enumerates a shared address or an
// empty result.
func pivotSeedDomains(cfg *config.Config, args *Args, out io.Writer) bool {
	phone := strings.TrimSpace(args.Phone)
	address := strings.TrimSpace(args.Address)
	if phone == "" && address == "" {
		return true
	}
	if phone != "" && address != "" {
		_, _ = afmt.R.Fprintln(out, "Give only one of -phone or -address")
		return false
	}

	seed := graph.AssetSelector{Type: "Location", Field: "address", Value: address}
	if phone != "" {
		seed = graph.AssetSelector{Type: "Phone", Field: "e164", Value: phone}
	}

	repo := tools.OpenGraphDatabase(cfg)
	if repo == nil {
		_, _ = afmt.R.Fprintln(out, "Unable to open the OAM database to resolve the seed")
		return false
	}
	defer func() { _ = repo.Close() }()

	g := oamrepo.Adapter{Repo: repo, Neo4jDatabase: oamrepo.Neo4jDatabaseName(cfg)}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	res, err := g.ResolveAsset(ctx, seed, 1)
	if err != nil || len(res.Candidates) == 0 {
		_, _ = afmt.Y.Fprintf(out, "%s %q is not in the database yet; enumerate a known domain for it, or "+
			"collect organizations from this %s first\n", seed.Type, seed.Value, strings.ToLower(seed.Type))
		return false
	}

	resolution, err := lens.ResolveSeedPivot(ctx, g, oamrepo.Catalog{}, res.Candidates[0].Asset, lens.LensLimits{})
	if err != nil {
		_, _ = afmt.R.Fprintf(out, "Failed to resolve the seed: %v\n", err)
		return false
	}

	printPivotResolution(out, resolution)

	switch {
	case resolution.SharedAddress:
		_, _ = afmt.Y.Fprintf(out, "This address is shared by %d organizations (a registered-agent or "+
			"shared-building address); it is not enumerated. Name a specific organization's domain with -d.\n",
			len(resolution.Organizations))
		return false
	case len(resolution.Domains) == 0:
		_, _ = afmt.Y.Fprintf(out, "Resolved %d organization(s) but no registered domains yet; enumerate one of "+
			"their known domains with -d\n", len(resolution.Organizations))
		return false
	}

	for _, d := range resolution.Domains {
		cfg.AddDomain(d)
	}
	_, _ = afmt.G.Fprintf(out, "Enumerating %d domain(s) resolved from %s %s: %s\n", len(resolution.Domains),
		strings.ToLower(resolution.SeedType), resolution.SeedValue, strings.Join(resolution.Domains, ", "))
	return true
}

// printPivotResolution lists the organizations a seed resolved to and the
// domains each controls, so the operator sees what will be enumerated.
func printPivotResolution(out io.Writer, r lens.PivotResolution) {
	_, _ = afmt.B.Fprintf(out, "\nResolved from %s %s:\n", strings.ToLower(r.SeedType), r.SeedValue)
	for _, o := range r.Organizations {
		name := o.Name
		if o.Principal {
			name += " (principal address)"
		}
		if len(o.Domains) > 0 {
			_, _ = afmt.G.Fprintf(out, "  %s: %s\n", name, strings.Join(o.Domains, ", "))
		} else {
			_, _ = afmt.G.Fprintf(out, "  %s\n", name)
		}
	}
}
