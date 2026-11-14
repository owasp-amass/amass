// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/owasp-amass/amass/v5/internal/graph"
	"github.com/owasp-amass/amass/v5/internal/graph/oamrepo"
	"github.com/owasp-amass/amass/v5/internal/lens"
)

type groupGraph interface {
	familyGraph
	graph.OrganizationResolver
}

// listGroup prints the corporate group of an organization, named with -org
// or found as a domain's main organization with -d. It reads only.
func listGroup(ctx context.Context, graph groupGraph, domain, org, format string, explicit bool,
	out io.Writer) error {
	root, err := groupRoot(ctx, graph, domain, org)
	if err != nil {
		return err
	}

	r, err := lens.FindCorporateGroup(ctx, graph, root)
	if err != nil {
		return err
	}

	switch {
	case !explicit || format == "text":
		_, err := fmt.Fprint(out, lens.FormatGroupReport(r))
		return err
	case format == "json":
		return writeJSON(out, r)
	}

	return fmt.Errorf("org-group format %q: use text or json", format)
}

// listGroupVendors prints the outside parties a corporate group depends on,
// across its organizations. It reads only.
func listGroupVendors(ctx context.Context, graph groupGraph, domain, org string, limits lens.LensLimits,
	format string, explicit bool, out io.Writer) error {
	root, err := groupRoot(ctx, graph, domain, org)
	if err != nil {
		return err
	}

	r, err := lens.FindGroupVendors(ctx, graph, oamrepo.Catalog{}, root, limits)
	if err != nil {
		return err
	}

	switch {
	case !explicit || format == "text":
		_, err := fmt.Fprint(out, lens.FormatGroupVendorReport(r))
		return err
	case format == "json":
		return writeJSON(out, r)
	}

	return fmt.Errorf("group-vendors format %q: use text or json", format)
}

// groupRoot finds the organization named with -org, or the domain named with
// -d.
func groupRoot(ctx context.Context, g groupGraph, domain, org string) (graph.Asset, error) {
	domain = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(domain), "."))
	org = strings.TrimSpace(org)

	var root graph.Asset
	switch {
	case domain != "" && org != "":
		return root, errors.New("use -org or -domain, not both")
	case domain != "":
		res, err := g.ResolveAsset(ctx, graph.AssetSelector{Type: "FQDN", Field: "name", Value: domain}, 2)
		if err != nil {
			return root, err
		}
		if len(res.Candidates) != 1 {
			return root, fmt.Errorf("%s is not a stored domain name", domain)
		}
		root = res.Candidates[0].Asset
	case org != "":
		res, err := g.ResolveOrganizations(ctx, graph.OrganizationQuery{Name: org}, 10)
		if err != nil {
			return root, err
		}
		switch len(res.Candidates) {
		case 0:
			return root, fmt.Errorf("no stored organization is named %q", org)
		case 1:
			root = res.Candidates[0].Asset
		default:
			names := make([]string, 0, len(res.Candidates))
			for _, c := range res.Candidates {
				names = append(names, fmt.Sprintf("%s [%s]", graph.AssetLabel(c.Asset), c.Asset.ID))
			}
			return root, fmt.Errorf("%q names %d organizations; be more specific: %s", org, len(names),
				strings.Join(names, "; "))
		}
	default:
		return root, errors.New("-org or -domain required")
	}

	return root, nil
}
