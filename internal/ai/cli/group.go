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

	"github.com/owasp-amass/amass/v5/internal/ai"
)

type groupGraph interface {
	familyGraph
	ai.OrganizationResolver
}

// listGroup prints the corporate group of an organization, named with -org
// or found as a domain's main organization with -d. It reads only.
func listGroup(ctx context.Context, graph groupGraph, domain, org, format string, explicit bool,
	out io.Writer) error {
	domain = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(domain), "."))
	org = strings.TrimSpace(org)

	var root ai.Asset
	switch {
	case domain != "" && org != "":
		return errors.New("use -org or -domain, not both")
	case domain != "":
		res, err := graph.ResolveAsset(ctx, ai.AssetSelector{Type: "FQDN", Field: "name", Value: domain}, 2)
		if err != nil {
			return err
		}
		if len(res.Candidates) != 1 {
			return fmt.Errorf("%s is not a stored domain name", domain)
		}
		root = res.Candidates[0].Asset
	case org != "":
		res, err := graph.ResolveOrganizations(ctx, ai.OrganizationQuery{Name: org}, 10)
		if err != nil {
			return err
		}
		switch len(res.Candidates) {
		case 0:
			return fmt.Errorf("no stored organization is named %q", org)
		case 1:
			root = res.Candidates[0].Asset
		default:
			names := make([]string, 0, len(res.Candidates))
			for _, c := range res.Candidates {
				names = append(names, fmt.Sprintf("%s [%s]", ai.AssetLabel(c.Asset), c.Asset.ID))
			}
			return fmt.Errorf("%q names %d organizations; be more specific: %s", org, len(names),
				strings.Join(names, "; "))
		}
	default:
		return errors.New("-org or -domain required")
	}

	r, err := ai.FindCorporateGroup(ctx, graph, root)
	if err != nil {
		return err
	}

	switch {
	case !explicit || format == "text":
		_, err := fmt.Fprint(out, ai.FormatGroupReport(r))
		return err
	case format == "json":
		return writeJSON(out, r)
	}

	return fmt.Errorf("org-group format %q: use text or json", format)
}
