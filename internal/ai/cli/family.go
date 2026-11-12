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

// familyGraph is what the family lens needs: the graph and a way to find
// the domain's FQDN.
type familyGraph interface {
	ai.Graph
	ai.AssetResolver
}

// listFamily prints the organizations tied to a domain, how each relates
// to its main organization, and the networks and registered domains that
// serve them. Departments and same-institution organizations are recorded
// in the journal as proposals; nothing in the Asset Database changes.
func listFamily(ctx context.Context, graph familyGraph, domain, journalPath, format string, explicit bool,
	out, errout io.Writer) error {
	domain = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(domain), "."))
	if domain == "" {
		return errors.New("-domain required")
	}

	res, err := graph.ResolveAsset(ctx, ai.AssetSelector{Type: "FQDN", Field: "name", Value: domain}, 2)
	if err != nil {
		return err
	}
	if len(res.Candidates) != 1 {
		return fmt.Errorf("%s is not a stored domain name", domain)
	}

	r, err := ai.FindOrganizationFamily(ctx, graph, res.Candidates[0].Asset)
	if err != nil {
		return err
	}
	if journalPath != "" {
		if err := recordFamily(&ai.Journal{Path: journalPath}, r, errout); err != nil {
			return err
		}
	}

	switch {
	case !explicit || format == "text":
		_, err := fmt.Fprint(out, ai.FormatFamilyReport(r))
		return err
	case format == "json":
		return writeJSON(out, r)
	}

	return fmt.Errorf("family format %q: use text or json", format)
}

// recordFamily records a family's departments and same-institution
// organizations as proposals.
func recordFamily(j *ai.Journal, r ai.FamilyReport, errout io.Writer) error {
	units, merges, err := j.SubmitFamily(r)
	if err != nil {
		return err
	}
	if units+merges > 0 {
		_, _ = fmt.Fprintf(errout, "%d department and %d merge proposal(s) recorded in %s; review with "+
			"`amass review proposals`\n", units, merges, j.Path)
	}

	return nil
}
