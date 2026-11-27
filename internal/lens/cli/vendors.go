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

	dnssd "github.com/owasp-amass/amass/v5/engine/plugins/service_discovery/dns"
	"github.com/owasp-amass/amass/v5/internal/graph"
	"github.com/owasp-amass/amass/v5/internal/graph/oamrepo"
	"github.com/owasp-amass/amass/v5/internal/lens"
)

// listVendors prints the outside parties a domain and its organization's
// assets depend on. It reads only.
func listVendors(ctx context.Context, g familyGraph, domain string, limits lens.LensLimits, format string,
	explicit bool, out io.Writer) error {
	if err := limits.Validate(); err != nil {
		return err
	}

	domain = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(domain), "."))
	if domain == "" {
		return errors.New("-domain required")
	}

	res, err := g.ResolveAsset(ctx, graph.AssetSelector{Type: "FQDN", Field: "name", Value: domain}, 2)
	if err != nil {
		return err
	}
	if len(res.Candidates) != 1 {
		return fmt.Errorf("%s is not a stored domain name", domain)
	}

	r, err := lens.FindVendors(ctx, g, oamrepo.Catalog{}, res.Candidates[0].Asset,
		lens.VendorOptions{KnownVerification: dnssd.IsVerificationRecord, Limits: limits})
	if err != nil {
		return err
	}

	switch {
	case !explicit || format == "text":
		_, err := fmt.Fprint(out, lens.FormatVendorReport(r))
		return err
	case format == "json":
		return writeJSON(out, r)
	}

	return fmt.Errorf("vendors format %q: use text or json", format)
}
