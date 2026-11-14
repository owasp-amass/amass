// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"context"
	"fmt"
	"io"

	"github.com/owasp-amass/amass/v5/internal/graph/oamrepo"
	"github.com/owasp-amass/amass/v5/internal/lens"
)

// listServices prints the services stored for what a domain (-d) or an
// organization (-org) controls. It reads only.
func listServices(ctx context.Context, graph groupGraph, domain, org string, limits lens.LensLimits, format string,
	explicit bool, out io.Writer) error {
	if err := limits.Validate(); err != nil {
		return err
	}

	root, err := groupRoot(ctx, graph, domain, org)
	if err != nil {
		return err
	}

	r, err := lens.FindServices(ctx, graph, oamrepo.Catalog{}, root, limits)
	if err != nil {
		return err
	}

	switch {
	case !explicit || format == "text":
		_, err := fmt.Fprint(out, lens.FormatServicesReport(r))
		return err
	case format == "json":
		return writeJSON(out, r)
	}

	return fmt.Errorf("services format %q: use text or json", format)
}
