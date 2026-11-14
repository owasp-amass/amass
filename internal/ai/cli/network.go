// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"context"
	"fmt"
	"io"

	"github.com/owasp-amass/amass/v5/internal/ai/lens"
	"github.com/owasp-amass/amass/v5/internal/ai/oamrepo"
)

// listNetwork prints the network infrastructure of what a domain (-d) or an
// organization (-org) controls: its netblocks and autonomous systems and
// where its names are hosted. It reads only.
func listNetwork(ctx context.Context, graph groupGraph, domain, org string, limits lens.LensLimits, format string,
	explicit bool, out io.Writer) error {
	if err := limits.Validate(); err != nil {
		return err
	}

	root, err := groupRoot(ctx, graph, domain, org)
	if err != nil {
		return err
	}

	r, err := lens.FindNetworkInfrastructure(ctx, graph, oamrepo.Catalog{}, root, limits)
	if err != nil {
		return err
	}

	switch {
	case !explicit || format == "text":
		_, err := fmt.Fprint(out, lens.FormatNetworkReport(r))
		return err
	case format == "json":
		return writeJSON(out, r)
	}

	return fmt.Errorf("network format %q: use text or json", format)
}
