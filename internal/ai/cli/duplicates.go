// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"context"
	"fmt"
	"io"

	"github.com/owasp-amass/amass/v5/internal/ai"
)

// listDuplicates compares the stored organizations and prints the pairs
// the duplicate signals link. It reads only.
func listDuplicates(ctx context.Context, graph ai.Graph, format string, explicit bool, out io.Writer) error {
	r, err := ai.FindDuplicateOrganizations(ctx, graph)
	if err != nil {
		return err
	}

	switch {
	case !explicit || format == "text":
		_, err := fmt.Fprint(out, ai.FormatDuplicateReport(r))
		return err
	case format == "json":
		return writeJSON(out, r)
	}

	return fmt.Errorf("duplicates format %q: use text or json", format)
}
