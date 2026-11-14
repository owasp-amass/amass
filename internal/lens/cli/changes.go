// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"context"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"

	"github.com/owasp-amass/amass/v5/internal/graph/oamrepo"
	"github.com/owasp-amass/amass/v5/internal/lens"
)

// listChanges prints what changed since a time in what a domain (-d) or an
// organization (-org) controls. It reads only.
func listChanges(ctx context.Context, graph groupGraph, domain, org string, since time.Time,
	limits lens.LensLimits, format string, explicit bool, out io.Writer) error {
	if err := limits.Validate(); err != nil {
		return err
	}

	root, err := groupRoot(ctx, graph, domain, org)
	if err != nil {
		return err
	}

	r, err := lens.FindChanges(ctx, graph, oamrepo.Catalog{}, root, since, limits)
	if err != nil {
		return err
	}

	switch {
	case !explicit || format == "text":
		_, err := fmt.Fprint(out, lens.FormatChangesReport(r))
		return err
	case format == "json":
		return writeJSON(out, r)
	}

	return fmt.Errorf("changes format %q: use text or json", format)
}

// parseSince reads -since: a date, an RFC 3339 time, or an age before now
// in days (7d) or as a duration (72h). Empty means the lens's default.
func parseSince(v string, now time.Time) (time.Time, error) {
	v = strings.TrimSpace(v)
	if v == "" {
		return time.Time{}, nil
	}
	for _, layout := range []string{time.RFC3339, "2006-01-02"} {
		if t, err := time.Parse(layout, v); err == nil {
			return t, nil
		}
	}
	if days, ok := strings.CutSuffix(v, "d"); ok {
		if n, err := strconv.Atoi(days); err == nil && n > 0 {
			return now.AddDate(0, 0, -n), nil
		}
	}
	if d, err := time.ParseDuration(v); err == nil && d > 0 {
		return now.Add(-d), nil
	}

	return time.Time{}, fmt.Errorf("-since %q: use a date (2026-11-01), an RFC 3339 time, or an age such as 7d", v)
}
