// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"

	"github.com/owasp-amass/amass/v5/internal/graph"
	"github.com/owasp-amass/amass/v5/internal/review"
)

// retractDocument retracts a lead the document model gave an enumeration, or
// undoes a stored document reading, by its journal ID.
func retractDocument(ctx context.Context, w review.DocumentLeadStore, j *review.Journal, id, reviewer string,
	out io.Writer) error {
	if review.IsDocumentReading(id) {
		if err := review.UndoDocumentStatements(ctx, w, j, id, reviewer); err != nil {
			return err
		}
		_, err := fmt.Fprintf(out, "Undid document reading %s: its statements were removed.\n", id)
		return err
	}

	removed, err := review.RetractDocumentLead(ctx, w, j, id, reviewer)
	if err != nil {
		return err
	}
	if removed {
		_, err = fmt.Fprintf(out, "Retracted %s: the asset was removed (the engine had linked nothing to it).\n", id)
	} else {
		_, err = fmt.Fprintf(out, "Retracted %s: the amass-ai tags were removed; the asset stays, since the "+
			"engine linked other assets to it.\n", id)
	}
	return err
}

// isDocumentDecision reports whether id names a document lead or reading.
func isDocumentDecision(id string) bool {
	return review.IsDocumentLead(id) || review.IsDocumentReading(id)
}

// AssetLookup returns a stored asset by its ID, and whether it is stored.
type AssetLookup func(id string) (graph.Asset, bool)

// LeadFootprintText describes one document lead: where it came from, how it
// settled and, when the engine confirmed it, what it led to, asset by asset,
// so its value can be judged. Assets removed since the lead settled are
// listed as removed.
func LeadFootprintText(j *review.Journal, id string, lookup AssetLookup) (string, error) {
	if j == nil {
		return "", errors.New("no review journal is configured")
	}
	leads, err := j.DocumentLeads()
	if err != nil {
		return "", err
	}
	var l *review.DocumentLead
	for i := range leads {
		if leads[i].ID == id {
			l = &leads[i]
		}
	}
	if l == nil {
		return "", fmt.Errorf("no document lead %s", id)
	}

	kind := l.Type
	if kind == "" {
		kind = "Organization"
	}
	var b strings.Builder
	fmt.Fprintf(&b, "%s: the %s %q, named (%s) in %s (read by %s), given to enumeration %s.\n", l.ID, kind, l.Name,
		l.Predicate, l.URL, l.Model, l.RunID)
	switch {
	case l.Status == review.ProposalRetracted:
		fmt.Fprintf(&b, "Retracted by %s at %s.\n", l.Reviewer, l.At.Format(time.RFC3339))
		return b.String(), nil
	case !l.Confirmed:
		b.WriteString("Not settled yet: its enumeration has not ended.\n")
		return b.String(), nil
	case l.Footprint == nil:
		b.WriteString("Confirmed.\n")
		return b.String(), nil
	}

	fmt.Fprintln(&b, footprintText(l.Footprint))
	byType := map[string][]string{}
	for _, eid := range l.Footprint.EntityIDs {
		a, ok := lookup(eid)
		if !ok {
			byType["removed since"] = append(byType["removed since"], eid)
			continue
		}
		byType[a.Type] = append(byType[a.Type], graph.AssetLabel(a)+" ["+eid+"]")
	}
	kinds := make([]string, 0, len(byType))
	for k := range byType {
		kinds = append(kinds, k)
	}
	sort.Strings(kinds)
	for _, k := range kinds {
		fmt.Fprintf(&b, "  %s:\n", k)
		for _, v := range byType[k] {
			fmt.Fprintf(&b, "    %s\n", v)
		}
	}
	listed, total := len(l.Footprint.EntityIDs), 0
	for _, n := range l.Footprint.Assets {
		total += n
	}
	if listed < total {
		fmt.Fprintf(&b, "  (the first %d of %d assets are listed)\n", listed, total)
	}
	return b.String(), nil
}

// footprintText describes what the engine collected from a confirmed lead.
func footprintText(fp *review.LeadFootprint) string {
	if len(fp.Assets) == 0 {
		return fmt.Sprintf("Confirmed: %d relation(s) touch it.", fp.Relations)
	}
	kinds := make([]string, 0, len(fp.Assets))
	for k := range fp.Assets {
		kinds = append(kinds, k)
	}
	sort.Strings(kinds)
	parts := make([]string, 0, len(kinds))
	for _, k := range kinds {
		parts = append(parts, fmt.Sprintf("%d %s", fp.Assets[k], k))
	}
	more := ""
	if fp.Truncated {
		more = " (more beyond the walk)"
	}
	return fmt.Sprintf("Confirmed; it led to %s over %d relation(s)%s.", strings.Join(parts, ", "), fp.Relations, more)
}
