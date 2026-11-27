// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"errors"
	"fmt"
	"io"

	"github.com/owasp-amass/amass/v5/internal/lens"
	"github.com/owasp-amass/amass/v5/internal/review"
)

// listSignals prints the ownership signal catalog: each signal with what it
// finds, why it counts, its guards and when it can mislead. Text is the
// default; markdown is docs/ai/SIGNALS.md.
func listSignals(format string, explicit bool, out io.Writer) error {
	switch {
	case !explicit || format == "text":
		_, err := fmt.Fprint(out, lens.SignalsText())
		return err
	case format == "markdown":
		_, err := fmt.Fprint(out, lens.SignalsMarkdown())
		return err
	case format == "json":
		return writeJSON(out, lens.OwnershipSignals())
	}

	return fmt.Errorf("signals format %q: use text, json or markdown", format)
}

// listDuplicateSignals prints the duplicate-organization signal catalog.
// Text is the default; markdown is docs/ai/DUPLICATES.md.
func listDuplicateSignals(format string, explicit bool, out io.Writer) error {
	switch {
	case !explicit || format == "text":
		_, err := fmt.Fprint(out, lens.DuplicateSignalsText())
		return err
	case format == "markdown":
		_, err := fmt.Fprint(out, lens.DuplicateSignalsMarkdown())
		return err
	case format == "json":
		return writeJSON(out, lens.DuplicateSignals())
	}

	return fmt.Errorf("duplicate-signals format %q: use text, json or markdown", format)
}

// listHorizontalSignals prints the horizontal domain-correlation signal
// catalog: each signal with what it finds, why it counts, its guards and when
// it can mislead. Text is the default; markdown is docs/ai/HORIZONTALS.md.
func listHorizontalSignals(format string, explicit bool, out io.Writer) error {
	switch {
	case !explicit || format == "text":
		_, err := fmt.Fprint(out, lens.HorizontalSignalsText())
		return err
	case format == "markdown":
		_, err := fmt.Fprint(out, lens.HorizontalSignalsMarkdown())
		return err
	case format == "json":
		return writeJSON(out, lens.HorizontalSignals())
	}

	return fmt.Errorf("horizontal-signals format %q: use text, json or markdown", format)
}

// listInfrastructureSignals prints the infrastructure (netblock/AS) correlation
// signal catalog. Text is the default; markdown is docs/ai/INFRASTRUCTURE.md.
func listInfrastructureSignals(format string, explicit bool, out io.Writer) error {
	switch {
	case !explicit || format == "text":
		_, err := fmt.Fprint(out, lens.InfrastructureSignalsText())
		return err
	case format == "markdown":
		_, err := fmt.Fprint(out, lens.InfrastructureSignalsMarkdown())
		return err
	case format == "json":
		return writeJSON(out, lens.InfrastructureSignals())
	}

	return fmt.Errorf("infrastructure-signals format %q: use text, json or markdown", format)
}

// listSignalPrecision reports how reviewers judged the proposals each
// ownership signal stood behind (amass review signal-precision), so a signal
// that misleads can be found and tuned in internal/semantics.
func listSignalPrecision(j *review.Journal, format string, out io.Writer) error {
	if j == nil {
		return errors.New("-journal required")
	}

	entries, err := j.OwnershipEntries()
	if err != nil {
		return err
	}

	rows := review.SignalPrecisions(entries)
	switch format {
	case "", "text":
		_, err = fmt.Fprintln(out, review.FormatSignalPrecisions(rows))
		return err
	case "json":
		return writeJSON(out, rows)
	}

	return fmt.Errorf("signal-precision format %q: use text or json", format)
}

// migrateSignals rewrites the review journal's records with the merged signal
// catalog's IDs (amass review migrate-signals), once, keeping the journal as
// it was beside it. Retrain the ownership model afterwards.
func migrateSignals(j *review.Journal, out io.Writer) error {
	if j == nil {
		return errors.New("-journal required")
	}

	n, err := j.MigrateSignalIDs()
	if err != nil {
		return err
	}
	if n == 0 {
		_, err = fmt.Fprintln(out, "The review journal already uses the current signal IDs.")
		return err
	}
	_, err = fmt.Fprintf(out, "Renamed the signals in %d journal records; the journal as it was is kept beside it. "+
		"Retrain the ownership model with: amass ai train -kind ownership\n", n)
	return err
}
