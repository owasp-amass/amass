// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"errors"
	"fmt"
	"io"

	"github.com/owasp-amass/amass/v5/internal/review"
)

// importJournal moves the file journal at path into the database's journal
// (amass review import-journal), once, after renaming its old signal IDs.
func importJournal(j *review.Journal, path string, out io.Writer) error {
	if j == nil || path == "" {
		return errors.New("-journal required: the file journal to import")
	}
	if !j.Shared() {
		return errors.New("the configured database keeps no journal (PostgreSQL and SQLite do); " +
			"the file journal stays where it is")
	}

	if _, err := (&review.Journal{Path: path}).MigrateSignalIDs(); err != nil {
		return err
	}
	n, done, err := j.ImportJournal(path)
	if err != nil {
		return fmt.Errorf("imported %d records before: %w", n, err)
	}
	if done {
		_, err = fmt.Fprintf(out, "%s was already imported (%d records).\n", path, n)
		return err
	}
	_, err = fmt.Fprintf(out, "Imported %d records from %s into the Asset Database's journal; the file is no "+
		"longer read and can be kept as a backup.\n", n, path)
	return err
}
