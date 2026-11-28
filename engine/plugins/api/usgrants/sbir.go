// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package usgrants

import (
	"encoding/csv"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/owasp-amass/amass/v5/engine/plugins/support"
	"github.com/owasp-amass/amass/v5/engine/plugins/support/org"
	et "github.com/owasp-amass/amass/v5/engine/types"
	"github.com/owasp-amass/amass/v5/internal/semantics"
	dbt "github.com/owasp-amass/asset-db/types"
	oamgen "github.com/owasp-amass/open-asset-model/general"
)

// SBIR.gov's award API refuses every request while it is under maintenance,
// so the awards come from its bulk export of every SBIR/STTR award (the
// file without abstracts, about 65 MB), which SBIR.gov refreshes monthly.
const (
	sbirBulkURL     = "https://data.www.sbir.gov/mod_awarddatapublic_no_abstract/award_data_no_abstract.csv"
	sbirBulkTTL     = 7 * 24 * time.Hour
	sbirBulkTimeout = 15 * time.Minute
	sbirBulkMax     = 512 << 20
)

// sbirIndex is the bulk award file, downloaded at most once per TTL and
// indexed by the recipient's organization name key, shared by every session.
type sbirIndex struct {
	sync.Mutex
	url     string
	file    string
	modTime time.Time // of the file the index was built from
	byKey   map[string][]grant
}

var sbirBulk = newSBIRIndex(filepath.Join(os.TempDir(), "amass-sbir"), sbirBulkURL)

func newSBIRIndex(dir, u string) *sbirIndex {
	return &sbirIndex{url: u, file: filepath.Join(dir, "award_data_no_abstract.csv")}
}

// awards returns the awards whose recipient has the name's key, refreshing
// the file and its index when the file is older than the TTL.
func (x *sbirIndex) awards(e *et.Event, name string) ([]grant, error) {
	x.Lock()
	defer x.Unlock()

	if err := os.MkdirAll(filepath.Dir(x.file), 0o755); err != nil {
		return nil, err
	}
	if err := support.CachedDownload(e, x.url, x.file, sbirBulkTTL, sbirBulkTimeout, sbirBulkMax); err != nil {
		return nil, err
	}
	fi, err := os.Stat(x.file)
	if err != nil {
		return nil, err
	}
	if x.byKey == nil || !fi.ModTime().Equal(x.modTime) {
		f, err := os.Open(x.file)
		if err != nil {
			return nil, err
		}
		byKey, err := parseSBIRAwards(f)
		_ = f.Close()
		if err != nil {
			return nil, err
		}
		x.byKey, x.modTime = byKey, fi.ModTime()
	}
	return x.byKey[semantics.OrgNameKey(name)], nil
}

// parseSBIRAwards reads the bulk award file (CSV with a header row) into the
// awards with a recipient and a positive amount, keyed by the recipient's
// organization name key. An award is identified by its contract number, or
// by its title and year when it has none.
func parseSBIRAwards(r io.Reader) (map[string][]grant, error) {
	cr := csv.NewReader(r)
	cr.FieldsPerRecord = -1
	cr.LazyQuotes = true
	cr.ReuseRecord = true

	header, err := cr.Read()
	if err != nil {
		return nil, fmt.Errorf("the SBIR award file has no header: %w", err)
	}
	col := map[string]int{}
	for i, h := range header {
		col[strings.TrimSpace(strings.TrimPrefix(h, "\ufeff"))] = i
	}
	for _, need := range []string{"Company", "Award Amount"} {
		if _, ok := col[need]; !ok {
			return nil, fmt.Errorf("the SBIR award file has no %q column", need)
		}
	}
	field := func(rec []string, name string) string {
		if i, ok := col[name]; ok && i < len(rec) {
			return strings.TrimSpace(rec[i])
		}
		return ""
	}

	out := map[string][]grant{}
	for {
		rec, err := cr.Read()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			// A malformed row is skipped; the rest of the file still counts.
			continue
		}

		company := field(rec, "Company")
		amount, _ := strconv.ParseFloat(strings.NewReplacer("$", "", ",", "").Replace(field(rec, "Award Amount")), 64)
		key := semantics.OrgNameKey(company)
		if key == "" || amount <= 0 {
			continue
		}

		year := field(rec, "Award Year")
		id := "sbir:" + field(rec, "Contract")
		if id == "sbir:" {
			title := field(rec, "Award Title")
			if title == "" {
				// Nothing identifies the award, so it cannot be stored once.
				continue
			}
			id = "sbir:" + strings.ReplaceAll(title, " ", "_") + ":" + year
		}
		date := field(rec, "Proposal Award Date")
		if date == "" {
			date = year
		}
		out[key] = append(out[key], grant{
			id:        id,
			amount:    amount,
			date:      date,
			agency:    field(rec, "Agency"),
			recipient: company,
			uei:       field(rec, "UEI"),
			duns:      field(rec, "Duns"),
		})
	}
	return out, nil
}

func querySBIR(h *source, e *et.Event, orgent *dbt.Entity, name string) {
	grants, err := sbirBulk.awards(e, name)
	if err != nil {
		e.Session.Log().Error(fmt.Sprintf("SBIR awards for %s are unavailable: %s", name, err),
			slog.Group("plugin", "name", h.name))
		return
	}

	var ueis, duns []string
	seen := map[string]bool{}
	for i := range grants {
		g := &grants[i]
		if !semantics.SameOrgName(name, g.recipient) || seen[g.id] {
			continue
		}
		seen[g.id] = true
		ueis, duns = append(ueis, g.uei), append(duns, g.duns)
		h.store(e, orgent, g)
	}

	// the recipient's identifiers, when the matched awards agree on them
	org.StoreMajorityIdentifier(e.Session, orgent, org.UEIIdentifier, ueis, h.src)
	org.StoreMajorityIdentifier(e.Session, orgent, oamgen.DUNSNumer, duns, h.src)
}
