// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package vuln

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"time"

	"github.com/owasp-amass/amass/v5/config"
)

// DataEnv names the data file when set; otherwise callers choose a path.
const DataEnv = "AMASS_VULN_DATA"

// Data is the local copy of the vulnerability data.
type Data struct {
	About string `json:"_about"`
	// CatalogHash identifies the catalog products the data was fetched for.
	CatalogHash  string                  `json:"catalog_hash"`
	UpdatedAt    time.Time               `json:"updated_at"`
	KEVFetchedAt time.Time               `json:"kev_fetched_at,omitzero"`
	Products     map[string]*ProductData `json:"products"`
	// KEV holds the CVEs in CISA's catalog, by CVE ID.
	KEV map[string]KEVEntry `json:"kev"`
}

// ProductData is the CVEs of one CPE name.
type ProductData struct {
	// FetchedAt is when the last fetch of this product began; the next
	// asks NVD for what changed since.
	FetchedAt time.Time       `json:"fetched_at"`
	CVEs      map[string]*CVE `json:"cves"`
}

// CVE is one vulnerability and the versions of the product it affects.
type CVE struct {
	ID        string    `json:"id"`
	Published time.Time `json:"published"`
	Score     float64   `json:"score,omitempty"`
	Severity  string    `json:"severity,omitempty"`
	Ranges    []Range   `json:"ranges"`
}

// Range is a set of affected versions as NVD gives them: an exact version,
// or bounds that each may be inclusive or exclusive. A range with neither
// covers every version.
type Range struct {
	Version   string `json:"version,omitempty"`
	StartIncl string `json:"start_incl,omitempty"`
	StartExcl string `json:"start_excl,omitempty"`
	EndIncl   string `json:"end_incl,omitempty"`
	EndExcl   string `json:"end_excl,omitempty"`
}

// KEVEntry is a CVE in CISA's Known Exploited Vulnerabilities catalog.
type KEVEntry struct {
	Name      string `json:"name,omitempty"`
	DateAdded string `json:"date_added,omitempty"`
	DueDate   string `json:"due_date,omitempty"`
}

const dataAbout = "Vulnerability data for the products in Amass's vulnerabilities.json, from the NVD CVE API and " +
	"CISA's Known Exploited Vulnerabilities catalog, written by amass vuln-update."

// Load reads a data file; a missing file is empty data.
func Load(path string) (*Data, error) {
	d := &Data{About: dataAbout, Products: map[string]*ProductData{}, KEV: map[string]KEVEntry{}}
	raw, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return d, nil
	}
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(raw, d); err != nil {
		return nil, err
	}
	if d.Products == nil {
		d.Products = map[string]*ProductData{}
	}
	if d.KEV == nil {
		d.KEV = map[string]KEVEntry{}
	}

	return d, nil
}

// Save writes the data file atomically.
func (d *Data) Save(path string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}

	raw, err := json.Marshal(d)
	if err != nil {
		return err
	}

	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o644); err != nil {
		return err
	}

	return os.Rename(tmp, path)
}

// DefaultPath is the data file: DataEnv when set, otherwise
// vulnerabilities.json in the Amass output directory.
func DefaultPath() string {
	if p := os.Getenv(DataEnv); p != "" {
		return p
	}

	return filepath.Join(config.OutputDirectory(), "vulnerabilities.json")
}
