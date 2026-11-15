// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"context"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/owasp-amass/amass/v5/internal/lens"
	"github.com/owasp-amass/amass/v5/internal/vuln"
)

// NVDKeyEnv is an optional NVD API key, which allows faster updates.
const NVDKeyEnv = "NVD_API_KEY"

// updateVulnerabilities refreshes the vulnerability data the vulnerable
// lens reads: NVD's CVEs for the catalog's products and CISA's KEV
// catalog. It writes only the data file.
func updateVulnerabilities(path string, timeout time.Duration, out, errout io.Writer) error {
	if path == "" {
		path = vuln.DefaultPath()
	}

	ctx, cancel := context.WithTimeout(context.Background(), max(timeout, 30*time.Minute))
	defer cancel()

	u := &vuln.Updater{APIKey: os.Getenv(NVDKeyEnv), Log: func(format string, args ...any) {
		_, _ = fmt.Fprintf(errout, format+"\n", args...)
	}}
	res, err := u.Update(ctx, path)
	if err != nil {
		return fmt.Errorf("update vulnerability data: %w", err)
	}

	_, err = fmt.Fprintf(out, "Updated %s: %d CPE names (%d fetched in full), %d CVEs, %d changed; %d known exploited "+
		"vulnerabilities in CISA's catalog.\n", path, res.Products, res.Full, res.CVEs, res.Changed, res.KEV)
	return err
}

// useVulnData points the vulnerable lens at path when one was given.
func useVulnData(path string) {
	if path != "" {
		lens.VulnDataPath = func() string { return path }
	}
}
