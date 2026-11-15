// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

// Package cli is the amass vuln-update command, which fetches or refreshes
// the vulnerability data the vulnerable software lens reads.
package cli

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/fatih/color"
	"github.com/owasp-amass/amass/v5/internal/afmt"
	"github.com/owasp-amass/amass/v5/internal/vuln"
)

// Description is shown in the amass subcommand list.
const Description = "Fetch or refresh the vulnerability data (NVD CVEs and CISA KEV) for identified software"

// NVDKeyEnv is an optional NVD API key, which allows faster updates.
const NVDKeyEnv = "NVD_API_KEY"

// CLIWorkflow runs amass vuln-update and exits with status 1 on failure.
func CLIWorkflow(cmdName string, args []string) {
	if err := Run(cmdName, args, os.Stdout, color.Error); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return
		}

		_, _ = afmt.R.Fprintf(color.Error, "%v\n", err)
		os.Exit(1)
	}
}

// Run parses the flags and updates the data file. It writes only that file.
func Run(cmdName string, args []string, out, errout io.Writer) error {
	fs := flag.NewFlagSet(cmdName, flag.ContinueOnError)
	fs.SetOutput(errout)

	var dir, path string
	var timeout time.Duration
	fs.StringVar(&dir, "dir", "", "Amass data directory that holds vulnerabilities.json")
	fs.StringVar(&path, "vuln-data", "", "Vulnerability data file "+
		"(default from AMASS_VULN_DATA, or vulnerabilities.json in the output directory)")
	fs.DurationVar(&timeout, "timeout", 30*time.Minute, "Maximum time for the update")
	fs.Usage = func() {
		_, _ = fmt.Fprintf(errout, "Usage: %s [flags]\n\n%s.\n\nFlags:\n", cmdName, Description)
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return fmt.Errorf("usage: %s [flags]; unexpected arguments %v", cmdName, fs.Args())
	}
	if timeout <= 0 {
		return errors.New("the timeout must be positive")
	}

	switch {
	case path != "":
	case dir != "" && os.Getenv(vuln.DataEnv) == "":
		path = filepath.Join(dir, "vulnerabilities.json")
	default:
		path = vuln.DefaultPath()
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
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
