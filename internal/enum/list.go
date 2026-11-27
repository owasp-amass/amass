// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package enum

import (
	"flag"
	"fmt"
	"io"
	"strings"

	"github.com/fatih/color"
	"github.com/owasp-amass/amass/v5/config"
	"github.com/owasp-amass/amass/v5/engine/plugins"
	"github.com/owasp-amass/amass/v5/internal/afmt"
)

// NeedsEngine reports whether the enum arguments start an enumeration, which
// needs the engine running. Printing the usage or the data sources does not,
// and neither do arguments that fail to parse, since the command only reports
// the error.
func NeedsEngine(clArgs []string) bool {
	if len(clArgs) == 0 {
		return false
	}

	args := newArgs()
	fs := NewFlagset(&args, flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	if err := fs.Parse(clArgs); err != nil {
		return false
	}

	return !args.Help && !args.Options.ListSources
}

// printDataSources writes the engine's data sources and other plugins, one
// per line, marking those with credentials in the datasources file.
func printDataSources(cfg *config.Config, w io.Writer) {
	names := plugins.PluginNames()

	var keyed int
	for _, name := range names {
		if hasCredentials(cfg, name) {
			keyed++
			_, _ = fmt.Fprintf(w, "%-30s %s\n", name, afmt.G.Sprint("credentials configured"))
			continue
		}
		_, _ = fmt.Fprintln(w, name)
	}

	_, _ = afmt.Y.Fprintf(color.Error, "\n%d plugins and data sources, %d with credentials configured\n",
		len(names), keyed)
}

// hasCredentials reports whether the datasources file gives the named data
// source at least one account with credentials.
func hasCredentials(cfg *config.Config, name string) bool {
	ds := cfg.GetDataSourceConfig(name)
	if ds == nil {
		return false
	}

	for _, c := range ds.Creds {
		if c != nil && strings.TrimSpace(c.Apikey+c.Secret+c.Username+c.Password) != "" {
			return true
		}
	}
	return false
}
