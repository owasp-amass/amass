// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package enum

import (
	"bytes"
	"strings"
	"testing"

	"github.com/owasp-amass/amass/v5/config"
)

func TestNeedsEngine(t *testing.T) {
	cases := map[string]struct {
		args []string
		want bool
	}{
		"no arguments":  {nil, false},
		"list":          {[]string{"-list"}, false},
		"list with dir": {[]string{"-dir", "/tmp/x", "-list"}, false},
		"help":          {[]string{"-h"}, false},
		"bad flag":      {[]string{"-nosuchflag"}, false},
		"domain":        {[]string{"-d", "example.com"}, true},
		"active domain": {[]string{"-active", "-d", "example.com"}, true},
	}
	for name, c := range cases {
		if got := NeedsEngine(c.args); got != c.want {
			t.Errorf("%s: NeedsEngine(%v) = %v, want %v", name, c.args, got, c.want)
		}
	}
}

func TestPrintDataSources(t *testing.T) {
	cfg := config.NewConfig()
	cfg.DataSrcConfigs = &config.DataSourceConfig{Datasources: []*config.DataSource{
		{Name: "Shodan", Creds: map[string]*config.Credentials{"account": {Apikey: "k"}}},
		{Name: "Censys", Creds: map[string]*config.Credentials{"account": {}}},
	}}

	var out bytes.Buffer
	printDataSources(cfg, &out)

	lines := strings.Split(strings.TrimSpace(out.String()), "\n")
	if len(lines) < 10 {
		t.Fatalf("only %d plugins were listed", len(lines))
	}

	var shodan, censys, bimi bool
	for _, l := range lines {
		f := strings.Fields(l)
		switch f[0] {
		case "Shodan":
			shodan = strings.Contains(l, "credentials configured")
		case "Censys":
			censys = !strings.Contains(l, "credentials configured")
		case "BIMI":
			bimi = true
		}
	}
	if !shodan || !censys || !bimi {
		t.Fatalf("shodan keyed %v, censys unkeyed %v, BIMI listed %v:\n%s", shodan, censys, bimi, out.String())
	}
}
