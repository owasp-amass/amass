// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package collect

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/owasp-amass/amass/v5/config"
	"gopkg.in/yaml.v3"
)

const sampleSources = `# these are the global options related to data sources.
global_options:
  minimum_ttl: 1440 #one day

# uncomment and add credentials for data sources that you'd like to be used by the engine
datasources:
#  - name: 360PassiveDNS
#    ttl: 3600
#    creds:
#      account:
#        apikey:
#  - name: Shodan
#    creds:
#      account:
#        apikey:
`

func TestDataSourceKeys(t *testing.T) {
	path := filepath.Join(t.TempDir(), "datasources.yaml")
	if err := os.WriteFile(path, []byte(sampleSources), 0o640); err != nil {
		t.Fatal(err)
	}

	st, err := DataSourceStatus(path)
	if err != nil || len(st) != 2 || st[0].Configured || st[1].Name != "Shodan" {
		t.Fatalf("status = %+v, %v", st, err)
	}

	if err := SetDataSourceCredentials(path, "Shodan", "", config.Credentials{Apikey: "k: with # odd chars"}); err != nil {
		t.Fatal(err)
	}
	if err := SetDataSourceCredentials(path, "Censys", "work", config.Credentials{Apikey: "id", Secret: "s"}); err != nil {
		t.Fatal(err)
	}
	// Replacing an account keeps one set of credentials.
	if err := SetDataSourceCredentials(path, "shodan", "account", config.Credentials{Apikey: "new"}); err != nil {
		t.Fatal(err)
	}

	data, _ := os.ReadFile(path)
	text := string(data)
	if !strings.Contains(text, "minimum_ttl: 1440") || !strings.Contains(text, "uncomment and add credentials") {
		t.Errorf("settings or comments lost:\n%s", text)
	}
	var dsc config.DataSourceConfig
	if err := yaml.Unmarshal(data, &dsc); err != nil {
		t.Fatal(err)
	}
	dsc.MapNames()
	if c := dsc.GetCredentials("Shodan"); c == nil || c.Apikey != "new" {
		t.Errorf("Shodan = %+v\n%s", c, text)
	}
	if c := dsc.GetCredentials("Censys"); c == nil || c.Secret != "s" {
		t.Errorf("Censys = %+v", c)
	}
	if info, _ := os.Stat(path); info.Mode().Perm() != 0o640 {
		t.Errorf("mode changed to %v", info.Mode().Perm())
	}

	st, _ = DataSourceStatus(path)
	got := map[string]bool{}
	for _, s := range st {
		got[s.Name] = s.Configured
	}
	if !got["Shodan"] || !got["Censys"] || got["360PassiveDNS"] {
		t.Errorf("status after = %+v", st)
	}
	if err := SetDataSourceCredentials(path, "Bad:name", "", config.Credentials{Apikey: "x"}); err == nil {
		t.Error("an invalid source name was accepted")
	}
	if err := SetDataSourceCredentials(path, "Shodan", "", config.Credentials{}); err == nil {
		t.Error("empty credentials were accepted")
	}
}
