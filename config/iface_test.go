// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"testing"

	"gopkg.in/yaml.v3"
)

func TestLoadNetworkSettings(t *testing.T) {
	tests := []struct {
		name    string
		options string
		want    string
		wantErr bool
	}{
		{name: "Name", options: "interface: eth0", want: "eth0"},
		{name: "Address", options: "interface: \" 192.0.2.10 \"", want: "192.0.2.10"},
		{name: "NotPresent", options: "", want: ""},
		{name: "NotAString", options: "interface: [eth0]", wantErr: true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			c := NewConfig()
			if err := yaml.Unmarshal([]byte(tc.options), &c.Options); err != nil {
				t.Fatalf("yaml: %v", err)
			}

			err := c.loadNetworkSettings(c)
			if (err != nil) != tc.wantErr {
				t.Fatalf("loadNetworkSettings error = %v, want error %v", err, tc.wantErr)
			}
			if c.Interface != tc.want {
				t.Errorf("Interface = %q, want %q", c.Interface, tc.want)
			}
		})
	}
}

func TestLoadActiveRouteSettings(t *testing.T) {
	c := NewConfig()
	opts := "active_route: socks5h://tor:9050\nactive_udp_route: eth1\n"
	if err := yaml.Unmarshal([]byte(opts), &c.Options); err != nil {
		t.Fatalf("yaml: %v", err)
	}

	if err := c.loadNetworkSettings(c); err != nil {
		t.Fatal(err)
	}
	if c.ActiveRoute != "socks5h://tor:9050" || c.ActiveUDPRoute != "eth1" {
		t.Errorf("active routes = %q, %q", c.ActiveRoute, c.ActiveUDPRoute)
	}

	c = NewConfig()
	if err := yaml.Unmarshal([]byte("active_route: 9050"), &c.Options); err != nil {
		t.Fatalf("yaml: %v", err)
	}
	if err := c.loadNetworkSettings(c); err == nil {
		t.Error("a number was accepted as the active route")
	}
}
