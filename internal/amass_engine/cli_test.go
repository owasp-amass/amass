// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package amass_engine

import (
	"flag"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/owasp-amass/amass/v5/engine/sessions"
	amassnet "github.com/owasp-amass/amass/v5/internal/net"
	amassdns "github.com/owasp-amass/amass/v5/internal/net/dns"
)

func TestNewFlagset(t *testing.T) {
	var args Args
	fs := NewFlagset(&args, flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	if err := fs.Parse([]string{"-nocolor", "-silent", "-log-dir", "/tmp/logs"}); err != nil {
		t.Fatal(err)
	}
	if !args.Options.NoColor || !args.Options.Silent || args.Filepaths.LogDir != "/tmp/logs" || args.Help {
		t.Errorf("args = %+v", args)
	}
	if err := fs.Parse([]string{"-nosuchflag"}); err == nil {
		t.Error("an unknown flag was accepted")
	}
}

func TestSelectLoggerWritesToTheLogDir(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "logs")
	l, err := selectLogger(dir)
	if err != nil || l == nil {
		t.Fatalf("selectLogger = %v, %v", l, err)
	}
	l.Info("engine started")

	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) != 1 || !strings.HasPrefix(entries[0].Name(), "amass_engine_") {
		t.Fatalf("log directory = %v, %v", entries, err)
	}
	data, err := os.ReadFile(filepath.Join(dir, entries[0].Name()))
	if err != nil || !strings.Contains(string(data), "engine started") {
		t.Errorf("log file = %q, %v", data, err)
	}
}

func TestResolverQPS(t *testing.T) {
	env := func(v string, set bool) func(string) (string, bool) {
		return func(key string) (string, bool) {
			if key != ResolverQPSEnv {
				return "", false
			}
			return v, set
		}
	}

	tests := []struct {
		name  string
		flag  int
		env   func(string) (string, bool)
		want  int
		fails bool
	}{
		{"the default", -1, env("", false), amassdns.DefaultResolverQPS, false},
		{"an empty variable", -1, env(" ", true), amassdns.DefaultResolverQPS, false},
		{"the variable", -1, env("40", true), 40, false},
		{"the flag over the variable", 8, env("40", true), 8, false},
		{"no limit", 0, env("40", true), 0, false},
		{"a bad variable", -1, env("fast", true), 0, true},
		{"a negative variable", -1, env("-3", true), 0, true},
	}
	for _, tt := range tests {
		got, err := resolverQPS(tt.flag, tt.env)
		if (err != nil) != tt.fails || (!tt.fails && got != tt.want) {
			t.Errorf("%s: resolverQPS = %d, %v; want %d", tt.name, got, err, tt.want)
		}
	}

	var args Args
	fs := NewFlagset(&args, flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	if err := fs.Parse(nil); err != nil || args.Options.ResolverQPS != -1 {
		t.Errorf("without the flag, ResolverQPS = %d, %v", args.Options.ResolverQPS, err)
	}
	if err := fs.Parse([]string{"-resolver-qps", "25"}); err != nil || args.Options.ResolverQPS != 25 {
		t.Errorf("-resolver-qps 25 gave %d, %v", args.Options.ResolverQPS, err)
	}
}

func TestEngineInterface(t *testing.T) {
	env := func(v string) func(string) (string, bool) {
		return func(key string) (string, bool) {
			if key != InterfaceEnv || v == "" {
				return "", false
			}
			return v, true
		}
	}
	loopback := amassnet.LocalAddrs{V4: netip.MustParseAddr("127.0.0.1")}

	tests := []struct {
		name  string
		flag  string
		env   func(string) (string, bool)
		want  amassnet.LocalAddrs
		fails bool
	}{
		{"neither", "", env(""), amassnet.LocalAddrs{}, false},
		{"the variable", "", env("127.0.0.1"), loopback, false},
		{"the flag over the variable", "127.0.0.1", env("no-such-iface0"), loopback, false},
		{"a missing interface", "no-such-iface0", env(""), amassnet.LocalAddrs{}, true},
		// 192.0.2.0/24 is reserved for documentation, so no interface has it
		{"an address on no interface", "", env("192.0.2.1"), amassnet.LocalAddrs{}, true},
	}
	for _, tt := range tests {
		got, err := engineInterface(tt.flag, tt.env)
		if (err != nil) != tt.fails || (!tt.fails && got != tt.want) {
			t.Errorf("%s: engineInterface = %v, %v; want %v", tt.name, got, err, tt.want)
		}
	}

	var args Args
	fs := NewFlagset(&args, flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	if err := fs.Parse([]string{"-iface", "eth0"}); err != nil || args.Options.Interface != "eth0" {
		t.Errorf("-iface eth0 gave %q, %v", args.Options.Interface, err)
	}
}

func TestEngineActiveRoute(t *testing.T) {
	env := map[string]string{ActiveRouteEnv: "socks5h://127.0.0.1:9050", ActiveUDPRouteEnv: "127.0.0.1"}
	lookup := func(key string) (string, bool) {
		v, ok := env[key]
		return v, ok
	}

	r, err := engineActiveRoute("", "", lookup)
	if err != nil || r.Proxy == nil || r.Proxy.Host != "127.0.0.1:9050" || r.UDP.IsZero() {
		t.Errorf("from the environment: %+v, %v", r, err)
	}
	if r, err := engineActiveRoute("127.0.0.1", "", lookup); err != nil || r.Proxy != nil || r.Local.IsZero() {
		t.Errorf("the flag over the variable: %+v, %v", r, err)
	}
	if _, err := engineActiveRoute("gopher://127.0.0.1:70", "", lookup); err == nil {
		t.Error("an unsupported proxy scheme was accepted")
	}
	if r, err := engineActiveRoute("", "", func(string) (string, bool) { return "", false }); err != nil || !r.IsZero() {
		t.Errorf("neither: %+v, %v", r, err)
	}
}

func TestWorkerSessions(t *testing.T) {
	env := func(v string) func(string) (string, bool) {
		return func(key string) (string, bool) { return v, key == WorkerSessionsEnv && v != "" }
	}
	for _, c := range []struct {
		flag  int
		env   string
		want  int
		fails bool
	}{
		{0, "", sessions.DefaultWorkerSessions, false},
		{0, "3", 3, false},
		{7, "3", 7, false},
		{0, "0", 0, true},
		{0, "many", 0, true},
	} {
		got, err := workerSessions(c.flag, env(c.env))
		if (err != nil) != c.fails || (!c.fails && got != c.want) {
			t.Errorf("workerSessions(%d, %q) = %d, %v", c.flag, c.env, got, err)
		}
	}
}
