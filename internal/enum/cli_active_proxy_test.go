// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package enum

import (
	"flag"
	"testing"

	"github.com/caffix/stringset"
	"github.com/owasp-amass/amass/v5/config"
)

func newTestArgs() *Args {
	return &Args{
		AltWordList:       stringset.New(),
		AltWordListMask:   stringset.New(),
		BruteWordList:     stringset.New(),
		BruteWordListMask: stringset.New(),
		Blacklist:         stringset.New(),
		Domains:           stringset.New(),
		Excluded:          stringset.New(),
		Included:          stringset.New(),
		Names:             stringset.New(),
		Resolvers:         stringset.New(),
	}
}

func TestFlagset_ActiveProxyParsing(t *testing.T) {
	args := newTestArgs()
	fs := NewFlagset(args, flag.ContinueOnError)

	if err := fs.Parse([]string{
		"-active",
		"-active-proxy", "socks5://127.0.0.1:1080",
	}); err != nil {
		t.Fatalf("parse: %v", err)
	}
	if !args.Options.Active {
		t.Fatalf("Active flag not parsed")
	}
	if args.ActiveProxy != "socks5://127.0.0.1:1080" {
		t.Fatalf("ActiveProxy not parsed, got %q", args.ActiveProxy)
	}
	if !args.Options.ActiveStrict {
		t.Fatalf("ActiveStrict should default to true")
	}
}

func TestFlagset_ActiveStrictDefaultTrue(t *testing.T) {
	args := newTestArgs()
	fs := NewFlagset(args, flag.ContinueOnError)
	if err := fs.Parse([]string{"-active"}); err != nil {
		t.Fatalf("parse: %v", err)
	}
	if !args.Options.ActiveStrict {
		t.Fatalf("ActiveStrict default should be true")
	}
}

func TestOverrideConfig_ActiveProxyPropagates(t *testing.T) {
	cfg := config.NewConfig()
	args := newTestArgs()
	args.Options.Active = true
	args.ActiveProxy = "http://10.0.0.1:3128"

	if err := args.OverrideConfig(cfg); err != nil {
		t.Fatalf("override: %v", err)
	}
	if !cfg.Active {
		t.Fatalf("config.Active not set")
	}
	if cfg.ActiveProxy != "http://10.0.0.1:3128" {
		t.Fatalf("config.ActiveProxy not set, got %q", cfg.ActiveProxy)
	}
	if !cfg.ActiveStrict {
		t.Fatalf("config.ActiveStrict should remain true (operator did not pass -active-strict)")
	}
}

func TestOverrideConfig_ActiveStrictUserOverride(t *testing.T) {
	cfg := config.NewConfig()
	args := newTestArgs()
	args.Options.Active = true
	args.Options.ActiveStrictSet = true
	args.Options.ActiveStrict = false

	if err := args.OverrideConfig(cfg); err != nil {
		t.Fatalf("override: %v", err)
	}
	if cfg.ActiveStrict {
		t.Fatalf("config.ActiveStrict should be false after explicit user override")
	}
}
