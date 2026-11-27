// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package assoc

import (
	"flag"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestNewFlagset(t *testing.T) {
	var args Args
	args.Triples = make([]string, 10)
	fs := NewFlagset(&args, flag.ContinueOnError)
	fs.SetOutput(io.Discard)

	err := fs.Parse([]string{"-t1", "<fqdn>:example.com-<dns_record>-<ipaddress>:*", "-t10", "last",
		"-nocolor", "-silent", "-config", "c.yaml", "-dir", "/tmp/amass", "-tf", "t.txt"})
	if err != nil {
		t.Fatal(err)
	}
	if args.Triples[0] != "<fqdn>:example.com-<dns_record>-<ipaddress>:*" || args.Triples[9] != "last" ||
		args.Triples[1] != "" {
		t.Errorf("triples = %q", args.Triples)
	}
	if !args.Options.NoColor || !args.Options.Silent || args.Filepaths.ConfigFile != "c.yaml" ||
		args.Filepaths.Directory != "/tmp/amass" || args.Filepaths.TripleFile != "t.txt" {
		t.Errorf("args = %+v", args)
	}
	if err := fs.Parse([]string{"-nosuchflag"}); err == nil {
		t.Error("an unknown flag was accepted")
	}
}

func TestReadTriplesTextFromFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "triples.txt")
	data := "  <fqdn>:example.com-<dns_record>-<ipaddress>:*  \n\n\t\n<ipaddress>:*-<port>-<service>:*\n"
	if err := os.WriteFile(path, []byte(data), 0600); err != nil {
		t.Fatal(err)
	}
	got, err := readTriplesTextFromFile(path)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"<fqdn>:example.com-<dns_record>-<ipaddress>:*", "<ipaddress>:*-<port>-<service>:*"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("triples = %q, want %q", got, want)
	}
	if _, err := readTriplesTextFromFile(filepath.Join(t.TempDir(), "missing.txt")); err == nil {
		t.Error("a missing file was read")
	}
}
