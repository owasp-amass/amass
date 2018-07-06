// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package sources

import (
	"bytes"
	"fmt"
	"io"
	"log"
	"testing"
)

const (
	TestDomain    string = "owasp.org"
	TestSubdomain string = "www.owasp.org"
)

func TestAllSources(t *testing.T) {
	for _, source := range GetAllSources() {
		var b bytes.Buffer
		l := log.New(io.Writer(&b), "", log.Lmicroseconds)

		source.SetLogger(l)

		fmt.Printf("Starting test for %s\n", source)

		if names := source.Query(TestDomain, TestDomain); len(names) == 0 {
			if source.Type() == ARCHIVE {
				fmt.Printf("%s did not find any names from the domain: %s\n", source, b.String())
			} else {
				t.Errorf("%s did not find any names from the domain: %s", source, b.String())
			}
			continue
		}

		if !source.Subdomains() {
			continue
		}

		if names := source.Query(TestDomain, TestSubdomain); len(names) == 0 {
			if source.Type() == ARCHIVE {
				fmt.Printf("%s did not find any names from the subdomain: %s\n", source, b.String())
			} else {
				t.Errorf("%s did not find any names from the subdomain: %s", source, b.String())
			}
		}
	}
}
