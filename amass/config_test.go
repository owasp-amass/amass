// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package amass

import (
	"reflect"
	"testing"
)

func TestExcludeDisabledDataSources(t *testing.T) {
	e := NewEnumeration()
	e.Config.DisabledDataSources = []string{"Crtsh"}
	original := []Service{
		NewAsk(e),
		NewCensys(e),
		NewCrtsh(e),
		NewGoogle(e),
	}
	got := e.Config.ExcludeDisabledDataSources(original)
	want := append(original[0:2], original[3:]...)
	if !reflect.DeepEqual(got, want) {
		t.Errorf("mismatched result, got %+v, want %+v", got, want)
	}
}

func TestAddDomainsDuplicate(t *testing.T) {
	domains := []string{"twitter.com", "google.com", "twitter.com"}

	e := NewEnumeration()
	e.Config.AddDomains(domains)

	got := e.Config.Domains()
	want := append(domains[0:2])

	if !reflect.DeepEqual(got, want) {
		t.Errorf("mismatched result, got %+v, want %+v", got, want)
	}
}

func TestIsDomainInScope(t *testing.T) {
	domain := "google.com"
	inScope := "mail.google.com"
	outOfScope := "mail.random.com"

	e := NewEnumeration()
	e.Config.AddDomain(domain)

	if !e.Config.IsDomainInScope(inScope) {
		t.Errorf("expected %s to be in the scope of %s", inScope, domain)
	}

	if e.Config.IsDomainInScope(outOfScope) {
		t.Errorf("expected %s to be out of the scope of %s", outOfScope, domain)
	}
}
