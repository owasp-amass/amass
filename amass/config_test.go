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
