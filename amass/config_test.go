package amass

import (
	"reflect"
	"testing"
)

func TestConfig_ExcludeDisabledDataSources(t *testing.T) {
	e := NewEnumeration()
	e.Config.DisabledDataSources = []string{
		"Crtsh",
	}
	original := []AmassService{
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
