package stringset

import (
	"testing"
)

func TestStringFilterDuplicate(t *testing.T) {
	sf := NewStringFilter()

	if sf.Duplicate("test1") {
		t.Errorf("StringFilter failed duplicate check")
	}

	if !sf.Duplicate("test1") {
		t.Errorf("StringFilter failed duplicate check")
	}
}
