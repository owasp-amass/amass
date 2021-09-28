package filter

import (
	"testing"
)

func TestStringFilterDuplicate(t *testing.T) {
	sf := NewStringFilter()
	defer sf.Close()

	if sf.Duplicate("test1") {
		t.Errorf("StringFilter failed duplicate check")
	}

	if !sf.Duplicate("test1") {
		t.Errorf("StringFilter failed duplicate check")
	}
}
