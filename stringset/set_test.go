package stringset

import (
	"strings"
	"testing"
)

func TestDeduplicate(t *testing.T) {
	tests := []struct {
		Set      []string
		Expected []string
	}{
		{[]string{"dup", "dup", "dup", "test1", "test2", "test3"}, []string{"dup", "test1", "test2", "test3"}},
		{[]string{"test1", "test2", "test3"}, []string{"test1", "test2", "test3"}},
	}

	for _, test := range tests {
		set := Deduplicate(test.Set)

		if l := len(set); l != len(test.Expected) {
			t.Errorf("Returned %d elements instead of %d", l, len(test.Expected))
			continue
		}

		for _, e := range test.Expected {
			var found bool

			for _, s := range set {
				if strings.EqualFold(s, e) {
					found = true
					break
				}
			}

			if !found {
				t.Errorf("%s was missing from the set", e)
			}
		}
	}
}

func TestSetHas(t *testing.T) {
	set := New("test1", "test2", "test3", "test1", "test2")
	if !set.Has("test1") {
		t.Errorf("Set missing expected value")
	}
}

func TestSetInsert(t *testing.T) {
	expected := 3
	set := New()
	set.Insert("test1")
	set.Insert("test2")
	set.Insert("test3")
	set.Insert("test3")
	set.Insert("test2")
	set.Insert("test1")
	if len(set) != expected {
		t.Errorf("Got %d, expected %d", len(set), expected)
	}
}

func TestSetInsertMany(t *testing.T) {
	expected := 3
	set := New()
	set.InsertMany("test1", "test2", "test3", "test1", "test2")
	if len(set) != expected {
		t.Errorf("Got %d, expected %d", len(set), expected)
	}
}

func TestSetRemove(t *testing.T) {
	expected := 2
	set := New("test1", "test2", "test3", "test1", "test2")
	set.Remove("test1")
	if len(set) != expected {
		t.Errorf("Got %d, expected %d", len(set), expected)
	}
}

func TestSetSlice(t *testing.T) {
	expected := 3
	set := New("test1", "test2", "test3", "test1", "test2")
	slice := set.Slice()
	if len(slice) != expected {
		t.Errorf("Got %d, expected %d", len(set), expected)
	}
}

func TestSetLen(t *testing.T) {
	tests := []struct {
		Set         []string
		ExpectedLen int
	}{
		{[]string{"test1"}, 1},
		{[]string{"test1", "test2", "test3", "test1", "test2"}, 3},
		{[]string{"test1", "test1", "test1", "test1", "test1"}, 1},
		{[]string{"test1", "test2", "test3", "test4", "test5"}, 5},
	}

	for _, test := range tests {
		set := New(test.Set...)

		if l := set.Len(); l != test.ExpectedLen {
			t.Errorf("Returned a set len of %d instead of %d", l, test.ExpectedLen)
		}
	}
}

func TestSetUnion(t *testing.T) {
	expected := 6
	set1 := New("test1", "test2", "test3", "test6")
	set2 := New("test1", "test2", "test3", "test4", "test5")
	set1.Union(set2)
	if len(set1) != expected {
		t.Errorf("Got %d, expected %d", len(set1), expected)
	}
}

func TestSetIntersect(t *testing.T) {
	expected := 3
	set1 := New("test1", "test2", "test3", "test6")
	set2 := New("test1", "test2", "test3", "test4", "test5")
	set1.Intersect(set2)
	if len(set1) != expected {
		t.Errorf("Got %d, expected %d", len(set1), expected)
	}
}

func TestSetSubtract(t *testing.T) {
	expected := 1
	set1 := New("test1", "test2", "test3", "test6")
	set2 := New("test1", "test2", "test3", "test4", "test5")
	set1.Subtract(set2)
	if len(set1) != expected {
		t.Errorf("Got %d, expected %d", len(set1), expected)
	}
}

func TestString(t *testing.T) {
	tests := []struct {
		Set      []string
		Expected string
	}{
		{[]string{"test1"}, "test1"},
		{[]string{"test1", "test2", "test3"}, "test1,test2,test3"},
	}

	for _, test := range tests {
		set := New(test.Set...)

		for _, e := range strings.Split(test.Expected, ",") {
			var found bool

			for s := range set {
				if strings.EqualFold(s, e) {
					found = true
					break
				}
			}

			if !found {
				t.Errorf("%s was missing from the set", e)
			}
		}
	}
}

func TestSet(t *testing.T) {
	tests := []struct {
		Value    string
		Expected []string
	}{
		{"", []string{}},
		{"test1", []string{"test1"}},
		{"test1,test2,test3", []string{"test1", "test2", "test3"}},
	}

	for _, test := range tests {
		set := New()

		set.Set(test.Value)
		for _, e := range test.Expected {
			var found bool

			for s := range set {
				if strings.EqualFold(s, e) {
					found = true
					break
				}
			}

			if !found {
				t.Errorf("%s was missing from the set", e)
			}
		}
	}
}
