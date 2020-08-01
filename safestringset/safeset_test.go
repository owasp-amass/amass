package safestringset

import (
	"strings"
	"testing"
)

func TestDeduplicate(t *testing.T) {
	tests := []struct {
		SafeSet  []string
		Expected []string
	}{
		{[]string{"dup", "dup", "dup", "test1", "test2", "test3"}, []string{"dup", "test1", "test2", "test3"}},
		{[]string{"test1", "test2", "test3"}, []string{"test1", "test2", "test3"}},
	}

	for _, test := range tests {
		set := Deduplicate(test.SafeSet)

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

func TestSafeSetHas(t *testing.T) {
	set := New("test1", "test2", "test3", "test1", "test2")
	if !set.Has("test1") {
		t.Errorf("SafeSet missing expected value")
	}
}

func TestSafeSetInsert(t *testing.T) {
	expected := 3
	set := New()
	set.Insert("test1")
	set.Insert("test2")
	set.Insert("test3")
	set.Insert("test3")
	set.Insert("test2")
	set.Insert("test1")
	if set.Len() != expected {
		t.Errorf("Got %d, expected %d", set.Len(), expected)
	}
}

func TestSafeSetInsertMany(t *testing.T) {
	expected := 3
	set := New()
	set.InsertMany("test1", "test2", "test3", "test1", "test2")
	if set.Len() != expected {
		t.Errorf("Got %d, expected %d", set.Len(), expected)
	}
}

func TestSafeSetRemove(t *testing.T) {
	expected := 2
	set := New("test1", "test2", "test3", "test1", "test2")
	set.Remove("test1")
	if set.Len() != expected {
		t.Errorf("Got %d, expected %d", set.Len(), expected)
	}
}

func TestSafeSetSlice(t *testing.T) {
	expected := 3
	set := New("test1", "test2", "test3", "test1", "test2")
	slice := set.Slice()
	if len(slice) != expected {
		t.Errorf("Got %d, expected %d", set.Len(), expected)
	}
}

func TestSafeSetLen(t *testing.T) {
	tests := []struct {
		SafeSet     []string
		ExpectedLen int
	}{
		{[]string{"test1"}, 1},
		{[]string{"test1", "test2", "test3", "test1", "test2"}, 3},
		{[]string{"test1", "test1", "test1", "test1", "test1"}, 1},
		{[]string{"test1", "test2", "test3", "test4", "test5"}, 5},
	}

	for _, test := range tests {
		set := New(test.SafeSet...)

		if l := set.Len(); l != test.ExpectedLen {
			t.Errorf("Returned a set len of %d instead of %d", l, test.ExpectedLen)
		}
	}
}

func TestSafeSetUnion(t *testing.T) {
	expected := 6
	set1 := New("test1", "test2", "test3", "test6")
	set2 := New("test1", "test2", "test3", "test4", "test5")
	set1.Union(set2)
	if set1.Len() != expected {
		t.Errorf("Got %d, expected %d", set1.Len(), expected)
	}
}

func TestSafeSetIntersect(t *testing.T) {
	expected := 3
	set1 := New("test1", "test2", "test3", "test6")
	set2 := New("test1", "test2", "test3", "test4", "test5")
	set1.Intersect(set2)
	if set1.Len() != expected {
		t.Errorf("Got %d, expected %d", set1.Len(), expected)
	}
}

func TestSafeSetSubtract(t *testing.T) {
	expected := 1
	set1 := New("test1", "test2", "test3", "test6")
	set2 := New("test1", "test2", "test3", "test4", "test5")
	set1.Subtract(set2)
	if set1.Len() != expected {
		t.Errorf("Got %d, expected %d", set1.Len(), expected)
	}
}

func TestString(t *testing.T) {
	tests := []struct {
		SafeSet  []string
		Expected string
	}{
		{[]string{"test1"}, "test1"},
		{[]string{"test1", "test2", "test3"}, "test1,test2,test3"},
	}

	for _, test := range tests {
		set := New(test.SafeSet...)

		for _, e := range strings.Split(test.Expected, ",") {
			var found bool

			for s := range set.m {
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

func TestSafeSet(t *testing.T) {
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

		set.SafeSet(test.Value)
		for _, e := range test.Expected {
			var found bool

			for s := range set.m {
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
