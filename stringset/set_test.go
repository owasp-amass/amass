package stringset

import (
	"testing"
)

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
	expected := 3
	set := New("test1", "test2", "test3", "test1", "test2")
	if len(set) != expected {
		t.Errorf("Got %d, expected %d", len(set), expected)
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
