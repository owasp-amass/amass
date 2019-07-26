package stringset

import "testing"

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
	if set.Len() != expected {
		t.Errorf("Got %d, expected %d", set.Len(), expected)
	}
}

func TestSetInsertMany(t *testing.T) {
	expected := 3
	set := New()
	set.InsertMany("test1", "test2", "test3", "test1", "test2")
	if set.Len() != expected {
		t.Errorf("Got %d, expected %d", set.Len(), expected)
	}
}

func TestSetRemove(t *testing.T) {
	expected := 2
	set := New("test1", "test2", "test3", "test1", "test2")
	set.Remove("test1")
	if set.Len() != expected {
		t.Errorf("Got %d, expected %d", set.Len(), expected)
	}
}

func TestSetToSlice(t *testing.T) {
	expected := 3
	set := New("test1", "test2", "test3", "test1", "test2")
	slice := set.ToSlice()
	if len(slice) != expected {
		t.Errorf("Got %d, expected %d", set.Len(), expected)
	}
}

func TestSetLen(t *testing.T) {
	expected := 3
	set := New("test1", "test2", "test3", "test1", "test2")
	if set.Len() != expected {
		t.Errorf("Got %d, expected %d", set.Len(), expected)
	}
}

func TestSetMerge(t *testing.T) {
	expected := 6
	set1 := New("test1", "test2", "test3", "test6")
	set2 := New("test1", "test2", "test3", "test4", "test5")
	set1.Union(set2)
	if set1.Len() != expected {
		t.Errorf("Got %d, expected %d", set1.Len(), expected)
	}
}
