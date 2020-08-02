package safestringset

import (
	"fmt"
	"strings"
	"sync"
)

// SafeSet implements set operations for string values safe for concurrent use
// Implemented as an option for fixing Amass issue #445
type SafeSet struct {
	m map[string]bool
	sync.RWMutex
}

// New returns a SafeSet containing the values provided in the arguments.
func New(initial ...string) *SafeSet {

	s := &SafeSet{
		m: make(map[string]bool),
	}

	for _, v := range initial {
		s.Insert(v)
	}

	return s
}

// Deduplicate utilizes the SafeSet type to generate a unique list of strings from the input slice.
func Deduplicate(input []string) []string {
	return New(input...).Slice()
}

// Insert adds the element string argument to the receiver SafeSet.
func (s *SafeSet) Insert(item string) {
	s.Lock()
	defer s.Unlock()
	s.m[item] = true
}

// InsertMany adds all the elements strings into the receiver SafeSet.
func (s *SafeSet) InsertMany(elements ...string) {
	for _, i := range elements {
		s.Insert(i)
	}
}

// Remove deletes the specified item from the map
func (s *SafeSet) Remove(item string) {
	s.Lock()
	defer s.Unlock()
	delete(s.m, item)
}

// Union adds all the elements from the other SafeSet argument into the receiver SafeSet.
func (s *SafeSet) Union(other *SafeSet) {
	for k := range other.m {
		s.Insert(k)
	}
}

// Has looks for the existence of an item
func (s *SafeSet) Has(item string) bool {
	s.RLock()
	defer s.RUnlock()
	_, ok := s.m[item]
	return ok
}

// Subtract removes all elements in the other SafeSet argument from the receiver SafeSet.
func (s *SafeSet) Subtract(other *SafeSet) {
	for item := range other.m {
		if s.Has(item) {
			s.Remove(item)
		}
	}
}

// Intersect causes the receiver SafeSet to only contain elements also found in the
// other SafeSet argument.
func (s *SafeSet) Intersect(other *SafeSet) {
	intersect := New()

	for item := range other.m {
		if s.Has(item) {
			intersect.Insert(item)
		}
	}

	var remove []string
	for item := range s.m {
		if !intersect.Has(item) {
			remove = append(remove, item)
		}
	}

	for _, r := range remove {
		s.Remove(r)
	}
}

func (s *SafeSet) String() string {
	return strings.Join(s.Slice(), ",")
}

// Len returns the number of items in a SafeSet.
func (s *SafeSet) Len() int {
	return len(s.List())
}

// Slice returns a string slice that contains all the elements in the SafeSet.
func (s *SafeSet) Slice() []string {
	var i uint64
	s.RLock()
	defer s.RUnlock()

	k := make([]string, len(s.m))

	for key := range s.m {
		k[i] = key
		i++
	}

	return k
}

// SafeSet implements the flag.Value interface.
func (s *SafeSet) SafeSet(input string) error {
	if input == "" {
		return fmt.Errorf("String parsing failed")
	}

	items := strings.Split(input, ",")
	for _, item := range items {
		s.Insert(strings.TrimSpace(item))
	}
	return nil
}

// List returns a slice of all items.
func (s *SafeSet) List() []string {
	s.RLock()
	defer s.RUnlock()
	list := make([]string, 0)
	for item := range s.m {
		list = append(list, item)
	}
	return list
}
