package stringset

import (
	"fmt"
	"strings"
)

type (
	// Set implements set operations for string values.
	Set map[string]nothing

	nothing struct{}
)

// Deduplicate utilizes the Set type to generate a unique list of strings from the input slice.
func Deduplicate(input []string) []string {
	return New(input...).Slice()
}

// New returns a Set containing the values provided in the arguments.
func New(initial ...string) Set {
	s := make(Set)

	for _, v := range initial {
		s.Insert(v)
	}

	return s
}

// Has returns true if the receiver Set already contains the element string argument.
func (s Set) Has(element string) bool {
	_, exists := s[strings.ToLower(element)]
	return exists
}

// Insert adds the element string argument to the receiver Set.
func (s Set) Insert(element string) {
	s[strings.ToLower(element)] = nothing{}
}

// InsertMany adds all the elements strings into the receiver Set.
func (s Set) InsertMany(elements ...string) {
	for _, i := range elements {
		s.Insert(i)
	}
}

// Remove will delete the element string from the receiver Set.
func (s Set) Remove(element string) {
	e := strings.ToLower(element)

	if _, ok := s[e]; ok {
		delete(s, e)
	}
}

// Slice returns a string slice that contains all the elements in the Set.
func (s Set) Slice() []string {
	var i uint64

	k := make([]string, len(s))

	for key := range s {
		k[i] = key
		i++
	}

	return k
}

// Union adds all the elements from the other Set argument into the receiver Set.
func (s Set) Union(other Set) {
	for k := range other {
		s.Insert(k)
	}
}

// Len returns the number of elements in the receiver Set.
func (s Set) Len() int {
	return len(s)
}

// Subtract removes all elements in the other Set argument from the receiver Set.
func (s Set) Subtract(other Set) {
	for item := range other {
		if s.Has(item) {
			s.Remove(item)
		}
	}
}

// Intersect causes the receiver Set to only contain elements also found in the
// other Set argument.
func (s Set) Intersect(other Set) {
	intersect := New()

	for item := range other {
		if s.Has(item) {
			intersect.Insert(item)
		}
	}

	var remove []string
	for item := range s {
		if !intersect.Has(item) {
			remove = append(remove, item)
		}
	}

	for _, r := range remove {
		s.Remove(r)
	}
}

// Set implements the flag.Value interface.
func (s *Set) String() string {
	return strings.Join(s.Slice(), ",")
}

// Set implements the flag.Value interface.
func (s *Set) Set(input string) error {
	if input == "" {
		return fmt.Errorf("String parsing failed")
	}

	items := strings.Split(input, ",")
	for _, item := range items {
		s.Insert(strings.TrimSpace(item))
	}
	return nil
}
