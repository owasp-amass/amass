package stringset

import (
	"strings"
)

type (
	Set map[string]nothing

	nothing struct{}
)

func New(initial ...string) Set {
	s := Set{}

	for _, v := range initial {
		s.Insert(v)
	}

	return s
}

func (s Set) Has(element string) bool {
	_, exists := s[element]
	return exists
}

func (s Set) Insert(element string) {
	s[strings.ToLower(element)] = nothing{}
}

func (s Set) InsertMany(elements ...string) {
	for _, i := range elements {
		s.Insert(i)
	}
}

func (s Set) Remove(element string) {
	delete(s, element)
}

func (s Set) ToSlice() []string {
	var i uint64

	k := make([]string, len(s))

	for key := range s {
		k[i] = key
		i++
	}

	return k
}

func (s Set) Union(other Set) {
	for k := range other {
		s.Insert(k)
	}
}

func (s Set) Len() int {
	return len(s)
}
