package utils

import (
	"strings"
)

type (
	Set struct {
		data map[string]nothing
	}

	nothing struct{}
)

func NewSet(initial ...string) *Set {
	s := &Set{make(map[string]nothing)}

	for _, v := range initial {
		s.Insert(v)
	}

	return s
}

func (s *Set) Has(element string) bool {
	_, exists := s.data[element]
	return exists
}

func (s *Set) Insert(element string) {
	s.data[strings.ToLower(element)] = nothing{}
}

func (s *Set) InsertMany(elements ...string) {
	for _, i := range elements {
		s.Insert(i)
	}
}

func (s *Set) Remove(element string) {
	delete(s.data, element)
}

func (s *Set) ToSlice() []string {
	var i uint64

	k := make([]string, len(s.data))

	for key := range s.data {
		k[i] = key
		i++
	}

	return k
}

func (s *Set) Union(other *Set) {
	for k := range other.data {
		s.Insert(k)
	}
}

func (s *Set) Len() int {
	return len(s.data)
}
