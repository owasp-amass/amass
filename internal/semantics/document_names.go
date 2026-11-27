// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package semantics

import (
	"bytes"
	"encoding/json"
	"regexp"
	"strings"
	"sync"
)

// documentNameRules tell when a name a document gives as an Organization or
// a Person names something else. Loaded from document_names.json; see that
// file's _about.
type documentNameRules struct {
	License       string   `json:"_license"`
	About         string   `json:"_about"`
	BuildingWords []string `json:"building_words"`
	LawWords      []string `json:"law_words"`
	LawPatterns   []string `json:"law_patterns"`
	CoursePattern string   `json:"course_pattern"`
	TitleEndings  []string `json:"title_endings"`
	TitleWords    []string `json:"title_words"`

	buildings, laws, endings, titles map[string]bool
	lawRE                            []*regexp.Regexp
	courseRE                         *regexp.Regexp
}

var loadDocumentNames = sync.OnceValue(func() *documentNameRules {
	r := &documentNameRules{}
	dec := json.NewDecoder(bytes.NewReader(File("document_names.json")))
	dec.DisallowUnknownFields()
	if err := dec.Decode(r); err != nil {
		panic("document_names.json: " + err.Error())
	}

	set := func(words []string) map[string]bool {
		m := make(map[string]bool, len(words))
		for _, w := range words {
			m[strings.ToLower(strings.TrimSpace(w))] = true
		}
		return m
	}
	r.buildings, r.laws = set(r.BuildingWords), set(r.LawWords)
	r.endings, r.titles = set(r.TitleEndings), set(r.TitleWords)
	for _, p := range r.LawPatterns {
		r.lawRE = append(r.lawRE, regexp.MustCompile(p))
	}
	r.courseRE = regexp.MustCompile(r.CoursePattern)
	return r
})

// MisnamedDocumentName returns what a name a document gives as an
// Organization or a Person (assetType) names instead, "a building", "a
// law", "a course" or "a job title", or "" when it may be one.
func MisnamedDocumentName(assetType, name string) string {
	r := loadDocumentNames()
	lower := strings.Join(strings.Fields(strings.ToLower(name)), " ")
	var words []string
	for _, w := range strings.Fields(lower) {
		if w = strings.Trim(w, ".,;:&'\"()"); w != "" {
			words = append(words, w)
		}
	}
	if len(words) == 0 {
		return ""
	}
	if r.courseRE.MatchString(lower) {
		return "a course"
	}

	last := words[len(words)-1]
	switch assetType {
	case "Organization":
		if r.buildings[last] {
			return "a building"
		}
		if r.laws[last] {
			return "a law"
		}
		for _, re := range r.lawRE {
			if re.MatchString(strings.Join(words, " ")) {
				return "a law"
			}
		}
	case "Person":
		if r.endings[last] {
			return "a job title"
		}
		for i := 0; i+1 < len(words); i++ {
			if r.titles[words[i]] && (words[i+1] == "of" || words[i+1] == "for") {
				return "a job title"
			}
		}
	}
	return ""
}
