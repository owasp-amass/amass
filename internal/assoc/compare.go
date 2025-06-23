// Copyright © by Jeff Foley 2017-2025. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package assoc

import (
	"reflect"
	"regexp"
	"strconv"
	"strings"

	oam "github.com/owasp-amass/open-asset-model"
)

func (n *Node) IsWildcard() bool {
	return n.Key == "*" && (n.Type != oam.AssetType("*") || len(n.Attributes) == 0)
}

func (p *Predicate) IsWildcard() bool {
	return p.Label == "*" && (p.Type != oam.RelationType("*") || len(p.Attributes) == 0)
}

func isRegexp(s string) (string, bool) {
	if strings.HasPrefix(s, "#/") && strings.HasSuffix(s, "/#") && len(s) > 4 {
		return s[2 : len(s)-2], true
	}
	return s, false
}

func valueMatch(a, b string, re *regexp.Regexp) bool {
	if re != nil {
		return re.MatchString(a)
	}
	return strings.EqualFold(a, b)
}

func allAttrsMatch(s any, attrs map[string]*AttrValue) bool {
	for k, v := range attrs {
		if !attrMatch(s, k, v) {
			return false
		}
	}
	return true
}

func attrMatch(s any, path string, av *AttrValue) bool {
	val := reflect.ValueOf(s)
	labels := strings.Split(path, ".")

	// follow the path through the nested structs
	for _, label := range labels {
		if val.Kind() == reflect.Ptr {
			val = val.Elem()
		}
		if val.Kind() != reflect.Struct {
			return false
		}

		var index int
		var found bool
		st := val.Type()
		for i := range st.NumField() {
			field := st.Field(i)
			// handle cases like `json:"name,omitempty"`
			tag := strings.SplitN(field.Tag.Get("json"), ",", 2)[0]

			if tag == label {
				found = true
				index = i
				break
			}
		}
		if !found {
			return false
		}

		val = val.Field(index)
	}

	// compare val to the value parameter
	switch val.Kind() {
	case reflect.Bool:
		b := "false"
		if val.Bool() {
			b = "true"
		}
		return strings.EqualFold(b, av.Value)
	case reflect.String:
		return valueMatch(val.String(), av.Value, av.Regexp)
	case reflect.Int:
		return valueMatch(strconv.FormatInt(val.Int(), 10), av.Value, av.Regexp)
	case reflect.Float64:
		fmt64 := strconv.FormatFloat(val.Float(), 'f', -1, 64)
		return valueMatch(fmt64, av.Value, av.Regexp)
	}

	return false
}
