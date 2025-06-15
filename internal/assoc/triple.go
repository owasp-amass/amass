// Copyright © by Jeff Foley 2017-2025. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package assoc

import (
	oam "github.com/owasp-amass/open-asset-model"
)

type Triple struct {
	Subject   string
	Predicate string
	Object    string
}

type Node struct {
	Key        string
	Type       oam.AssetType
	Attributes map[string]string
	Properties []Property
}

type Predicate struct {
	Label      string
	Type       oam.RelationType
	Attributes map[string]string
	Properties []Property
}

type Property struct {
	Name       string
	Value      string
	Type       oam.PropertyType
	Attributes map[string]string
}
