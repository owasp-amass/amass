// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package semantics

import (
	"embed"
	"fmt"
)

// files holds the data files the AI packages read: the vocabularies, lens
// rules and fingerprints that keep their behavior data-driven.
//
//go:embed *.json
var files embed.FS

// File returns the named data file of this directory. A missing file is a
// build defect, so it panics rather than returning an error.
func File(name string) []byte {
	b, err := files.ReadFile(name)
	if err != nil {
		panic(fmt.Sprintf("semantics: %v", err))
	}
	return b
}
