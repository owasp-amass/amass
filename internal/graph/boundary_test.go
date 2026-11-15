// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package graph_test

import (
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"strings"
	"testing"
)

// The graph view, the lenses, review, collection and the semantics data run
// during enumerations and from amass lens and amass review, with no language
// model configured. None of them, tests included, may import internal/ai, which
// holds what needs a model; internal/ai builds on them, not the reverse.
func TestModelFreePackagesDoNotImportAI(t *testing.T) {
	const ai = "github.com/owasp-amass/amass/v5/internal/ai"
	fset := token.NewFileSet()
	for _, dir := range []string{".", "../lens", "../review", "../semantics", "../collect"} {
		err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
			if err != nil || d.IsDir() || !strings.HasSuffix(path, ".go") {
				return err
			}

			f, err := parser.ParseFile(fset, path, nil, parser.ImportsOnly)
			if err != nil {
				return err
			}
			for _, imp := range f.Imports {
				p := strings.Trim(imp.Path.Value, `"`)
				if p == ai || strings.HasPrefix(p, ai+"/") {
					t.Errorf("%s imports %s", path, p)
				}
			}

			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
}
