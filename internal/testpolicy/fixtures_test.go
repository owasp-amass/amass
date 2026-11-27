// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

// Package testpolicy holds checks on the repository's test data.
package testpolicy

import (
	"bufio"
	"go/scanner"
	"go/token"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strings"
	"testing"

	"golang.org/x/net/publicsuffix"
)

// hostPattern finds lower-case host names. In Go sources only string
// literals and comments are read, so selectors such as tc.name are not
// taken for host names.
var hostPattern = regexp.MustCompile(`(?:^|[^A-Za-z0-9_.@-])((?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24})(?:$|[^A-Za-z0-9_-])`)

// fixture reports whether a repository file is test data: a test source,
// a file under a testdata directory, the shared test fixtures or the
// question evaluation set.
func fixture(rel string) bool {
	rel = filepath.ToSlash(rel)
	return strings.HasSuffix(rel, "_test.go") || strings.Contains(rel, "/testdata/") ||
		strings.HasPrefix(rel, "internal/graph/graphtest/") || strings.HasPrefix(rel, "internal/ai/questions/")
}

// Tests never name the assets of a real organization seen in a live run.
// The subject of a test is OWASP's (owasp.org), Utica University's
// (utica.edu) or SUNY Poly's (sunyit.edu, sunypoly.edu); every other
// domain is a reserved or made-up name, or a provider or standard the
// shipped data already names. A domain this rejects is either replaced, or,
// when it is a provider or a made-up name, added to testdata/allowed_domains.txt.
func TestFixturesNameNoRealOrganizations(t *testing.T) {
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}

	allowed, patterns := loadAllowed(t)
	shipped := shippedDomains(t, root)
	found := map[string][]string{}

	err = filepath.WalkDir(root, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(root, p)
		if d.IsDir() {
			switch d.Name() {
			case ".git", "vendor", "node_modules":
				return filepath.SkipDir
			}
			return nil
		}
		if !fixture(rel) || strings.HasPrefix(filepath.ToSlash(rel), "internal/testpolicy/") {
			return nil
		}

		data, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		for _, m := range hostPattern.FindAllStringSubmatch(text(rel, data), -1) {
			reg := registered(m[1])
			if reg == "" || allowed[reg] || shipped[reg] || matchesAny(reg, patterns) {
				continue
			}
			if !slices.Contains(found[reg], rel) {
				found[reg] = append(found[reg], rel)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}

	var names []string
	for reg := range found {
		names = append(names, reg)
	}
	sort.Strings(names)
	for _, reg := range names {
		t.Errorf("%s in %s: use owasp.org, utica.edu, sunyit.edu or a reserved name (example.com, *.example), "+
			"or add a provider or made-up name to internal/testpolicy/testdata/allowed_domains.txt",
			reg, strings.Join(found[reg], ", "))
	}
}

// text returns what a file says: a Go source's string literals and comments,
// or the whole of any other file.
func text(name string, data []byte) string {
	if !strings.HasSuffix(name, ".go") {
		return string(data)
	}

	var s scanner.Scanner
	var b strings.Builder
	fset := token.NewFileSet()
	s.Init(fset.AddFile(name, -1, len(data)), data, nil, scanner.ScanComments)
	for {
		_, tok, lit := s.Scan()
		if tok == token.EOF {
			break
		}
		if tok == token.STRING || tok == token.COMMENT {
			b.WriteString(lit)
			b.WriteByte('\n')
		}
	}

	return b.String()
}

// registered returns the name a registry holds for host, or "" when host
// has no public suffix that ICANN manages (reserved names such as
// example.test, and dotted identifiers that are not host names).
func registered(host string) string {
	host = strings.Trim(host, ".")
	suffix, icann := publicsuffix.PublicSuffix(host)
	if !icann || suffix == host {
		return ""
	}
	reg, err := publicsuffix.EffectiveTLDPlusOne(host)
	if err != nil {
		return ""
	}

	return reg
}

// loadAllowed reads the allowed registered domains and the patterns, such as
// *example*, that allow any registered domain matching them.
func loadAllowed(t *testing.T) (map[string]bool, []string) {
	f, err := os.Open(filepath.Join("testdata", "allowed_domains.txt"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()

	allowed := map[string]bool{}
	var patterns []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line, _, _ := strings.Cut(sc.Text(), "#")
		if line = strings.TrimSpace(line); line == "" {
			continue
		}
		if strings.ContainsAny(line, "*?[") {
			patterns = append(patterns, line)
			continue
		}
		allowed[line] = true
	}
	if err := sc.Err(); err != nil {
		t.Fatal(err)
	}

	return allowed, patterns
}

func matchesAny(reg string, patterns []string) bool {
	for _, p := range patterns {
		if ok, _ := path.Match(p, reg); ok {
			return true
		}
	}
	return false
}

// shippedDomains returns the registered domains the shipped semantics data
// names: the providers, platforms and standards the code recognizes.
func shippedDomains(t *testing.T, root string) map[string]bool {
	out := map[string]bool{}
	files, err := filepath.Glob(filepath.Join(root, "internal", "semantics", "*.json"))
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range files {
		data, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		for _, m := range hostPattern.FindAllStringSubmatch(strings.ToLower(string(data)), -1) {
			if reg := registered(m[1]); reg != "" {
				out[reg] = true
			}
		}
	}

	return out
}
