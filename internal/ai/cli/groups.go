// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
)

// LensDescription and ReviewDescription describe the amass lens and amass
// review commands.
const (
	LensDescription   = "Read-only views of the Asset Database: organization families, duplicates and contradicted identities"
	ReviewDescription = "Review and apply inferred changes: ownership, merges of duplicates, identity corrections"
)

// lensOps are the amass lens views, by name, and the operation that runs
// each. Lenses read the Asset Database; duplicates and identity also record
// their findings in the review journal.
var lensOps = map[string]string{
	"family":     "family",
	"duplicates": "duplicates",
	"identity":   "identity-conflicts",
}

// reviewOps are the amass review commands. Only approve and retract change
// the Asset Database, and only for a proposal a reviewer names.
var reviewOps = map[string]string{
	"proposals":         "proposals",
	"approve":           "approve",
	"reject":            "reject",
	"retract":           "retract",
	"signals":           "signals",
	"duplicate-signals": "duplicate-signals",
}

// movedOps are amass ai operations that moved to amass lens or amass
// review; amass ai still runs them, with a note.
var movedOps = func() map[string]string {
	out := map[string]string{}
	for name, op := range lensOps {
		out[op] = "amass lens " + name
	}
	for name, op := range reviewOps {
		out[op] = "amass review " + name
	}
	return out
}()

// LensWorkflow runs amass lens.
func LensWorkflow(_ string, args []string) {
	if err := RunLens(os.Stdin, os.Stdout, os.Stderr, args); err != nil {
		fmt.Fprintln(os.Stderr, "amass lens:", err)
		os.Exit(1)
	}
}

// ReviewWorkflow runs amass review.
func ReviewWorkflow(_ string, args []string) {
	if err := RunReview(os.Stdin, os.Stdout, os.Stderr, args); err != nil {
		fmt.Fprintln(os.Stderr, "amass review:", err)
		os.Exit(1)
	}
}

// RunLens runs one lens: amass lens <name> [flags].
func RunLens(in io.Reader, out, errout io.Writer, args []string) error {
	return runGroup("lens", lensOps, in, out, errout, args)
}

// RunReview runs one review command: amass review <name> [flags].
func RunReview(in io.Reader, out, errout io.Writer, args []string) error {
	return runGroup("review", reviewOps, in, out, errout, args)
}

func runGroup(group string, ops map[string]string, in io.Reader, out, errout io.Writer, args []string) error {
	names := make([]string, 0, len(ops))
	for n := range ops {
		names = append(names, n)
	}
	sort.Strings(names)

	usage := fmt.Sprintf("usage: amass %s <%s> [flags]", group, strings.Join(names, "|"))

	// The name is the first argument that is not a flag or a flag's value,
	// so flags may also come first (amass lens -config c.yaml family).
	at := -1
	for i := 0; i < len(args); i++ {
		a := args[i]
		if !strings.HasPrefix(a, "-") {
			at = i
			break
		}
		if !strings.Contains(a, "=") && !boolFlags[strings.TrimLeft(a, "-")] {
			i++
		}
	}
	if at < 0 {
		return errors.New(usage)
	}

	op, ok := ops[args[at]]
	if !ok {
		return fmt.Errorf("unknown %s %q; %s", group, args[at], usage)
	}

	rest := append(append([]string{}, args[:at]...), args[at+1:]...)
	return run(group, in, out, errout, append(rest, op))
}

// boolFlags are the flags that take no value.
var boolFlags = map[string]bool{"allow-http": true, "classifier-review": true, "think": true, "trace": true,
	"narrate": true, "h": true, "help": true}
