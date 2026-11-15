// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

// Package cli implements amass lens and amass review: the read-only views
// of the Asset Database computed in Go, and the review of the proposals they
// record. Neither uses a language model.
package cli

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/owasp-amass/amass/v5/config"
	"github.com/owasp-amass/amass/v5/internal/graph/oamrepo"
	"github.com/owasp-amass/amass/v5/internal/lens"
	"github.com/owasp-amass/amass/v5/internal/tools"
)

// LensDescription and ReviewDescription describe the amass lens and amass
// review commands.
const (
	LensDescription   = "Read-only views of the Asset Database: organization families, corporate groups (org-group), vendors, vendors across a group (group-vendors), exposed services, network infrastructure, dangling DNS, recent changes, duplicates, identities and person-named organizations"
	ReviewDescription = "Review and apply inferred changes: ownership, merges of duplicates, identity corrections"
)

// lensOps are the amass lens views, by name, and the operation that runs
// each. Lenses read the Asset Database; family, duplicates, identity and
// person-named also record their findings in the review journal.
var lensOps = map[string]string{
	"family":        "family",
	"org-group":     "org-group",
	"group-vendors": "group-vendors",
	"duplicates":    "duplicates",
	"identity":      "identity-conflicts",
	"person-named":  "person-named",
	"vendors":       "vendors",
}

// The registered subject lenses are amass lens commands too.
func init() {
	for _, l := range lens.SubjectLenses() {
		lensOps[l.Command] = l.Command
	}
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

// Operations maps each operation this package runs, by the name amass ai
// used for it, to the command that runs it now ("amass lens identity").
func Operations() map[string]string {
	out := map[string]string{}
	for name, op := range lensOps {
		out[op] = "amass lens " + name
	}
	for name, op := range reviewOps {
		out[op] = "amass review " + name
	}

	return out
}

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

// RunOperation runs an operation by the name amass ai used for it, such as
// identity-conflicts, with its flags in args.
func RunOperation(op string, in io.Reader, out, errout io.Writer, args []string) error {
	group := "lens"
	if _, ok := Operations()[op]; !ok {
		return fmt.Errorf("unknown operation %q", op)
	}
	for _, o := range reviewOps {
		if o == op {
			group = "review"
		}
	}

	return run(group, in, out, errout, append(append([]string{}, args...), op))
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
var boolFlags = map[string]bool{"h": true, "help": true, "read-stats": true}

// run parses the flags and runs op, the last argument.
func run(group string, _ io.Reader, out, errout io.Writer, args []string) error {
	fs := flag.NewFlagSet(group, flag.ContinueOnError)
	fs.SetOutput(errout)
	var dir, configPath, journalPath, outputFormat, domainName, orgName, proposalID, reviewer, since string
	var withDomain, withOrg string
	var lensAssets, lensReads int
	var readStats bool
	var timeout time.Duration
	fs.StringVar(&dir, "dir", "", "Amass data directory")
	fs.StringVar(&configPath, "config", "", "Amass configuration file")
	fs.StringVar(&journalPath, "journal", "",
		"Review journal path (default: the attribution journal, ai-review.jsonl in the output directory)")
	fs.StringVar(&outputFormat, "format", "text", "Output format: text or json (signals: text, json or markdown)")
	fs.StringVar(&domainName, "domain", "", "Enumerated domain the lens starts from")
	fs.StringVar(&domainName, "d", "", "Enumerated domain the lens starts from (same as -domain)")
	fs.StringVar(&orgName, "org", "",
		"Organization the lens starts from (or use -d for a domain)")
	fs.StringVar(&since, "since", "",
		"Start of the changes lens window: a date (2026-11-01), an RFC 3339 time, or an age such as 7d or 72h (default 30d)")
	fs.StringVar(&withDomain, "with", "", "Second domain for the compare lens")
	fs.StringVar(&withOrg, "with-org", "", "Second organization for the compare lens")
	fs.StringVar(&proposalID, "proposal", "", "Proposal ID for approve, reject or retract")
	fs.StringVar(&reviewer, "reviewer", "", "Name recorded with an approve, reject or retract decision")
	fs.IntVar(&lensAssets, "max-assets", 0, fmt.Sprintf("Maximum controlled assets a lens follows "+
		"(default 2000, up to %d); larger runs may need a longer -investigation-timeout", lens.LensMaxAssetsLimit))
	fs.IntVar(&lensReads, "max-reads", 0, fmt.Sprintf("Maximum database reads of one lens run "+
		"(default 20000, up to %d)", lens.LensMaxReadsLimit))
	fs.BoolVar(&readStats, "read-stats", false,
		"Print the database reads the run made and their time to standard error")
	fs.DurationVar(&timeout, "investigation-timeout", 8*time.Minute,
		"Maximum time for one lens or review run (default from AMASS_AI_INVESTIGATION_TIMEOUT, the limit amass ai also uses)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return fmt.Errorf("usage: amass %s <name> [flags]; unexpected arguments %v", group, fs.Args())
	}

	explicit := false
	fs.Visit(func(f *flag.Flag) { explicit = explicit || f.Name == "investigation-timeout" })
	if v, ok := os.LookupEnv("AMASS_AI_INVESTIGATION_TIMEOUT"); ok && !explicit {
		d, err := time.ParseDuration(v)
		if err != nil {
			return fmt.Errorf("AMASS_AI_INVESTIGATION_TIMEOUT: %w", err)
		}

		timeout = d
	}
	if timeout <= 0 || timeout > 2*time.Hour {
		return errors.New("investigation timeout must be between 0 and 2h")
	}

	format := outputFormat
	operation := fs.Arg(0)

	cfg := config.NewConfig()
	if err := config.AcquireConfig(dir, configPath, cfg); err != nil && configPath != "" {
		return fmt.Errorf("load Amass config: %w", err)
	}
	// The review journal defaults to the one automatic attribution uses.
	if journalPath == "" {
		_, path, err := cfg.AIAttribution(os.LookupEnv)
		if err != nil {
			return err
		}

		journalPath = path
	}

	// These read and append to the journal only.
	switch operation {
	case "signals":
		return listSignals(format, true, out)
	case "duplicate-signals":
		return listDuplicateSignals(format, true, out)
	case "proposals":
		return listProposals(journalPath, format, true, out)
	case "reject":
		return rejectProposal(journalPath, proposalID, reviewer, out)
	}

	repo := tools.OpenGraphDatabase(cfg)
	if repo == nil {
		return errors.New("unable to open OAM database")
	}

	defer func() { _ = repo.Close() }()
	g := oamrepo.Adapter{Repo: repo, Neo4jDatabase: oamrepo.Neo4jDatabaseName(cfg)}
	if readStats {
		g.Stats = &oamrepo.ReadStats{}
		start := time.Now()
		defer func() {
			_, _ = fmt.Fprintf(errout, "\nDatabase reads (%s elapsed):\n", time.Since(start).Round(time.Millisecond))
			g.Stats.Write(errout)
		}()
	}

	limits := lens.LensLimits{MaxAssets: lensAssets, MaxReads: lensReads}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	switch operation {
	case "approve":
		switch {
		case isPersonNamedProposal(proposalID):
			return approvePersonNamed(ctx, g, journalPath, proposalID, reviewer, out)
		case isIdentityProposal(proposalID):
			return approveIdentity(ctx, g, journalPath, proposalID, reviewer, out)
		case isMergeProposal(proposalID):
			return approveMerge(ctx, g, journalPath, proposalID, reviewer, out)
		}

		return approveProposal(ctx, g, journalPath, proposalID, reviewer, out)
	case "retract":
		switch {
		case isPersonNamedProposal(proposalID):
			return retractPersonNamed(ctx, g, journalPath, proposalID, reviewer, out)
		case isIdentityProposal(proposalID):
			return retractIdentity(ctx, g, journalPath, proposalID, reviewer, out)
		case isMergeProposal(proposalID):
			return retractMerge(ctx, g, journalPath, proposalID, reviewer, out)
		}

		return retractProposal(ctx, g, journalPath, proposalID, reviewer, out)
	case "duplicates":
		return listDuplicates(ctx, g, journalPath, format, true, out, errout)
	case "identity-conflicts":
		return listIdentityConflicts(ctx, g, journalPath, format, true, out, errout)
	case "person-named":
		return listPersonNamed(ctx, g, journalPath, format, true, out, errout)
	case "vendors":
		return listVendors(ctx, g, domainName, limits, format, true, out)
	case "family":
		return listFamily(ctx, g, domainName, journalPath, format, true, out, errout)
	case "org-group":
		return listGroup(ctx, g, domainName, orgName, format, true, out)
	case "group-vendors":
		return listGroupVendors(ctx, g, domainName, orgName, limits, format, true, out)
	}

	if l, ok := lens.SubjectLensNamed(operation); ok {
		root, err := groupRoot(ctx, g, domainName, orgName)
		if err != nil {
			return err
		}

		opts := lens.Options{Limits: limits}
		if opts.Since, err = parseSince(since, time.Now()); err != nil {
			return err
		}
		if l.NeedsOther {
			if withDomain == "" && withOrg == "" {
				return fmt.Errorf("the %s lens needs a second subject: -with <domain> or -with-org <name>", l.Command)
			}
			if opts.Other, err = groupRoot(ctx, g, withDomain, withOrg); err != nil {
				return err
			}
		}

		r, err := l.Find(ctx, g, oamrepo.Catalog{}, root, opts)
		if err != nil {
			return err
		}
		switch format {
		case "text":
			_, err := fmt.Fprint(out, r.Text())
			return err
		case "json":
			return writeJSON(out, r)
		}

		return fmt.Errorf("%s format %q: use text or json", l.Command, format)
	}

	return fmt.Errorf("unknown operation %q", operation)
}

func writeJSON(out io.Writer, v any) error {
	pretty, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}

	_, err = fmt.Fprintln(out, string(pretty))
	return err
}
