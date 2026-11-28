// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

// Package cli implements amass lens, amass db and amass review: the
// read-only views of the Asset Database computed in Go, the database-hygiene
// scans that record correction proposals, and the review of those proposals.
// None of them uses a language model.
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
	"github.com/owasp-amass/amass/v5/internal/graph"
	"github.com/owasp-amass/amass/v5/internal/graph/oamrepo"
	"github.com/owasp-amass/amass/v5/internal/lens"
	"github.com/owasp-amass/amass/v5/internal/review"
	"github.com/owasp-amass/amass/v5/internal/tools"
)

// LensDescription, DBDescription and ReviewDescription describe the amass
// lens, amass db and amass review commands.
const (
	LensDescription   = "Read-only views of the Asset Database: organization families, corporate groups (org-group), vendors, vendors across a group (group-vendors), domains related to an organization (related-domains), exposed services, network infrastructure, dangling DNS, and recent changes"
	DBDescription     = "Database hygiene: scan the whole Asset Database for records to correct — duplicate organizations, contradicted legal identities, organizations that are really people, people that are really organizations (org-named), and organizations that are units of a parent (org-units) — and record each fix as a review proposal"
	ReviewDescription = "Review and apply inferred changes: ownership, merges of duplicates, identity corrections, and inferred relationships (org-units and other correlations)"
)

// lensOps are the amass lens views, by name, and the operation that runs
// each. Lenses read the Asset Database; family also records its findings in
// the review journal.
var lensOps = map[string]string{
	"family":                 "family",
	"org-group":              "org-group",
	"group-vendors":          "group-vendors",
	"vendors":                "vendors",
	"related-domains":        "related-domains",
	"related-infrastructure": "related-infrastructure",
}

// dbOps are the amass db commands, by name, and the operation that runs each.
// Unlike lenses, these scan the whole Asset Database for records to correct
// and record their findings in the review journal, so they are not read-only
// views and are not lenses.
var dbOps = map[string]string{
	"duplicates":        "duplicates",
	"person-duplicates": "person-duplicates",
	"identity":          "identity-conflicts",
	"person-named":      "person-named",
	"org-named":         "org-named",
	"org-units":         "org-units",
	"doc-relations":     "doc-relations",
}

// The registered subject lenses are amass lens commands too.
func init() {
	for _, l := range lens.SubjectLenses() {
		lensOps[l.Command] = l.Command
	}
}

// reviewOps are the amass review commands. Only approve and retract change
// the Asset Database for a proposal a reviewer names; keep-merged-names
// gives merges applied before merges kept every name the names they dropped;
// import-journal moves a file journal into the database's journal.
var reviewOps = map[string]string{
	"proposals":              "proposals",
	"approve":                "approve",
	"reject":                 "reject",
	"retract":                "retract",
	"signals":                "signals",
	"duplicate-signals":      "duplicate-signals",
	"horizontal-signals":     "horizontal-signals",
	"infrastructure-signals": "infrastructure-signals",
	"applied":                "applied",
	"signal-precision":       "signal-precision",
	"migrate-signals":        "migrate-signals",
	"keep-merged-names":      "keep-merged-names",
	"import-journal":         "import-journal",
	"lead":                   "lead",
}

// Operations maps each operation this package runs, by the name amass ai
// used for it, to the command that runs it now ("amass db identity").
func Operations() map[string]string {
	out := map[string]string{}
	for name, op := range lensOps {
		out[op] = "amass lens " + name
	}
	for name, op := range dbOps {
		out[op] = "amass db " + name
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

// DBWorkflow runs amass db.
func DBWorkflow(_ string, args []string) {
	if err := RunDB(os.Stdin, os.Stdout, os.Stderr, args); err != nil {
		fmt.Fprintln(os.Stderr, "amass db:", err)
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

// RunDB runs one database-hygiene command: amass db <name> [flags].
func RunDB(in io.Reader, out, errout io.Writer, args []string) error {
	return runGroup("db", dbOps, in, out, errout, args)
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
	for _, o := range dbOps {
		if o == op {
			group = "db"
		}
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
	var dir, configPath, journalPath, outputFormat, domainName, orgName, proposalID, reviewer, since, as string
	var only bool
	var withDomain, withOrg string
	var lensAssets, lensReads, ownerSteps, ownerDepth int
	var readStats, fixedHubs bool
	var vulnData string
	var timeout time.Duration
	fs.StringVar(&dir, "dir", "", "Amass data directory")
	fs.StringVar(&configPath, "config", "", "Amass configuration file")
	fs.StringVar(&journalPath, "journal", "",
		"Review journal path (default: the attribution journal, review.jsonl in the output directory)")
	fs.StringVar(&outputFormat, "format", "text", "Output format: text or json (signals: text, json or markdown)")
	fs.StringVar(&domainName, "domain", "", "Enumerated domain the lens starts from")
	fs.StringVar(&domainName, "d", "", "Enumerated domain the lens starts from (same as -domain)")
	fs.StringVar(&orgName, "org", "",
		"Organization the lens starts from (or use -d for a domain)")
	fs.StringVar(&since, "since", "",
		"Start of the changes lens window: a date (2026-11-01), an RFC 3339 time, or an age such as 7d or 72h (default 30d)")
	fs.StringVar(&withDomain, "with", "", "Second domain for the compare lens")
	fs.StringVar(&withOrg, "with-org", "", "Second organization for the compare lens")
	fs.StringVar(&proposalID, "proposal", "", "Proposal ID for approve, reject, retract or lead")
	fs.StringVar(&reviewer, "reviewer", "", "Name recorded with an approve, reject or retract decision")
	fs.StringVar(&as, "as", "", "What an approved name proposal (nk-...) names: person or organization")
	fs.BoolVar(&only, "only", false, "Approve or reject just this name proposal (nk-...), not every pending one "+
		"of the same name in the same field")
	fs.IntVar(&lensAssets, "max-assets", 0, "Optional limit on the controlled assets a lens follows "+
		"(default: none; a lens reads the whole footprint, bounded by -investigation-timeout)")
	fs.IntVar(&lensReads, "max-reads", 0, "Optional limit on the database reads of one lens run (default: none)")
	fs.IntVar(&ownerSteps, "owner-steps", 0, fmt.Sprintf("Assets the search for an asset's owner visits before "+
		"giving up (default: %d)", lens.DefaultOwnerSteps))
	fs.IntVar(&ownerDepth, "owner-depth", 0, fmt.Sprintf("Levels the search for the subject's own owner climbs "+
		"(default: %d)", lens.DefaultOwnerDepth))
	fs.StringVar(&vulnData, "vuln-data", "", "Vulnerability data file the vulnerable lens reads "+
		"(default from AMASS_VULN_DATA, or vulnerabilities.json in the output directory)")
	fs.BoolVar(&readStats, "read-stats", false,
		"Print the database reads the run made and their time to standard error")
	fs.BoolVar(&fixedHubs, "fixed-hubs", false, "Use the fixed hub limits in signals.json, not the limits the "+
		"database's data derives (as options.hubs.derive false does)")
	fs.DurationVar(&timeout, "investigation-timeout", 8*time.Minute,
		"Maximum time for one lens or review run (default from AMASS_LLM_INVESTIGATION_TIMEOUT, the limit amass ai also uses)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return fmt.Errorf("usage: amass %s <name> [flags]; unexpected arguments %v", group, fs.Args())
	}

	explicit := false
	fs.Visit(func(f *flag.Flag) { explicit = explicit || f.Name == "investigation-timeout" })
	if v, ok := os.LookupEnv("AMASS_LLM_INVESTIGATION_TIMEOUT"); ok && !explicit {
		d, err := time.ParseDuration(v)
		if err != nil {
			return fmt.Errorf("AMASS_LLM_INVESTIGATION_TIMEOUT: %w", err)
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
	case "horizontal-signals":
		return listHorizontalSignals(format, true, out)
	case "infrastructure-signals":
		return listInfrastructureSignals(format, true, out)
	}

	repo := tools.OpenGraphDatabase(cfg)
	if repo == nil {
		return errors.New("unable to open OAM database")
	}

	defer func() { _ = repo.Close() }()
	g := oamrepo.New(repo, cfg)
	g.FixedHubs = g.FixedHubs || fixedHubs
	if readStats {
		g.Stats = &oamrepo.ReadStats{}
		start := time.Now()
		defer func() {
			_, _ = fmt.Fprintf(errout, "\nDatabase reads (%s elapsed):\n", time.Since(start).Round(time.Millisecond))
			g.Stats.Write(errout)
		}()
	}

	limits := lens.LensLimits{MaxAssets: lensAssets, MaxReads: lensReads, OwnerSteps: ownerSteps,
		OwnerDepth: ownerDepth}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	// the journal is kept in the database when it keeps one
	j := review.OpenJournal(journalPath, repo)
	if operation != "import-journal" && j.FileNotImported() {
		_, _ = fmt.Fprintf(errout, "note: the review journal is kept in the Asset Database; %s has records that "+
			"were never imported and are not read: amass review import-journal -journal %s\n", journalPath,
			journalPath)
	}
	switch operation {
	case "proposals":
		return listProposals(j, format, true, out)
	case "signal-precision":
		return listSignalPrecision(j, format, out)
	case "migrate-signals":
		return migrateSignals(j, out)
	case "import-journal":
		return importJournal(j, journalPath, out)
	case "reject":
		if only {
			text, err := Decide(ctx, g, j, operation, proposalID, "", reviewer, true)
			if _, werr := fmt.Fprint(out, text); err == nil {
				err = werr
			}
			return err
		}
		return rejectProposal(j, proposalID, reviewer, out)
	case DecisionApprove, DecisionRetract:
		text, err := Decide(ctx, g, j, operation, proposalID, as, reviewer, only)
		if _, werr := fmt.Fprint(out, text); err == nil {
			err = werr
		}
		return err
	case "keep-merged-names":
		return keepMergedNames(ctx, g, j, out)
	case "duplicates":
		return listDuplicates(ctx, g, j, format, true, out, errout)
	case "person-duplicates":
		return listPersonDuplicates(ctx, g, j, format, true, out, errout)
	case "identity-conflicts":
		return listIdentityConflicts(ctx, g, j, format, true, out, errout)
	case "person-named":
		return listPersonNamed(ctx, g, j, format, true, out, errout)
	case "org-named":
		return listOrgNamed(ctx, g, j, format, true, out, errout)
	case "org-units":
		return listOrgUnits(ctx, g, j, format, true, out, errout)
	case "doc-relations":
		return listDocRelations(ctx, g, domainName, orgName, j, format, out, errout)
	case "vendors":
		return listVendors(ctx, g, domainName, limits, format, true, out)
	case "family":
		return listFamily(ctx, g, domainName, j, format, true, out, errout)
	case "org-group":
		return listGroup(ctx, g, domainName, orgName, format, true, out)
	case "group-vendors":
		return listGroupVendors(ctx, g, domainName, orgName, limits, format, true, out)
	case "related-domains":
		return listRelatedDomains(ctx, g, domainName, orgName, format, out)
	case "related-infrastructure":
		return listRelatedInfrastructure(ctx, g, domainName, orgName, format, out)
	case "accounts":
		return listAccounts(ctx, g, domainName, orgName, j, format, out, errout)
	case "applied":
		return listApplied(j, format, out)
	case "lead":
		if proposalID == "" {
			return errors.New("-proposal required: the document lead's ID (doclead:<run>:<entity>)")
		}
		text, err := LeadFootprintText(j, proposalID, func(id string) (graph.Asset, bool) {
			a, err := g.GetAsset(ctx, id)
			return a, err == nil
		})
		if err != nil {
			return err
		}
		_, err = fmt.Fprint(out, text)
		return err
	}

	if l, ok := lens.SubjectLensNamed(operation); ok {
		useVulnData(vulnData)
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
