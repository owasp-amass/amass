// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

// Package cli is amass secrets: data source credentials kept encrypted in
// the Asset Database, where every engine and tool on the database finds them.
package cli

import (
	"bufio"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/owasp-amass/amass/v5/config"
	"github.com/owasp-amass/amass/v5/internal/secrets"
	"github.com/owasp-amass/amass/v5/internal/tools"
)

// Description describes amass secrets.
const Description = "Keep data source credentials encrypted in the Asset Database, shared by every engine on it"

const usage = "usage: amass secrets <set|list|delete|rotate|found|new-key> [flags] [args]\n" +
	"  set <source> <field>     store a credential read from standard input (fields: apikey, secret, username, password)\n" +
	"  list                     list the stored credentials, never their values\n" +
	"  delete <source> [field]  delete a source's credential, or all of them without a field\n" +
	"  rotate                   re-encrypt every credential under a new key read from standard input\n" +
	"  found <kind>:<hash>      print the value of a credential found exposed (an exposed_secret Identifier)\n" +
	"  new-key                  print a new key for " + secrets.KeyEnv

// OpenStore opens the secret store of the database the configuration in
// dir or configPath names, under key, and returns a function closing it.
// Tests replace it.
var OpenStore = func(dir, configPath string, key *secrets.Key) (*secrets.Store, func(), error) {
	cfg := config.NewConfig()
	if err := config.AcquireConfig(dir, configPath, cfg); err != nil && configPath != "" {
		return nil, nil, fmt.Errorf("load Amass config: %w", err)
	}

	repo := tools.OpenGraphDatabase(cfg)
	if repo == nil {
		return nil, nil, errors.New("unable to open the Asset Database")
	}

	store := secrets.Open(repo, key)
	if store == nil {
		_ = repo.Close()
		return nil, nil, errors.New("this database keeps no secrets: the encrypted store needs a PostgreSQL or " +
			"SQLite Asset Database; with Neo4j, give credentials in the data sources file or in " +
			"AMASS_SECRET_<SOURCE>_<FIELD> environment variables")
	}

	return store, func() { _ = repo.Close() }, nil
}

// CLIWorkflow runs amass secrets.
func CLIWorkflow(_ string, args []string) {
	if err := Run(os.Stdin, os.Stdout, os.Stderr, args, os.LookupEnv); err != nil {
		fmt.Fprintln(os.Stderr, "amass secrets:", err)
		os.Exit(1)
	}
}

// Run runs one amass secrets command; lookup reads the environment.
func Run(in io.Reader, out, errout io.Writer, args []string, lookup func(string) (string, bool)) error {
	fs := flag.NewFlagSet("secrets", flag.ContinueOnError)
	fs.SetOutput(errout)
	var dir, configPath, format string
	fs.StringVar(&dir, "dir", "", "Amass data directory")
	fs.StringVar(&configPath, "config", "", "Amass configuration file")
	fs.StringVar(&format, "format", "text", "Output format of list: text or json")
	// flags may come before the command, after it, or both
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() == 0 {
		return errors.New(usage)
	}
	cmd := fs.Arg(0)
	if err := fs.Parse(fs.Args()[1:]); err != nil {
		return err
	}
	rest := fs.Args()

	if cmd == "new-key" {
		k, err := secrets.NewKey()
		if err != nil {
			return err
		}
		_, err = fmt.Fprintln(out, k)
		return err
	}

	switch cmd {
	case "set":
		if len(rest) != 2 {
			return errors.New("usage: amass secrets set [flags] <source> <field>, with the value on standard input")
		}
	case "delete":
		if len(rest) < 1 || len(rest) > 2 {
			return errors.New("usage: amass secrets delete [flags] <source> [field]")
		}
	case "found":
		if len(rest) != 1 {
			return errors.New("usage: amass secrets found [flags] <kind>:<hash>, the ID of an exposed_secret Identifier")
		}
		if _, _, ok := secrets.ParseFound(rest[0]); !ok {
			return fmt.Errorf("%q is not an exposed_secret Identifier's ID (<kind>:<hash>)", rest[0])
		}
	case "list", "rotate":
		if len(rest) != 0 {
			return fmt.Errorf("amass secrets %s takes no arguments", cmd)
		}
	default:
		return fmt.Errorf("unknown command %q\n%s", cmd, usage)
	}

	key, err := secrets.LoadKey(lookup)
	if err != nil {
		return err
	}
	if key == nil {
		return fmt.Errorf("set %s or %s to the secrets key (amass secrets new-key makes one)",
			secrets.KeyEnv, secrets.KeyFileEnv)
	}

	store, done, err := OpenStore(dir, configPath, key)
	if err != nil {
		return err
	}
	defer done()

	actor := "amass secrets"
	if u, ok := lookup("USER"); ok && u != "" {
		actor += " (" + u + ")"
	}

	switch cmd {
	case "set":
		value, err := readLine(in)
		if err != nil {
			return err
		}
		if value == "" {
			return errors.New("no value on standard input")
		}
		if err := store.Put(rest[0], rest[1], value, actor); err != nil {
			return err
		}
		_, err = fmt.Fprintf(out, "Stored %s\n", secrets.Name(rest[0], rest[1]))
		return err
	case "delete":
		return remove(store, out, rest, actor)
	case "rotate":
		return rotate(store, in, out, actor)
	case "found":
		kind, hash, _ := secrets.ParseFound(rest[0])
		value, err := store.Found(kind, hash, actor)
		if err != nil {
			return err
		}
		_, err = fmt.Fprintln(out, value)
		return err
	}
	return list(store, out, format)
}

// readLine reads the first line of in, without its line ending.
func readLine(in io.Reader) (string, error) {
	line, err := bufio.NewReader(in).ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return "", err
	}
	return strings.TrimRight(line, "\r\n"), nil
}

// list prints the stored credentials without their values.
func list(store *secrets.Store, out io.Writer, format string) error {
	entries, err := store.List()
	if err != nil {
		return err
	}

	switch format {
	case "json":
		enc := json.NewEncoder(out)
		enc.SetIndent("", "  ")
		return enc.Encode(entries)
	case "text":
	default:
		return fmt.Errorf("unknown format %q; use text or json", format)
	}

	if len(entries) == 0 {
		_, err := fmt.Fprintln(out, "No credentials are stored.")
		return err
	}
	tw := tabwriter.NewWriter(out, 0, 4, 2, ' ', 0)
	_, _ = fmt.Fprintln(tw, "SOURCE\tFIELD\tKEY\tUPDATED\tBY")
	for _, e := range entries {
		_, _ = fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n", e.Source, e.Field, e.KeyID,
			e.UpdatedAt.Local().Format(time.RFC3339), e.UpdatedBy)
	}
	return tw.Flush()
}

// remove deletes one credential, or every credential of a source.
func remove(store *secrets.Store, out io.Writer, args []string, actor string) error {
	var fields []string
	if len(args) == 2 {
		fields = []string{args[1]}
	} else {
		entries, err := store.List()
		if err != nil {
			return err
		}
		for _, e := range entries {
			if strings.EqualFold(e.Source, args[0]) {
				fields = append(fields, e.Field)
			}
		}
		if len(fields) == 0 {
			return fmt.Errorf("no credentials are stored for %s", args[0])
		}
	}

	for _, f := range fields {
		if err := store.Delete(args[0], f, actor); err != nil {
			return err
		}
		if _, err := fmt.Fprintf(out, "Deleted %s\n", secrets.Name(args[0], f)); err != nil {
			return err
		}
	}
	return nil
}

// rotate re-encrypts the store under the key on the first line of in.
func rotate(store *secrets.Store, in io.Reader, out io.Writer, actor string) error {
	encoded, err := readLine(in)
	if err != nil {
		return err
	}
	if encoded == "" {
		return errors.New("give the new key on standard input (amass secrets new-key makes one)")
	}
	next, err := secrets.ParseKey(encoded)
	if err != nil {
		return err
	}
	if next.ID() == store.Key.ID() {
		return errors.New("the new key is the current key")
	}

	rotated, skipped, err := store.Rotate(next, actor)
	if err != nil {
		return fmt.Errorf("after rotating %d: %w", rotated, err)
	}
	_, err = fmt.Fprintf(out, "Rotated %d credentials to key %s; %d under another key were left as they are.\n"+
		"Give every engine and tool the new key in %s.\n", rotated, next.ID(), skipped, secrets.KeyEnv)
	return err
}
