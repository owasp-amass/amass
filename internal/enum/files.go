// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package enum

import (
	"fmt"
	"log/slog"

	"github.com/caffix/stringset"
	"github.com/owasp-amass/amass/v5/config"
	"github.com/owasp-amass/amass/v5/internal/tools"
	"github.com/owasp-amass/amass/v5/resources"
)

// Obtain parameters from provided input files
func processInputFiles(args *Args) error {
	getList := func(fp []string, name string, s *stringset.Set) error {
		for _, p := range fp {
			if p != "" {
				list, err := config.GetListFromFile(p)
				if err != nil {
					return fmt.Errorf("failed to parse the %s file: %v", name, err)
				}
				s.InsertMany(list...)
			}
		}
		return nil
	}

	if args.Options.BruteForcing {
		if len(args.Filepaths.BruteWordlist) > 0 {
			if err := getList(args.Filepaths.BruteWordlist, "brute force wordlist", args.BruteWordList); err != nil {
				return err
			}
		} else {
			if f, err := resources.GetResourceFile("namelist.txt"); err == nil {
				if list, err := config.GetWordList(f); err == nil {
					args.BruteWordList.InsertMany(list...)
				}
			}
		}
	}
	if !args.Options.NoAlts {
		if len(args.Filepaths.AltWordlist) > 0 {
			if err := getList(args.Filepaths.AltWordlist, "alterations wordlist", args.AltWordList); err != nil {
				return err
			}
		} else {
			if f, err := resources.GetResourceFile("alterations.txt"); err == nil {
				if list, err := config.GetWordList(f); err == nil {
					args.AltWordList.InsertMany(list...)
				}
			}
		}
	}
	if err := getList([]string{args.Filepaths.Blacklist}, "blacklist", args.Blacklist); err != nil {
		return err
	}
	if err := getList(args.Filepaths.Names, "subdomain names", args.Names); err != nil {
		return err
	}
	if err := getList(args.Filepaths.Domains, "domain names", args.Domains); err != nil {
		return err
	}
	if err := getList(args.Filepaths.Resolvers, "resolver", args.Resolvers); err != nil {
		return err
	}
	return nil
}

func selectLogger(dir, logfile string) (*slog.Logger, error) {
	l, err := tools.NewSyslogLogger()
	if err == nil {
		return l, nil
	}
	return tools.NewFileLogger(dir, logfile)
}
