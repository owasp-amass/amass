// Copyright 2017-2020 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package config

import (
	"fmt"

	"github.com/caffix/stringset"
	"github.com/go-ini/ini"
)

func (c *Config) loadBruteForceSettings(cfg *ini.File) error {
	bruteforce, err := cfg.GetSection("bruteforce")
	if err != nil {
		return nil
	}

	c.BruteForcing = bruteforce.Key("enabled").MustBool(true)
	if !c.BruteForcing {
		return nil
	}

	c.Recursive = bruteforce.Key("recursive").MustBool(true)
	c.MinForRecursive = bruteforce.Key("minimum_for_recursive").MustInt(0)
	c.MaxDepth = bruteforce.Key("max_depth").MustInt(0)

	if bruteforce.HasKey("wordlist_file") {
		for _, wordlist := range bruteforce.Key("wordlist_file").ValueWithShadows() {
			list, err := GetListFromFile(wordlist)
			if err != nil {
				return fmt.Errorf("Unable to load the file in the bruteforce wordlist_file setting: %s: %v", wordlist, err)
			}
			c.Wordlist = append(c.Wordlist, list...)
		}
	}

	c.Wordlist = stringset.Deduplicate(c.Wordlist)
	return nil
}

func (c *Config) loadAlterationSettings(cfg *ini.File) error {
	alterations, err := cfg.GetSection("alterations")
	if err != nil {
		return nil
	}

	c.Alterations = alterations.Key("enabled").MustBool(true)
	if !c.Alterations {
		return nil
	}

	c.FlipWords = alterations.Key("flip_words").MustBool(true)
	c.AddWords = alterations.Key("add_words").MustBool(true)
	c.FlipNumbers = alterations.Key("flip_numbers").MustBool(true)
	c.AddNumbers = alterations.Key("add_numbers").MustBool(true)
	c.MinForWordFlip = alterations.Key("minimum_for_word_flip").MustInt(2)
	c.EditDistance = alterations.Key("edit_distance").MustInt(1)

	if alterations.HasKey("wordlist_file") {
		for _, wordlist := range alterations.Key("wordlist_file").ValueWithShadows() {
			list, err := GetListFromFile(wordlist)
			if err != nil {
				return fmt.Errorf("Unable to load the file in the alterations wordlist_file setting: %s: %v", wordlist, err)
			}
			c.AltWordlist = append(c.AltWordlist, list...)
		}
	}

	c.AltWordlist = stringset.Deduplicate(c.AltWordlist)
	return nil
}
