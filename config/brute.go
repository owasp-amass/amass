// Copyright © by Jeff Foley 2017-2025. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"fmt"

	"github.com/caffix/stringset"
)

func (c *Config) loadBruteForceSettings(cfg *Config) error {
	bruteforceRaw, ok := c.Options["bruteforce"]
	if !ok {
		return nil
	}

	bruteforce, ok := bruteforceRaw.(map[string]interface{})
	if !ok {
		return fmt.Errorf("bruteforce is not a map[string]interface{}")
	}

	enabled, ok := bruteforce["enabled"].(bool)
	if !ok {
		return fmt.Errorf("bruteforce enabled is not a bool")
	}

	c.BruteForcing = enabled
	if !c.BruteForcing {
		return nil
	}

	if wordlistPathRaw, ok := bruteforce["wordlists"]; ok {
		wordlistPaths, ok := wordlistPathRaw.([]interface{})
		if !ok {
			return fmt.Errorf("bruteforce wordlist_file is not an array")
		}

		for _, wordlistPathRaw := range wordlistPaths {
			wordlistPath, ok := wordlistPathRaw.(string)
			if !ok {
				return fmt.Errorf("bruteforce wordlist_file item is not a string")
			}

			absPath, err := c.AbsPathFromConfigDir(wordlistPath)
			if err != nil {
				return fmt.Errorf("failed to get absolute path for wordlist file: %w", err)
			}

			wordlist, err := GetListFromFile(absPath)
			if err != nil {
				return fmt.Errorf("unable to load the file in the bruteforce wordlist_file setting: %s: %v", absPath, err)
			}

			c.Wordlist = append(c.Wordlist, wordlist...)
		}
	}

	c.Wordlist = stringset.Deduplicate(c.Wordlist)
	return nil
}

func (c *Config) loadAlterationSettings(cfg *Config) error {
	alterationsRaw, ok := c.Options["alterations"]
	if !ok {
		return nil
	}

	alterations, ok := alterationsRaw.(map[string]interface{})
	if !ok {
		return fmt.Errorf("alterations is not a map[string]interface{}")
	}

	enabled, ok := alterations["enabled"].(bool)
	if !ok {
		return fmt.Errorf("alterations enabled is not a bool")
	}

	c.Alterations = enabled
	if !c.Alterations {
		return nil
	}

	if wordlistPathRaw, ok := alterations["wordlists"]; ok {
		wordlistPaths, ok := wordlistPathRaw.([]interface{})
		if !ok {
			return fmt.Errorf("alterations wordlist_file is not an array")
		}

		for _, wordlistPathRaw := range wordlistPaths {
			wordlistPath, ok := wordlistPathRaw.(string)
			if !ok {
				return fmt.Errorf("alterations wordlist_file item is not a string")
			}

			absPath, err := c.AbsPathFromConfigDir(wordlistPath)
			if err != nil {
				return fmt.Errorf("failed to get absolute path for wordlist file: %w", err)
			}

			wordlist, err := GetListFromFile(absPath)
			if err != nil {
				return fmt.Errorf("unable to load the file in the alterations wordlist_file setting: %s: %v", absPath, err)
			}

			c.AltWordlist = append(c.AltWordlist, wordlist...)
		}
	}

	c.AltWordlist = stringset.Deduplicate(c.AltWordlist)
	return nil
}
