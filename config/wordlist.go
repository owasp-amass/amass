// Copyright © by Jeff Foley 2017-2023. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"fmt"
	"strings"
)

const (
	maskLetters = "abcdefghijklmnopqrstuvwxyz"
	maskDigits  = "0123456789"
	maskSpecial = "-"
)

// ExpandMask will return a slice of words that a "hashcat-style" mask matches.
func ExpandMask(word string) ([]string, error) {
	var expanded []string
	var chars string

	if strings.Count(word, "?") > 3 {
		return expanded, fmt.Errorf("exceeded maximum mask size (3): %s", word)
	}

	parts := strings.SplitN(word, "?", 2)
	if len(parts) > 1 {
		if len(parts[1]) > 0 {
			switch parts[1][0] {
			case 'a':
				chars = maskLetters + maskDigits + maskSpecial
			case 'd':
				chars = maskDigits
			case 'u':
				fallthrough
			case 'l':
				chars = maskLetters
			case 's':
				chars = maskSpecial
			default:
				return expanded, fmt.Errorf("improper mask used: %s", word)
			}
			for _, ch := range chars {
				newWord := parts[0] + string(ch) + parts[1][1:]
				nextRound, err := ExpandMask(newWord)
				if err != nil {
					return expanded, err
				}
				expanded = append(expanded, nextRound...)
			}
		}
	} else {
		expanded = append(expanded, word)
	}
	return expanded, nil
}

// ExpandMaskWordlist performs ExpandMask on a slice of words.
func ExpandMaskWordlist(wordlist []string) ([]string, error) {
	var newWordlist []string

	for _, word := range wordlist {
		if words, err := ExpandMask(word); err == nil {
			newWordlist = append(newWordlist, words...)
		}
	}

	return newWordlist, nil
}
