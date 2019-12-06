// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package wordlist

import (
	"bufio"
	"fmt"
	"io"
	"strings"
)

const (
	maskLetters = "abcdefghijklmnopqrstuvwxyz"
	maskDigits  = "0123456789"
	maskSpecial = "-"
)

var (
	// KnownValidTLDs is a list of valid top-level domains that is maintained by the IANA.
	KnownValidTLDs []string
)

func getWordList(reader io.Reader) []string {
	var words []string

	scanner := bufio.NewScanner(reader)
	for scanner.Scan() {
		// Get the next word in the list
		w := strings.TrimSpace(scanner.Text())
		if err := scanner.Err(); err == nil && w != "" && !strings.Contains(w, "-") {
			words = append(words, w)
		}
	}
	return words
}

// ExpandMask will return a slice of words that a "hashcat-style" mask matches.
func ExpandMask(word string) ([]string, error) {
	var expanded []string
	var chars string

	if strings.Count(word, "?") > 3 {
		return expanded, fmt.Errorf("Exceeded maximum mask size (3): %s", word)
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
				return expanded, fmt.Errorf("Improper mask used: %s", word)
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
	var newWords []string
	var err error

	for _, word := range wordlist {
		newWords, err = ExpandMask(word)
		if err != nil {
			break
		}

		newWordlist = append(newWordlist, newWords...)
	}

	return newWordlist, err
}
