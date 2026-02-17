// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"bufio"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/caffix/stringset"
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

// GetListFromFile reads a wordlist text or gzip file and returns the slice of words.
func GetListFromFile(path string) ([]string, error) {
	var reader io.Reader

	absPath, err := filepath.Abs(path)
	if err != nil {
		return nil, fmt.Errorf("failed to get absolute path: %v", err)
	}

	file, err := os.Open(absPath)
	if err != nil {
		return nil, fmt.Errorf("error opening the file %s: %v", absPath, err)
	}
	defer func() { _ = file.Close() }()
	reader = file

	if finfo, err := file.Stat(); err == nil && finfo.Size() == 0 {
		return nil, errors.New("the file is empty")
	}

	if gz, err := getGzipReader(file, absPath); err == nil {
		defer func() { _ = gz.Close() }()
		reader = gz
	}

	return GetWordList(reader)
}

func getGzipReader(file *os.File, absPath string) (*gzip.Reader, error) {
	finfo, err := file.Stat()
	if err != nil {
		return nil, err
	}

	if finfo.Size() < 512 {
		return nil, errors.New("file cannot be checked for compression")
	}

	// We need to determine if this is a gzipped file or a plain text file, so we
	// first read the first 512 bytes to pass them down to http.DetectContentType
	// for mime detection. The file is rewinded before passing it along to the
	// next reader
	head := make([]byte, 512)
	if _, err = file.Read(head); err != nil {
		return nil, fmt.Errorf("error reading the first 512 bytes from %s: %s", absPath, err)
	}
	if _, err = file.Seek(0, 0); err != nil {
		return nil, fmt.Errorf("error rewinding the file %s: %s", absPath, err)
	}

	// Read the file as gzip if it's actually compressed
	if mt := http.DetectContentType(head); mt == "application/gzip" || mt == "application/x-gzip" {
		gzReader, err := gzip.NewReader(file)
		if err != nil {
			return nil, fmt.Errorf("error gz-reading the file %s: %v", absPath, err)
		}

		return gzReader, nil
	}

	return nil, fmt.Errorf("%s is not compressed", absPath)
}

func GetWordList(reader io.Reader) ([]string, error) {
	var words []string

	scanner := bufio.NewScanner(reader)
	for scanner.Scan() {
		// Get the next word in the list
		w := strings.TrimSpace(scanner.Text())
		if err := scanner.Err(); err == nil && w != "" {
			words = append(words, w)
		}
	}

	return stringset.Deduplicate(words), nil
}
