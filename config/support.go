// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package config

import (
	"bufio"
	"compress/gzip"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	amasshttp "github.com/OWASP/Amass/net/http"
	"github.com/OWASP/Amass/stringset"
)

const (
	outputDirectoryName         = "amass"
)

// AcquireConfig populates the Config struct provided by the config argument.
// The configuration file path and a bool indicating the settings were
// successfully loaded are returned.
func AcquireConfig(dir, file string, config *Config) error {
	var err error

	if file != "" {
		err = config.LoadSettings(file)
		if err == nil {
			return nil
		}
	}
	if dir = OutputDirectory(dir); dir != "" {
		if finfo, err := os.Stat(dir); !os.IsNotExist(err) && finfo.IsDir() {
			file := filepath.Join(dir, "config.ini")

			err = config.LoadSettings(file)
			if err == nil {
				return nil
			}
		}
	}
	return err
}

// OutputDirectory returns the file path of the Amass output directory. A suitable
// path provided will be used as the output directory instead.
func OutputDirectory(dir string) string {
	if dir == "" {
		if path, err := os.UserConfigDir(); err == nil {
			dir = filepath.Join(path, outputDirectoryName)
		}
	}
	return dir
}

// GetListFromFile reads a wordlist text or gzip file and returns the slice of words.
func GetListFromFile(path string) ([]string, error) {
	var reader io.Reader

	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("Error opening the file %s: %v", path, err)
	}
	defer file.Close()
	reader = file

	// We need to determine if this is a gzipped file or a plain text file, so we
	// first read the first 512 bytes to pass them down to http.DetectContentType
	// for mime detection. The file is rewinded before passing it along to the
	// next reader
	head := make([]byte, 512)
	if _, err = file.Read(head); err != nil {
		return nil, fmt.Errorf("Error reading the first 512 bytes from %s: %s", path, err)
	}
	if _, err = file.Seek(0, 0); err != nil {
		return nil, fmt.Errorf("Error rewinding the file %s: %s", path, err)
	}

	// Read the file as gzip if it's actually compressed
	if mt := http.DetectContentType(head); mt == "application/gzip" || mt == "application/x-gzip" {
		gzReader, err := gzip.NewReader(file)
		if err != nil {
			return nil, fmt.Errorf("Error gz-reading the file %s: %v", path, err)
		}
		defer gzReader.Close()
		reader = gzReader
	}

	s, err := getWordList(reader)
	return s, err
}

func getWordlistByURL(url string) ([]string, error) {
	page, err := amasshttp.RequestWebPage(url, nil, nil, "", "")
	if err != nil {
		return nil, fmt.Errorf("Failed to obtain the wordlist at %s: %v", url, err)
	}
	return getWordList(strings.NewReader(page))
}

func getWordlistByBox(path string) ([]string, error) {
	content, err := BoxOfDefaultFiles.FindString(path)
	if err != nil {
		return nil, fmt.Errorf("Failed to obtain the embedded wordlist: %s: %v", path, err)
	}
	return getWordList(strings.NewReader(content))
}

func getWordList(reader io.Reader) ([]string, error) {
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

func uniqueIntAppend(s []int, e string) []int {
	if a1, err := strconv.Atoi(e); err == nil {
		var found bool

		for _, a2 := range s {
			if a1 == a2 {
				found = true
				break
			}
		}
		if !found {
			s = append(s, a1)
		}
	}
	return s
}
