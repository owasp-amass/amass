// Copyright © by Jeff Foley 2017-2025. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package tools

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/owasp-amass/amass/v4/config"
	"github.com/owasp-amass/amass/v4/resources"
)

func CreateOutputDirectory(dirpath string) error {
	// Prepare output file paths
	dir := config.OutputDirectory(dirpath)
	if dir == "" {
		return errors.New("failed to obtain the path for the output directory")
	}
	// If the directory does not yet exist, create it
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("mkdir failed for %s: %v", dir, err)
	}
	return nil
}

func CreateDefaultConfigFiles(dirpath string) error {
	for _, filename := range resources.DefaultFilesList {
		filepath := filepath.Join(dirpath, filename)
		if _, err := os.Stat(filepath); !os.IsNotExist(err) {
			// If the file already exists, skip creating it
			continue
		}

		file, err := resources.GetResourceFile(filename)
		if err != nil {
			return fmt.Errorf("failed to obtain the embedded file %s: %v", filename, err)
		}
		defer func() { _ = file.Close() }()

		// Create the default config file in the specified directory
		outFile, err := os.Create(filepath)
		if err != nil {
			return fmt.Errorf("failed to create the output file %s: %v", filepath, err)
		}
		defer func() { _ = outFile.Close() }()

		if _, err := io.Copy(outFile, file); err != nil {
			return fmt.Errorf("failed to copy the file %s: %v", filepath, err)
		}
	}
	return nil
}
