// Copyright © by Jeff Foley 2017-2025. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package tools

import (
	"errors"
	"fmt"
	"os"

	"github.com/owasp-amass/amass/v4/config"
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
