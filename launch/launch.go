// Copyright © by Jeff Foley 2024. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package launch

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/owasp-amass/amass/v4/resources"
	"github.com/owasp-amass/config/config"
)

func LaunchEngine() error {
	name := "amass_engine"
	dir := createOutputDirectory()
	if dir == "" {
		return errors.New("failed to find the output directory")
	}

	data, err := resources.GetResourceFileData(name)
	if err != nil {
		return err
	}

	enginepath := filepath.Join(dir, name)
	f, err := os.OpenFile(enginepath, os.O_TRUNC|os.O_RDWR|os.O_CREATE, 0755)
	if err != nil {
		return err
	}

	_, err = f.Write(data)
	f.Close()
	if err != nil {
		return err
	}

	cmd := exec.Command(enginepath)
	cmd.Dir = dir
	return cmd.Start()
}

func createOutputDirectory() string {
	// Prepare output file paths
	dir := config.OutputDirectory("")
	if dir == "" {
		return ""
	}
	// If the directory does not yet exist, create it
	if err := os.MkdirAll(dir, 0755); err != nil {
		return ""
	}
	return dir
}
