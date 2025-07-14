// Copyright © by Jeff Foley 2017-2025. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"io"
	"os"

	"github.com/google/uuid"
	"github.com/owasp-amass/amass/v5/engine/api/graphql/client"
)

func engineIsRunning() bool {
	c := client.NewClient("http://127.0.0.1:4000/graphql")

	if _, err := c.SessionStats(uuid.New()); err != nil && err.Error() == "invalid session token" {
		return true
	}
	return false
}

func startEngine() error {
	p, err := os.Executable()
	if err != nil {
		return fmt.Errorf("failed to get executable path: %w", err)
	}
	if p == "" {
		return fmt.Errorf("executable path is empty")
	}

	cmd := initCmd(p)
	if cmd == nil {
		return fmt.Errorf("failed to initialize command for %s", p)
	}
	cmd.Stdout = io.Discard
	cmd.Stderr = io.Discard
	cmd.Stdin = os.Stdin

	cmd.Dir, err = os.Getwd()
	if err != nil {
		return err
	}

	return cmd.Start()
}
