// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

// Command amass-ai-mcp is a dedicated stdio MCP entry point. It must never
// print banners or status messages to stdout (reserved for JSON-RPC).
package main

import (
	"fmt"
	"os"

	"github.com/owasp-amass/amass/v5/internal/ai/cli"
)

func main() {
	args := append(append([]string(nil), os.Args[1:]...), "mcp")
	if err := cli.Run(os.Stdin, os.Stdout, os.Stderr, args); err != nil {
		fmt.Fprintln(os.Stderr, "amass-ai-mcp:", err)
		os.Exit(1)
	}
}
