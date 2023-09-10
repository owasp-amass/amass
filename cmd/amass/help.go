// Copyright © by Jeff Foley 2017-2023. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"flag"
)

func runHelpCommand(clArgs []string) {
	help := []string{"-help"}
	helpBuf := new(bytes.Buffer)
	helpCommand := flag.NewFlagSet("help", flag.ContinueOnError)
	helpCommand.SetOutput(helpBuf)
	if len(clArgs) < 1 {
		commandUsage(mainUsageMsg, helpCommand, helpBuf)
		return
	}
	switch clArgs[0] {
	case "enum":
		runEnumCommand(help)
	case "intel":
		runIntelCommand(help)
	default:
		commandUsage(mainUsageMsg, helpCommand, helpBuf)
		return
	}
}
