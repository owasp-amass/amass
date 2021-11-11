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
	case "db":
		runDBCommand(help)
	case "dns":
		runDNSCommand(help)
	case "enum":
		runEnumCommand(help)
	case "intel":
		runIntelCommand(help)
	case "track":
		runTrackCommand(help)
	case "viz":
		runVizCommand(help)
	default:
		commandUsage(mainUsageMsg, helpCommand, helpBuf)
		return
	}
}
