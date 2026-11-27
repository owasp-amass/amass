// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/owasp-amass/amass/v5/internal/ai"
	"github.com/owasp-amass/amass/v5/internal/ai/llm"
	"github.com/owasp-amass/amass/v5/internal/confighelp"
)

// configAssist asks the model for a configuration that meets request, shows it
// with a credential-masked diff, and writes it to configPath once the user
// approves — at an interactive prompt, or ahead of time with approve. The
// configuration it writes is the one it showed, in the same run.
func configAssist(ctx context.Context, in io.Reader, out, errout io.Writer, model llm.Model,
	configPath, request string, approve bool) error {
	var current string
	if configPath != "" {
		if raw, err := os.ReadFile(configPath); err == nil {
			current = string(raw)
		}
	}

	edit, err := ai.SuggestConfig(ctx, model, current, request)
	if err != nil {
		return err
	}

	_, _ = fmt.Fprintf(out, "Summary: %s\n", edit.Summary)
	if edit.Rationale != "" {
		_, _ = fmt.Fprintf(out, "\n%s\n", edit.Rationale)
	}

	_, _ = fmt.Fprintf(out, "\nProposed configuration:\n%s\n", edit.Content)
	safeCurrent, _ := confighelp.RedactSecrets(current)
	safeProposed, _ := confighelp.RedactSecrets(edit.Content)
	if diff := confighelp.Diff(safeCurrent, safeProposed); diff != "" {
		_, _ = fmt.Fprintf(out, "\nChanges (credentials masked):\n%s\n", diff)
	}

	if configPath == "" {
		_, _ = fmt.Fprintln(out, "\nNo -config file was given, so there is nothing to write.")
		return nil
	}

	apply := approve
	if !apply && isInteractive(in) {
		_, _ = fmt.Fprintf(errout, "\nWrite this configuration to %s? [y/N] ", configPath)
		apply = confirmed(in)
	}
	if !apply {
		_, _ = fmt.Fprintf(out, "\nNothing was written. Re-run with -approve-config to write it to %s.\n", configPath)
		return nil
	}

	if err := edit.Apply(configPath); err != nil {
		return err
	}

	_, _ = fmt.Fprintf(out, "\nWrote %s. The new configuration applies to the next enumeration.\n", configPath)
	return nil
}

// isInteractive reports whether in is a terminal, so a prompt would reach a
// person. A pipe or file is not interactive.
func isInteractive(in io.Reader) bool {
	f, ok := in.(*os.File)
	if !ok {
		return false
	}

	info, err := f.Stat()
	return err == nil && info.Mode()&os.ModeCharDevice != 0
}

// confirmed reads one line from in and reports whether it is a yes.
func confirmed(in io.Reader) bool {
	s := bufio.NewScanner(in)
	if !s.Scan() {
		return false
	}

	switch strings.ToLower(strings.TrimSpace(s.Text())) {
	case "y", "yes":
		return true
	}

	return false
}
