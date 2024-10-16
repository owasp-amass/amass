// Copyright © by Jeff Foley 2017-2024. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"path"
	"time"

	amasshttp "github.com/owasp-amass/amass/v4/utils/net/http"
)

func main() {
	var hostname string
	var help1, help2 bool

	if len(os.Args) < 2 {
		fmt.Fprintf(os.Stderr, "Usage: %s %s\n\n", path.Base(os.Args[0]), "--host HOSTNAME [-h | -help]")
		return
	}

	flag.BoolVar(&help1, "h", false, "Show the program usage message")
	flag.BoolVar(&help2, "help", false, "Show the program usage message")
	flag.StringVar(&hostname, "host", "", "Hostname or IP address of the Amass Engine")
	//flag.BoolVar(&version, "version", false, "Print the version number of this Amass binary")
	flag.Parse()

	if (help1 || help2) || hostname == "" {
		fmt.Fprintf(os.Stderr, "Usage: %s %s\n\n", path.Base(os.Args[0]), "--host HOSTNAME")
		flag.PrintDefaults()
		return
	}
	/*if version {
		fmt.Fprintf(color.Error, "%s\n", format.Version)
		return
	}*/

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	u := "http://" + hostname + ":4000/graphql"
	if _, err := amasshttp.RequestWebPage(ctx, &amasshttp.Request{URL: u}); err != nil {
		// a failure to respond indicates that the server is not yet available
		os.Exit(1)
	}
}
