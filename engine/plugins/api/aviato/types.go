// Copyright © by Jeff Foley 2017-2025. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package aviato

import (
	"log/slog"

	et "github.com/owasp-amass/amass/v4/engine/types"
	"golang.org/x/time/rate"
)

type aviato struct {
	name   string
	log    *slog.Logger
	rlimit *rate.Limiter
	source *et.Source
}
