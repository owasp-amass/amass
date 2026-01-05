// Copyright © by Jeff Foley 2017-2025. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package gleif

import (
	"log/slog"

	et "github.com/owasp-amass/amass/v5/engine/types"
)

type gleif struct {
	name    string
	log     *slog.Logger
	fuzzy   *fuzzyCompletions
	related *relatedOrgs
	source  *et.Source
}

type fuzzyCompletions struct {
	name   string
	plugin *gleif
}

type relatedOrgs struct {
	name   string
	plugin *gleif
}
