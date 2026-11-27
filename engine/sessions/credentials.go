// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package sessions

import (
	"os"
	"strings"

	"github.com/owasp-amass/amass/v5/internal/secrets"
)

// fillCredentials gives the data sources the session's configuration has
// no credentials for those in the engine's environment and, when the engine
// has the secrets key, those stored encrypted in the session's database,
// so engines on one database share the keys set once.
func (s *Session) fillCredentials() {
	key, err := secrets.LoadKey(os.LookupEnv)
	if err != nil {
		s.log.Warn("secrets: " + err.Error())
	}
	filled, err := secrets.Fill(s.cfg, secrets.Open(s.db, key), os.Environ())
	if err != nil {
		s.log.Warn("secrets: " + err.Error())
		return
	}
	if len(filled) > 0 {
		s.log.Info("data source credentials from the environment and the shared store",
			"sources", strings.Join(filled, ", "))
	}
}
