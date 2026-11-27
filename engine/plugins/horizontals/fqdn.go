// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package horizontals

import (
	"errors"

	et "github.com/owasp-amass/amass/v5/engine/types"
	oamdns "github.com/owasp-amass/open-asset-model/dns"
)

type horfqdn struct {
	name   string
	plugin *horizPlugin
}

func (h *horfqdn) Name() string {
	return h.name
}

func (h *horfqdn) check(e *et.Event) error {
	fqdn, ok := e.Entity.Asset.(*oamdns.FQDN)
	if !ok {
		return errors.New("failed to extract the FQDN asset")
	}

	// the expansion policy may admit nothing at all
	if !e.Session.Config().Widens() {
		return nil
	}

	if _, conf := e.Session.Scope().IsAssetInScope(fqdn, 0); conf > 0 {
		return nil
	}

	h.plugin.admitAssociated(e)
	return nil
}
