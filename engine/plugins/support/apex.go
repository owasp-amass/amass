// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package support

import (
	"strings"

	et "github.com/owasp-amass/amass/v5/engine/types"
	oam "github.com/owasp-amass/open-asset-model"
	oamdns "github.com/owasp-amass/open-asset-model/dns"
	"golang.org/x/net/publicsuffix"
)

// InScopeApexToCheck returns the registered domain an FQDN event names, when
// it is a registered domain in the session's scope that src has not checked
// within the TTL from FQDN to toType, and marks it checked. It returns ""
// for any other event.
func InScopeApexToCheck(e *et.Event, toType oam.AssetType, src *et.Source, plugin string) (string, error) {
	fqdn, ok := e.Entity.Asset.(*oamdns.FQDN)
	if !ok {
		return "", nil
	}
	apex := strings.ToLower(fqdn.Name)
	if dom, err := publicsuffix.EffectiveTLDPlusOne(apex); err != nil || dom != apex {
		return "", nil
	}
	if _, conf := e.Session.Scope().IsAssetInScope(fqdn, 0); conf == 0 {
		return "", nil
	}

	since, err := TTLStartTime(e.Session.Config(), string(oam.FQDN), string(toType), plugin)
	if err != nil {
		return "", err
	}
	if AssetMonitoredWithinTTL(e.Session, e.Entity, src, since) {
		return "", nil
	}
	MarkAssetMonitored(e.Session, e.Entity, src)
	return apex, nil
}
