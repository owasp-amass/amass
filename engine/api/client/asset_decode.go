// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package client

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"

	oam "github.com/owasp-amass/open-asset-model"
	oamacct "github.com/owasp-amass/open-asset-model/account"
	oamcert "github.com/owasp-amass/open-asset-model/certificate"
	oamcon "github.com/owasp-amass/open-asset-model/contact"
	oamdns "github.com/owasp-amass/open-asset-model/dns"
	oamfile "github.com/owasp-amass/open-asset-model/file"
	oamfin "github.com/owasp-amass/open-asset-model/financial"
	oamgen "github.com/owasp-amass/open-asset-model/general"
	oamnet "github.com/owasp-amass/open-asset-model/network"
	oamorg "github.com/owasp-amass/open-asset-model/org"
	oampeop "github.com/owasp-amass/open-asset-model/people"
	oamplat "github.com/owasp-amass/open-asset-model/platform"
	oamreg "github.com/owasp-amass/open-asset-model/registration"
	oamurl "github.com/owasp-amass/open-asset-model/url"
)

// NewAsset returns a new, empty asset of the type, ready to be decoded into,
// or ok=false for a type the Open Asset Model does not define.
func NewAsset(atype oam.AssetType) (oam.Asset, bool) {
	switch atype {
	case oam.Account:
		return &oamacct.Account{}, true
	case oam.AutnumRecord:
		return &oamreg.AutnumRecord{}, true
	case oam.AutonomousSystem:
		return &oamnet.AutonomousSystem{}, true
	case oam.ContactRecord:
		return &oamcon.ContactRecord{}, true
	case oam.DomainRecord:
		return &oamreg.DomainRecord{}, true
	case oam.File:
		return &oamfile.File{}, true
	case oam.FQDN:
		return &oamdns.FQDN{}, true
	case oam.FundsTransfer:
		return &oamfin.FundsTransfer{}, true
	case oam.GeoLocation:
		return &oamcon.GeoLocation{}, true
	case oam.Identifier:
		return &oamgen.Identifier{}, true
	case oam.IPAddress:
		return &oamnet.IPAddress{}, true
	case oam.IPNetRecord:
		return &oamreg.IPNetRecord{}, true
	case oam.Netblock:
		return &oamnet.Netblock{}, true
	case oam.Organization:
		return &oamorg.Organization{}, true
	case oam.Person:
		return &oampeop.Person{}, true
	case oam.Phone:
		return &oamcon.Phone{}, true
	case oam.Product:
		return &oamplat.Product{}, true
	case oam.ProductRelease:
		return &oamplat.ProductRelease{}, true
	case oam.Service:
		return &oamplat.Service{}, true
	case oam.StorageBucket:
		return &oamplat.StorageBucket{}, true
	case oam.StreetAddress:
		return &oamcon.StreetAddress{}, true
	case oam.TLSCertificate:
		return &oamcert.TLSCertificate{}, true
	case oam.URL:
		return &oamurl.URL{}, true
	}
	return nil, false
}

// ParseAsset decodes one asset of the type named by atype, compared without
// regard to case, from its JSON.
func ParseAsset(atype string, raw json.RawMessage) (oam.Asset, error) {
	for _, t := range oam.AssetList {
		if strings.EqualFold(atype, string(t)) {
			a, _ := NewAsset(t)
			if err := json.Unmarshal(raw, a); err != nil {
				return nil, err
			}
			return a, nil
		}
	}
	return nil, fmt.Errorf("unknown asset type: %s", atype)
}

// DecodeAssetsForScopeEndpoint decodes the assets of one type that the scope
// endpoint returns, {"data": [...]}.
func DecodeAssetsForScopeEndpoint(atype oam.AssetType, data io.ReadCloser) ([]oam.Asset, error) {
	var scope struct {
		Data []json.RawMessage `json:"data"`
	}
	if err := json.NewDecoder(data).Decode(&scope); err != nil {
		return nil, err
	}

	var results []oam.Asset
	for _, raw := range scope.Data {
		a, err := ParseAsset(string(atype), raw)
		if err != nil {
			return nil, err
		}
		results = append(results, a)
	}
	if len(results) == 0 {
		return nil, errors.New("zero decoded assets")
	}
	return results, nil
}
