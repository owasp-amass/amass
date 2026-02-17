// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package client

import (
	"encoding/json"
	"errors"
	"io"

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

func decodeAssetsForScopeEndpoint(atype oam.AssetType, data io.ReadCloser) ([]oam.Asset, error) {
	var results []oam.Asset

	switch atype {
	case oam.Account:
		var scope struct {
			Data []oamacct.Account `json:"data"`
		}
		if err := json.NewDecoder(data).Decode(&scope); err != nil {
			return nil, err
		}
		for _, a := range scope.Data {
			results = append(results, &a)
		}
	case oam.AutnumRecord:
		var scope struct {
			Data []oamreg.AutnumRecord `json:"data"`
		}
		if err := json.NewDecoder(data).Decode(&scope); err != nil {
			return nil, err
		}
		for _, a := range scope.Data {
			results = append(results, &a)
		}
	case oam.AutonomousSystem:
		var scope struct {
			Data []oamnet.AutonomousSystem `json:"data"`
		}
		if err := json.NewDecoder(data).Decode(&scope); err != nil {
			return nil, err
		}
		for _, a := range scope.Data {
			results = append(results, &a)
		}
	case oam.ContactRecord:
		var scope struct {
			Data []oamcon.ContactRecord `json:"data"`
		}
		if err := json.NewDecoder(data).Decode(&scope); err != nil {
			return nil, err
		}
		for _, a := range scope.Data {
			results = append(results, &a)
		}
	case oam.DomainRecord:
		var scope struct {
			Data []oamreg.DomainRecord `json:"data"`
		}
		if err := json.NewDecoder(data).Decode(&scope); err != nil {
			return nil, err
		}
		for _, a := range scope.Data {
			results = append(results, &a)
		}
	case oam.File:
		var scope struct {
			Data []oamfile.File `json:"data"`
		}
		if err := json.NewDecoder(data).Decode(&scope); err != nil {
			return nil, err
		}
		for _, a := range scope.Data {
			results = append(results, &a)
		}
	case oam.FQDN:
		var scope struct {
			Data []oamdns.FQDN `json:"data"`
		}
		if err := json.NewDecoder(data).Decode(&scope); err != nil {
			return nil, err
		}
		for _, a := range scope.Data {
			results = append(results, &a)
		}
	case oam.FundsTransfer:
		var scope struct {
			Data []oamfin.FundsTransfer `json:"data"`
		}
		if err := json.NewDecoder(data).Decode(&scope); err != nil {
			return nil, err
		}
		for _, a := range scope.Data {
			results = append(results, &a)
		}
	case oam.Identifier:
		var scope struct {
			Data []oamgen.Identifier `json:"data"`
		}
		if err := json.NewDecoder(data).Decode(&scope); err != nil {
			return nil, err
		}
		for _, a := range scope.Data {
			results = append(results, &a)
		}
	case oam.IPAddress:
		var scope struct {
			Data []oamnet.IPAddress `json:"data"`
		}
		if err := json.NewDecoder(data).Decode(&scope); err != nil {
			return nil, err
		}
		for _, a := range scope.Data {
			results = append(results, &a)
		}
	case oam.IPNetRecord:
		var scope struct {
			Data []oamreg.IPNetRecord `json:"data"`
		}
		if err := json.NewDecoder(data).Decode(&scope); err != nil {
			return nil, err
		}
		for _, a := range scope.Data {
			results = append(results, &a)
		}
	case oam.Location:
		var scope struct {
			Data []oamcon.Location `json:"data"`
		}
		if err := json.NewDecoder(data).Decode(&scope); err != nil {
			return nil, err
		}
		for _, a := range scope.Data {
			results = append(results, &a)
		}
	case oam.Netblock:
		var scope struct {
			Data []oamnet.Netblock `json:"data"`
		}
		if err := json.NewDecoder(data).Decode(&scope); err != nil {
			return nil, err
		}
		for _, a := range scope.Data {
			results = append(results, &a)
		}
	case oam.Organization:
		var scope struct {
			Data []oamorg.Organization `json:"data"`
		}
		if err := json.NewDecoder(data).Decode(&scope); err != nil {
			return nil, err
		}
		for _, a := range scope.Data {
			results = append(results, &a)
		}
	case oam.Phone:
		var scope struct {
			Data []oamcon.Phone `json:"data"`
		}
		if err := json.NewDecoder(data).Decode(&scope); err != nil {
			return nil, err
		}
		for _, a := range scope.Data {
			results = append(results, &a)
		}
	case oam.Person:
		var scope struct {
			Data []oampeop.Person `json:"data"`
		}
		if err := json.NewDecoder(data).Decode(&scope); err != nil {
			return nil, err
		}
		for _, a := range scope.Data {
			results = append(results, &a)
		}
	case oam.Product:
		var scope struct {
			Data []oamplat.Product `json:"data"`
		}
		if err := json.NewDecoder(data).Decode(&scope); err != nil {
			return nil, err
		}
		for _, a := range scope.Data {
			results = append(results, &a)
		}
	case oam.ProductRelease:
		var scope struct {
			Data []oamplat.ProductRelease `json:"data"`
		}
		if err := json.NewDecoder(data).Decode(&scope); err != nil {
			return nil, err
		}
		for _, a := range scope.Data {
			results = append(results, &a)
		}
	case oam.Service:
		var scope struct {
			Data []oamplat.Service `json:"data"`
		}
		if err := json.NewDecoder(data).Decode(&scope); err != nil {
			return nil, err
		}
		for _, a := range scope.Data {
			results = append(results, &a)
		}
	case oam.TLSCertificate:
		var scope struct {
			Data []oamcert.TLSCertificate `json:"data"`
		}
		if err := json.NewDecoder(data).Decode(&scope); err != nil {
			return nil, err
		}
		for _, a := range scope.Data {
			results = append(results, &a)
		}
	case oam.URL:
		var scope struct {
			Data []oamurl.URL `json:"data"`
		}
		if err := json.NewDecoder(data).Decode(&scope); err != nil {
			return nil, err
		}
		for _, a := range scope.Data {
			results = append(results, &a)
		}
	}

	if len(results) == 0 {
		return nil, errors.New("zero decoded assets")
	}
	return results, nil
}
