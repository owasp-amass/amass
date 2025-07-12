//go:build !cgo
// +build !cgo

// Copyright © by Jeff Foley 2017-2025. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package libpostal

import (
	"context"
	"encoding/json"
	"errors"
	"net/url"
	"os"

	"github.com/owasp-amass/amass/v5/internal/net/http"
)

type parsed struct {
	Parts []ParsedComponent `json:"parts"`
}

var postalHost, postalPort string

func init() {
	postalHost = os.Getenv("POSTAL_SERVER_HOST")
	postalPort = os.Getenv("POSTAL_SERVER_PORT")
}

func ParseAddress(address string) ([]ParsedComponent, error) {
	if postalHost == "" || postalPort == "" {
		return nil, errors.New(ErrPostalLibNotAvailable)
	}

	resp, err := http.RequestWebPage(context.TODO(), &http.Request{
		URL: "http://" + postalHost + ":" + postalPort + "/parse?address=" + url.QueryEscape(address),
	})
	if err != nil {
		return nil, err
	}

	var p parsed
	if err := json.Unmarshal([]byte("{\"parts\":"+resp.Body+"}"), &p); err != nil {
		return nil, err
	}
	return p.Parts, nil
}

/*
func expandAddress(address string) (string, error) {
	if postalHost == "" || postalPort == "" {
		return "", errors.New("no postal server information provided")
	}

	resp, err := http.RequestWebPage(context.TODO(), &http.Request{
		URL: "http://" + postalHost + ":" + postalPort + "/expand?address=" + url.QueryEscape(address),
	})
	if err != nil {
		return "", err
	}

	type expanded struct {
		Forms []string `json:"forms"`
	}

	var ex expanded
	if err := json.Unmarshal([]byte("{\"forms\":"+resp.Body+"}"), &ex); err != nil {
		return "", err
	}

	num := len(ex.Forms)
	if num == 0 {
		return "", errors.New("the libpostal expansion returned zero normalized strings")
	}
	return ex.Forms[num-1], nil
}
*/
