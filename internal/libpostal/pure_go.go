//go:build !cgo

// Copyright © by Jeff Foley 2017-2025. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package libpostal

import (
	"context"
	"encoding/json"
	"os"
	"time"

	"github.com/owasp-amass/amass/v5/internal/net/http"
)

type parsed struct {
	Parts []ParsedComponent `json:"parts"`
}

type parseRequest struct {
	Address  string `json:"addr"`
	Language string `json:"lang"`
	Country  string `json:"country"`
}

var (
	postalHost           string
	postalPort           string
	parserDefaultOptions = getDefaultParserOptions()
)

func init() {
	postalHost = os.Getenv("POSTAL_SERVER_HOST")
	if postalHost == "" {
		postalHost = "0.0.0.0"
	}

	postalPort = os.Getenv("POSTAL_SERVER_PORT")
	if postalPort == "" {
		postalPort = "4001"
	}
}

func getDefaultParserOptions() ParserOptions {
	return ParserOptions{
		Language: "",
		Country:  "",
	}
}

func ParseAddress(address string) ([]ParsedComponent, error) {
	return ParseAddressOptions(address, parserDefaultOptions)
}

func ParseAddressOptions(address string, options ParserOptions) ([]ParsedComponent, error) {
	req := parseRequest{
		Address:  address,
		Language: options.Language,
		Country:  options.Country,
	}

	reqJSON, err := json.Marshal(req)
	if err != nil {
		return nil, err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	resp, err := http.RequestWebPage(ctx, &http.Request{
		Method: "POST",
		URL:    "http://" + postalHost + ":" + postalPort + "/parse",
		Body:   string(reqJSON),
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
