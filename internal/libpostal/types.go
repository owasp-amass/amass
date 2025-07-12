// Copyright © by Jeff Foley 2017-2025. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package libpostal

const ErrPostalLibNotAvailable = "libpostal is not available"

type ParserOptions struct {
	Language string
	Country  string
}

type ParsedComponent struct {
	Label string `json:"label"`
	Value string `json:"value"`
}

func getDefaultParserOptions() ParserOptions {
	return ParserOptions{
		Language: "",
		Country:  "",
	}
}
