// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package core

type DNSAnswer struct {
	Name string `json:"name"`
	Type int    `json:"type"`
	TTL  int    `json:"TTL"`
	Data string `json:"data"`
}

// AmassRequest - Contains data obtained throughout AmassService processing
type AmassRequest struct {
	Name    string
	Domain  string
	Records []DNSAnswer
	Tag     string
	Source  string
}
