// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package amass

import "net"

// DNSAnswer is the type used by Amass to represent a DNS record.
type DNSAnswer struct {
	Name string `json:"name"`
	Type int    `json:"type"`
	TTL  int    `json:"TTL"`
	Data string `json:"data"`
}

// Request contains data obtained throughout Service processing
type Request struct {
	Name    string
	Domain  string
	Address string
	Records []DNSAnswer
	Tag     string
	Source  string
}

// Output contains all the output data for an enumerated DNS name.
type Output struct {
	Name      string
	Domain    string
	Addresses []AddressInfo
	Tag       string
	Source    string
}

// AddressInfo stores all network addressing info for the Output type.
type AddressInfo struct {
	Address     net.IP
	Netblock    *net.IPNet
	ASN         int
	Description string
}
