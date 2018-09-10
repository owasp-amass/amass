// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package handlers

import (
	"net"
)

const (
	OptDomain         = "domain"
	OptCNAME          = "cname"
	OptA              = "a"
	OptAAAA           = "aaaa"
	OptPTR            = "ptr"
	OptSRV            = "service"
	OptNS             = "ns"
	OptMX             = "mx"
	OptInfrastructure = "infrastructure"
)

type DataHandler interface {
	InsertDomain(domain, tag, source string) error

	InsertCNAME(name, domain, target, tdomain, tag, source string) error

	InsertA(name, domain, addr, tag, source string) error

	InsertAAAA(name, domain, addr, tag, source string) error

	InsertPTR(name, domain, target, tag, source string) error

	InsertSRV(name, domain, service, target, tag, source string) error

	InsertNS(name, domain, target, tdomain, tag, source string) error

	InsertMX(name, domain, target, tdomain, tag, source string) error

	InsertInfrastructure(addr string, asn int, cidr *net.IPNet, desc string) error
}

type JSONFileFormat struct {
	Type         string `json:"type"`
	Name         string `json:"name"`
	Domain       string `json:"domain"`
	Service      string `json:"service"`
	TargetName   string `json:"target_name"`
	TargetDomain string `json:"target_domain"`
	Address      string `json:"addr"`
	ASN          int    `json:"asn"`
	CIDR         string `json:"cidr"`
	Description  string `json:"desc"`
	Tag          string `json:"tag"`
	Source       string `json:"source"`
}
