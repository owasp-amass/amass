// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package handlers

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/OWASP/Amass/amass/core"
)

// These strings represent the various Amass data operations.
const (
	OptDomain         = "domain"
	OptSubdomain      = "subdomain"
	OptCNAME          = "cname"
	OptA              = "a"
	OptAAAA           = "aaaa"
	OptPTR            = "ptr"
	OptSRV            = "service"
	OptNS             = "ns"
	OptMX             = "mx"
	OptInfrastructure = "infrastructure"
)

// Different data operations require different parameters to be provided:
// Domain: UUID, Timestamp, Type, Domain, Tag, and Source
// Subdomain: UUID, Timestamp, Type, Name, Domain, Tag and Source
// CNAME: UUID, Timestamp, Type, Name, Domain, TargetName, TargetDomain, Tag and Source
// A: UUID, Timestamp, Type, Name, Domain, Address, Tag and Source
// AAAA: UUID, Timestamp, Type, Name, Domain, Address, Tag and Source
// PTR: UUID, Timestamp, Type, Name, Domain, TargetName, Tag and Source
// SRV: UUID, Timestamp, Type, Name, Domain, Service, TargetName, Tag and Source
// NS: UUID, Timestamp, Type, Name, Domain, TargetName, TargetDomain, Tag and Source
// MX: UUID, Timestamp, Type, Name, Domain, TargetName, TargetDomain, Tag and Source
// Infrastructure: UUID, Timestamp, Type, Address, ASN, CIDR and Description

// DataOptsParams defines the parameters for Amass data operations.
type DataOptsParams struct {
	UUID         string `json:"uuid"`
	Timestamp    string `json:"timestamp"`
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

// DataHandler is the interface for storage of Amass data operations.
type DataHandler interface {
	fmt.Stringer

	// Inserts data operations into the graph.
	Insert(data *DataOptsParams) error

	// Sets a 'read' property on the vertex matching Name, Domain and UUID.
	MarkAsRead(data *DataOptsParams) error

	// Return true if the Name, Domain and UUID match a CNAME in the graph.
	IsCNAMENode(data *DataOptsParams) bool

	// Returns complete paths in the graph that have not yet been marked.
	GetUnreadOutput(uuid string) []*core.Output
}

// DataOptsDriver uses a slice of DataOptsParams to populate another Amass DataHandler.
func DataOptsDriver(data []DataOptsParams, handler DataHandler) error {
	var err error

	for _, opt := range data {
		if err = handler.Insert(&opt); err != nil {
			break
		}
	}
	return err
}

// ParseDataOpts decodes JSON entries provided via a Reader and returns a DataOptsParams slice.
func ParseDataOpts(r io.Reader) ([]DataOptsParams, error) {
	var data []DataOptsParams

	dec := json.NewDecoder(r)
	for {
		var opt DataOptsParams

		if err := dec.Decode(&opt); err == io.EOF {
			break
		} else if err != nil {
			return nil, err
		}

		data = append(data, opt)
	}
	return data, nil
}
