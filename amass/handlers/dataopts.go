// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package handlers

import (
	"encoding/json"
	"io"
	"net"
)

type DataOptsHandler struct {
	Enc *json.Encoder
}

func NewDataOptsHandler(w io.Writer) *DataOptsHandler {
	return &DataOptsHandler{Enc: json.NewEncoder(w)}
}

func (d *DataOptsHandler) String() string {
	return "Data Operations Storage Handler"
}

func DataOptsDriver(data []JSONFileFormat, handler DataHandler) error {
	var err error

	for _, opt := range data {
		var err error
		var ipnet *net.IPNet

		switch opt.Type {
		case OptDomain:
			err = handler.InsertDomain(opt.Domain, opt.Tag, opt.Source)
		case OptCNAME:
			err = handler.InsertCNAME(opt.Name, opt.Domain, opt.TargetName, opt.TargetDomain, opt.Tag, opt.Source)
		case OptA:
			err = handler.InsertA(opt.Name, opt.Domain, opt.Address, opt.Tag, opt.Source)
		case OptAAAA:
			err = handler.InsertAAAA(opt.Name, opt.Domain, opt.Address, opt.Tag, opt.Source)
		case OptPTR:
			err = handler.InsertPTR(opt.Name, opt.Domain, opt.TargetName, opt.Tag, opt.Source)
		case OptSRV:
			err = handler.InsertSRV(opt.Name, opt.Domain, opt.Service, opt.TargetName, opt.Tag, opt.Source)
		case OptNS:
			err = handler.InsertNS(opt.Name, opt.Domain, opt.TargetName, opt.TargetDomain, opt.Tag, opt.Source)
		case OptMX:
			err = handler.InsertMX(opt.Name, opt.Domain, opt.TargetName, opt.TargetDomain, opt.Tag, opt.Source)
		case OptInfrastructure:
			if _, ipnet, err = net.ParseCIDR(opt.CIDR); err == nil {
				err = handler.InsertInfrastructure(opt.Address, opt.ASN, ipnet, opt.Description)
			}
		}
		if err != nil {
			break
		}
	}
	return err
}

func ParseDataOpts(r io.Reader) ([]JSONFileFormat, error) {
	var data []JSONFileFormat

	dec := json.NewDecoder(r)
	for {
		var opt JSONFileFormat

		if err := dec.Decode(&opt); err == io.EOF {
			break
		} else if err != nil {
			return nil, err
		}

		data = append(data, opt)
	}
	return data, nil
}

func (d *DataOptsHandler) InsertDomain(domain, tag, source string) error {
	return d.Enc.Encode(&JSONFileFormat{
		Type:   OptDomain,
		Domain: domain,
		Tag:    tag,
		Source: source,
	})
}

func (d *DataOptsHandler) InsertCNAME(name, domain, target, tdomain, tag, source string) error {
	return d.Enc.Encode(&JSONFileFormat{
		Type:         OptCNAME,
		Name:         name,
		Domain:       domain,
		TargetName:   target,
		TargetDomain: tdomain,
		Tag:          tag,
		Source:       source,
	})
}

func (d *DataOptsHandler) InsertA(name, domain, addr, tag, source string) error {
	return d.Enc.Encode(&JSONFileFormat{
		Type:    OptA,
		Name:    name,
		Domain:  domain,
		Address: addr,
		Tag:     tag,
		Source:  source,
	})
}

func (d *DataOptsHandler) InsertAAAA(name, domain, addr, tag, source string) error {
	return d.Enc.Encode(&JSONFileFormat{
		Type:    OptAAAA,
		Name:    name,
		Domain:  domain,
		Address: addr,
		Tag:     tag,
		Source:  source,
	})
}

func (d *DataOptsHandler) InsertPTR(name, domain, target, tag, source string) error {
	return d.Enc.Encode(&JSONFileFormat{
		Type:       OptPTR,
		Name:       name,
		Domain:     domain,
		TargetName: target,
		Tag:        tag,
		Source:     source,
	})
}

func (d *DataOptsHandler) InsertSRV(name, domain, service, target, tag, source string) error {
	return d.Enc.Encode(&JSONFileFormat{
		Type:       OptSRV,
		Name:       name,
		Domain:     domain,
		Service:    service,
		TargetName: target,
		Tag:        tag,
		Source:     source,
	})
}

func (d *DataOptsHandler) InsertNS(name, domain, target, tdomain, tag, source string) error {
	return d.Enc.Encode(&JSONFileFormat{
		Type:         OptNS,
		Name:         name,
		Domain:       domain,
		TargetName:   target,
		TargetDomain: tdomain,
		Tag:          tag,
		Source:       source,
	})
}

func (d *DataOptsHandler) InsertMX(name, domain, target, tdomain, tag, source string) error {
	return d.Enc.Encode(&JSONFileFormat{
		Type:         OptMX,
		Name:         name,
		Domain:       domain,
		TargetName:   target,
		TargetDomain: tdomain,
		Tag:          tag,
		Source:       source,
	})
}

func (d *DataOptsHandler) InsertInfrastructure(addr string, asn int, cidr *net.IPNet, desc string) error {
	return d.Enc.Encode(&JSONFileFormat{
		Type:        OptInfrastructure,
		Address:     addr,
		ASN:         asn,
		CIDR:        cidr.String(),
		Description: desc,
	})
}
