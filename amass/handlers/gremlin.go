// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package handlers

import (
	"log"
	"strconv"

	"github.com/qasaur/gremgo"
)

// Gremlin is the client object for a Gremlin/TinkerPop graph database connection.
type Gremlin struct {
	client gremgo.Client
}

// NewGremlin returns a client object that implements the Amass DataHandler interface.
// The url param typically looks like the following: localhost:8182
func NewGremlin(url, username, password string, l *log.Logger) (*Gremlin, error) {
	errs := make(chan error)
	go func(e chan error) {
		err := <-e
		l.Println("Gremlin: Lost connection to the database: " + err.Error())
	}(errs)

	var err error
	var grem gremgo.Client
	var config gremgo.DialerConfig
	if username != "" && password != "" {
		config = gremgo.SetAuthentication(username, password)
	}

	dialer := gremgo.NewDialer("ws://"+url, config)
	grem, err = gremgo.Dial(dialer, errs)
	if err != nil {
		return nil, err
	}
	return &Gremlin{client: grem}, nil
}

// Close cleans up the Gremlin client object.
func (g *Gremlin) Close() {
	g.client.Close()
}

// String returns a description for the Gremlin client object.
func (g *Gremlin) String() string {
	return "Gremlin TinkerPop Handler"
}

// Insert implements the Amass DataHandler interface.
func (g *Gremlin) Insert(data *DataOptsParams) error {
	var err error

	switch data.Type {
	case OptDomain:
		err = g.insertDomain(data)
	case OptCNAME:
		err = g.insertCNAME(data)
	case OptA:
		err = g.insertA(data)
	case OptAAAA:
		err = g.insertAAAA(data)
	case OptPTR:
		err = g.insertPTR(data)
	case OptSRV:
		err = g.insertSRV(data)
	case OptNS:
		err = g.insertNS(data)
	case OptMX:
		err = g.insertMX(data)
	case OptInfrastructure:
		err = g.insertInfrastructure(data)
	}
	return err
}

func (g *Gremlin) insertDomain(data *DataOptsParams) error {
	bindings := map[string]string{
		"uuid":      data.UUID,
		"timestamp": data.Timestamp,
		"domain":    data.Domain,
		"tag":       data.Tag,
		"source":    data.Source,
	}

	_, err := g.client.Execute(
		"g.V().hasLabel('domain').has('name', domain).has('enum', uuid).fold()."+
			"coalesce(unfold(),addV('domain').property('enum', uuid)."+
			"property('timestamp', timestamp).property('name', domain)."+
			"property('tag', tag).property('source', source)",
		bindings,
		map[string]string{},
	)
	return err
}

func (g *Gremlin) insertSubdomain(data *DataOptsParams) error {
	return g.insertSub("subdomain", data)
}

func (g *Gremlin) insertSub(label string, data *DataOptsParams) error {
	bindings := map[string]string{
		"label":     label,
		"uuid":      data.UUID,
		"timestamp": data.Timestamp,
		"name":      data.Name,
		"domain":    data.Domain,
		"tag":       data.Tag,
		"source":    data.Source,
	}

	err := g.insertDomain(data)
	if err != nil {
		return err
	}

	if data.Name != data.Domain {
		_, err = g.client.Execute(
			"g.V().hasLabel(label).has('name', name).has('enum', uuid).fold()."+
				"coalesce(unfold(),g.addV(label).property('name', name).property('enum', uuid)."+
				"property('timestamp', timestamp).property('tag', tag).property('source', source))",
			bindings,
			map[string]string{},
		)
		if err != nil {
			return err
		}

		_, err = g.client.Execute(
			"d = g.V().hasLabel('domain').has('name', domain).has('enum', uuid).next() "+
				"s = g.V().hasLabel(label).has('name', name).has('enum', uuid).next() "+
				"g.V(d).out('root_of').hasLabel(label).has('name', name).has('enum', uuid).fold()."+
				"coalesce(unfold(), d.addE('root_of').to(s))",
			bindings,
			map[string]string{},
		)
		if err != nil {
			return err
		}
	}
	return nil
}

func (g *Gremlin) insertCNAME(data *DataOptsParams) error {
	bindings := map[string]string{
		"uuid":      data.UUID,
		"timestamp": data.Timestamp,
		"sname":     data.Name,
		"sdomain":   data.Domain,
		"tname":     data.TargetName,
		"tdomain":   data.TargetDomain,
		"tag":       data.Tag,
		"source":    data.Source,
	}

	if err := g.insertSubdomain(data); err != nil {
		return err
	}

	err := g.insertSubdomain(&DataOptsParams{
		UUID:      data.UUID,
		Timestamp: data.Timestamp,
		Name:      data.TargetName,
		Domain:    data.TargetDomain,
		Tag:       data.Tag,
		Source:    data.Source,
	})
	if err != nil {
		return err
	}

	_, err = g.client.Execute(
		"s = g.V().hasLabel('subdomain').has('name', sname).has('enum', uuid).next() "+
			"t = g.V().hasLabel('domain','subdomain').has('name', tname).has('enum', uuid).next() "+
			"g.V(s).out('cname_to').hasLabel('domain','subdomain').has('name', tname).has('enum', uuid).fold()."+
			"coalesce(unfold(), s.addE('cname_to').to(t))",
		bindings,
		map[string]string{},
	)
	return err
}

func (g *Gremlin) insertA(data *DataOptsParams) error {
	bindings := map[string]string{
		"uuid":      data.UUID,
		"timestamp": data.Timestamp,
		"name":      data.Name,
		"domain":    data.Domain,
		"addr":      data.Address,
		"type":      "IPv4",
		"tag":       data.Tag,
		"source":    data.Source,
	}

	if err := g.insertSubdomain(data); err != nil {
		return err
	}

	_, err := g.client.Execute(
		"g.V().hasLabel('address').has('addr', addr).has('type', type).has('enum', uuid).fold()."+
			"coalesce(unfold(),addV('address').property('addr', addr).property('type', type).property('enum', uuid)."+
			"property('timestamp', timestamp).property('tag', tag).property('source', source))",
		bindings,
		map[string]string{},
	)
	if err != nil {
		return err
	}

	_, err = g.client.Execute(
		"s = g.V().hasLabel('domain','subdomain').has('name', name).has('enum', uuid).next() "+
			"a = g.V().hasLabel('address').has('addr', addr).has('enum', uuid).next() "+
			"g.V(s).out('a_to').hasLabel('address').has('addr', addr).has('enum', uuid).fold()."+
			"coalesce(unfold(), s.addE('a_to').to(a))",
		bindings,
		map[string]string{},
	)
	return err
}

func (g *Gremlin) insertAAAA(data *DataOptsParams) error {
	bindings := map[string]string{
		"uuid":      data.UUID,
		"timestamp": data.Timestamp,
		"name":      data.Name,
		"domain":    data.Domain,
		"addr":      data.Address,
		"type":      "IPv6",
		"tag":       data.Tag,
		"source":    data.Source,
	}

	if data.Name != data.Domain {
		if err := g.insertSubdomain(data); err != nil {
			return err
		}
	}

	_, err := g.client.Execute(
		"g.V().hasLabel('address').has('addr', addr).has('type', type).has('enum', uuid).fold()."+
			"coalesce(unfold(),addV('address').property('addr', addr).property('type', type).property('enum', uuid)."+
			"property('timestamp', timestamp).property('tag', tag).property('source', source))",
		bindings,
		map[string]string{},
	)
	if err != nil {
		return err
	}

	_, err = g.client.Execute(
		"s = g.V().hasLabel('domain','subdomain').has('name', name).has('enum', uuid).next() "+
			"a = g.V().hasLabel('address').has('addr', addr).has('enum', uuid).next() "+
			"g.V(s).out('aaaa_to').hasLabel('address').has('addr', addr).has('enum', uuid).fold()."+
			"coalesce(unfold(), s.addE('aaaa_to').to(a))",
		bindings,
		map[string]string{},
	)
	return err
}

func (g *Gremlin) insertPTR(data *DataOptsParams) error {
	bindings := map[string]string{
		"uuid":      data.UUID,
		"timestamp": data.Timestamp,
		"name":      data.Name,
		"domain":    data.Domain,
		"target":    data.TargetName,
		"tag":       data.Tag,
		"source":    data.Source,
	}

	err := g.insertSubdomain(&DataOptsParams{
		UUID:      data.UUID,
		Timestamp: data.Timestamp,
		Name:      data.TargetName,
		Domain:    data.Domain,
		Tag:       data.Tag,
		Source:    data.Source,
	})
	if err != nil {
		return err
	}

	_, err = g.client.Execute(
		"g.V().hasLabel('ptr').has('name', name).has('enum', uuid).fold()."+
			"coalesce(unfold(),addV('ptr').property('name', name).property('enum', uuid)."+
			"property('timestamp', timestamp).property('tag', tag).property('source', source))",
		bindings,
		map[string]string{},
	)
	if err != nil {
		return err
	}

	_, err = g.client.Execute(
		"p = g.V().hasLabel('ptr').has('name', name).has('enum', uuid).next() "+
			"t = g.V().hasLabel('domain','subdomain').has('name', target).has('enum', uuid).next() "+
			"g.V(p).out('ptr_to').hasLabel('domain','subdomain').has('name', target).has('enum', uuid).fold()."+
			"coalesce(unfold(), p.addE('ptr_to').to(t))",
		bindings,
		map[string]string{},
	)
	return err
}

func (g *Gremlin) insertSRV(data *DataOptsParams) error {
	bindings := map[string]string{
		"uuid":      data.UUID,
		"timestamp": data.Timestamp,
		"name":      data.Name,
		"domain":    data.Domain,
		"service":   data.Service,
		"target":    data.TargetName,
		"tag":       data.Tag,
		"source":    data.Source,
	}

	if err := g.insertSubdomain(data); err != nil {
		return err
	}

	err := g.insertSubdomain(&DataOptsParams{
		UUID:      data.UUID,
		Timestamp: data.Timestamp,
		Name:      data.Service,
		Domain:    data.Domain,
		Tag:       data.Tag,
		Source:    data.Source,
	})
	if err != nil {
		return err
	}

	err = g.insertSubdomain(&DataOptsParams{
		UUID:      data.UUID,
		Timestamp: data.Timestamp,
		Name:      data.TargetName,
		Domain:    data.Domain,
		Tag:       data.Tag,
		Source:    data.Source,
	})
	if err != nil {
		return err
	}

	_, err = g.client.Execute(
		"s = g.V().hasLabel('domain','subdomain').has('name', name).has('enum', uuid).next() "+
			"srv = g.V().hasLabel('subdomain').has('name', service).has('enum', uuid).next() "+
			"g.V(srv).out('service_for').hasLabel('domain','subdomain').has('name', name).has('enum', uuid).fold()."+
			"coalesce(unfold(), srv.addE('service_for').to(s))",
		bindings,
		map[string]string{},
	)
	if err != nil {
		return err
	}

	_, err = g.client.Execute(
		"t = g.V().hasLabel('subdomain').has('name', target).has('enum', uuid).next() "+
			"srv = g.V().hasLabel('subdomain').has('name', service).has('enum', uuid).next() "+
			"g.V(srv).out('srv_to').hasLabel('subdomain').has('name', target).has('enum', uuid).fold()."+
			"coalesce(unfold(), srv.addE('srv_to').to(t))",
		bindings,
		map[string]string{},
	)
	return err
}

func (g *Gremlin) insertNS(data *DataOptsParams) error {
	bindings := map[string]string{
		"uuid":      data.UUID,
		"timestamp": data.Timestamp,
		"name":      data.Name,
		"domain":    data.Domain,
		"target":    data.TargetName,
		"tdomain":   data.TargetDomain,
		"tag":       data.Tag,
		"source":    data.Source,
	}

	if err := g.insertSubdomain(data); err != nil {
		return err
	}

	err := g.insertSub("ns", &DataOptsParams{
		UUID:      data.UUID,
		Timestamp: data.Timestamp,
		Name:      data.TargetName,
		Domain:    data.TargetDomain,
		Tag:       data.Tag,
		Source:    data.Source,
	})
	if err != nil {
		return err
	}

	_, err = g.client.Execute(
		"s = g.V().hasLabel('domain','subdomain').has('name', name).has('enum', uuid).next() "+
			"ns = g.V().hasLabel('ns').has('name', target).has('enum', uuid).next() "+
			"g.V(s).out('ns_to').hasLabel('ns').has('name', target).has('enum', uuid).fold()."+
			"coalesce(unfold(), s.addE('ns_to').to(ns))",
		bindings,
		map[string]string{},
	)
	return err
}

func (g *Gremlin) insertMX(data *DataOptsParams) error {
	bindings := map[string]string{
		"uuid":      data.UUID,
		"timestamp": data.Timestamp,
		"name":      data.Name,
		"domain":    data.Domain,
		"target":    data.TargetName,
		"tdomain":   data.TargetDomain,
		"tag":       data.Tag,
		"source":    data.Source,
	}

	if err := g.insertSubdomain(data); err != nil {
		return err
	}

	err := g.insertSub("mx", &DataOptsParams{
		UUID:      data.UUID,
		Timestamp: data.Timestamp,
		Name:      data.TargetName,
		Domain:    data.TargetDomain,
		Tag:       data.Tag,
		Source:    data.Source,
	})
	if err != nil {
		return err
	}

	_, err = g.client.Execute(
		"s = g.V().hasLabel('domain','subdomain').has('name', name).has('enum', uuid).next() "+
			"mx = g.V().hasLabel('mx').has('name', target).has('enum', uuid).next() "+
			"g.V(s).out('mx_to').hasLabel('mx').has('name', target).has('enum', uuid).fold()."+
			"coalesce(unfold(), s.addE('mx_to').to(mx))",
		bindings,
		map[string]string{},
	)
	return err
}

func (g *Gremlin) insertInfrastructure(data *DataOptsParams) error {
	bindings := map[string]string{
		"uuid":      data.UUID,
		"timestamp": data.Timestamp,
		"addr":      data.Address,
		"asn":       strconv.Itoa(data.ASN),
		"cidr":      data.CIDR,
		"desc":      data.Description,
	}

	_, err := g.client.Execute(
		"g.V().hasLabel('netblock').has('cidr', cidr).has('enum', uuid).fold()."+
			"coalesce(unfold(),addV('netblock').property('cidr', cidr).property('enum', uuid)."+
			"property('timestamp', timestamp).property('tag', tag).property('source', source))",
		bindings,
		map[string]string{},
	)
	if err != nil {
		return err
	}

	_, err = g.client.Execute(
		"a = g.V().hasLabel('address').has('addr', addr).has('enum', uuid).next() "+
			"nb = g.V().hasLabel('netblock').has('cidr', cidr).has('enum', uuid).next() "+
			"g.V(nb).out('contains').hasLabel('address').has('addr', addr).has('enum', uuid).fold()."+
			"coalesce(unfold(), nb.addE('contains').to(a))",
		bindings,
		map[string]string{},
	)
	if err != nil {
		return err
	}

	_, err = g.client.Execute(
		"g.V().hasLabel('as').has('asn', asn).has('enum', uuid).fold()."+
			"coalesce(unfold(),addV('as').property('asn', asn).property('desc', desc).property('enum', uuid)."+
			"property('timestamp', timestamp).property('tag', tag).property('source', source))",
		bindings,
		map[string]string{},
	)
	if err != nil {
		return err
	}

	_, err = g.client.Execute(
		"a = g.V().hasLabel('as').has('asn', asn).has('enum', uuid).next() "+
			"nb = g.V().hasLabel('netblock').has('cidr', cidr).has('enum', uuid).next() "+
			"g.V(a).out('has_prefix').hasLabel('netblock').has('cidr', cidr).has('enum', uuid).fold()."+
			"coalesce(unfold(), a.addE('has_prefix').to(nb))",
		bindings,
		map[string]string{},
	)
	return err
}
