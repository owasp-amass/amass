// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package handlers

import (
	"log"
	"strconv"
	"time"

	"github.com/qasaur/gremgo"
)

// Gremlin is the client object for a Gremlin/TinkerPop graph database connection.
type Gremlin struct {
	Log      *log.Logger
	URL      string
	username string
	password string
	pool     *gremgo.Pool
}

// NewGremlin returns a client object that implements the Amass DataHandler interface.
// The url param typically looks like the following: localhost:8182
func NewGremlin(url, user, pass string, l *log.Logger) (*Gremlin, error) {
	g := &Gremlin{
		Log:      l,
		URL:      url,
		username: user,
		password: pass,
		pool: &gremgo.Pool{
			MaxActive:   10,
			IdleTimeout: 30 * time.Second,
		},
	}
	g.pool.Dial = g.getClient
	return g, nil
}

func (g *Gremlin) getClient() (*gremgo.Client, error) {
	errs := make(chan error)
	go func(e chan error) {
		err := <-e
		g.Log.Println("Gremlin: Lost connection to the database: " + err.Error())
	}(errs)

	var err error
	var grem gremgo.Client
	var config gremgo.DialerConfig
	if g.username != "" && g.password != "" {
		config = gremgo.SetAuthentication(g.username, g.password)
		dialer := gremgo.NewDialer("ws://"+g.URL, config)
		grem, err = gremgo.Dial(dialer, errs)
	} else {
		dialer := gremgo.NewDialer("ws://" + g.URL)
		grem, err = gremgo.Dial(dialer, errs)
	}
	return &grem, err
}

// Close cleans up the Gremlin client object.
func (g *Gremlin) Close() {
	return
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

	conn, err := g.pool.Get()
	if err != nil {
		return err
	}
	defer conn.Close()

	_, err = conn.Client.Execute(
		"g.V().hasLabel('domain').has('name', domain).has('enum', uuid).fold()."+
			"coalesce(unfold(),addV('domain').property('enum', uuid)."+
			"property('timestamp', timestamp).property('name', domain)."+
			"property('tag', tag).property('source', source))",
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
		"nodelabel": label,
		"uuid":      data.UUID,
		"timestamp": data.Timestamp,
		"name":      data.Name,
		"domain":    data.Domain,
		"tag":       data.Tag,
		"source":    data.Source,
	}

	if err := g.insertDomain(data); err != nil {
		return err
	}

	if data.Name != data.Domain {
		conn, err := g.pool.Get()
		if err != nil {
			return err
		}
		defer conn.Close()

		_, err = conn.Client.Execute(
			"g.V().hasLabel(nodelabel).has('name', name).has('enum', uuid).fold().coalesce(unfold(),"+
				"V().hasLabel('domain').has('name', domain).has('enum', uuid)."+
				"addE('root_of').to("+
				"addV(nodelabel).property('name', name).property('enum', uuid)."+
				"property('timestamp', timestamp).property('tag', tag).property('source', source)))",
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

	conn, err := g.pool.Get()
	if err != nil {
		return err
	}
	defer conn.Close()

	_, err = conn.Client.Execute(
		"g.V().hasLabel('subdomain').has('name', sname).has('enum', uuid)."+
			"out('cname_to').hasLabel('domain','subdomain').has('name', tname).has('enum', uuid)."+
			"fold().coalesce(unfold(),"+
			"V().hasLabel('subdomain').has('name', sname).has('enum', uuid)."+
			"addE('cname_to').to("+
			"V().hasLabel('domain','subdomain').has('name', tname).has('enum', uuid)))",
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

	conn, err := g.pool.Get()
	if err != nil {
		return err
	}
	defer conn.Close()

	_, err = conn.Client.Execute(
		"g.V().hasLabel('address').has('addr', addr).has('type', type).has('enum', uuid).fold().coalesce(unfold(),"+
			"g.V().hasLabel('domain','subdomain','ns','mx').has('name', name).has('enum', uuid)."+
			"addE('a_to').to("+
			"addV('address').property('addr', addr).property('type', type).property('enum', uuid)."+
			"property('timestamp', timestamp).property('tag', tag).property('source', source)))",
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

	if err := g.insertSubdomain(data); err != nil {
		return err
	}

	conn, err := g.pool.Get()
	if err != nil {
		return err
	}
	defer conn.Close()

	_, err = conn.Client.Execute(
		"g.V().hasLabel('address').has('addr', addr).has('type', type).has('enum', uuid).fold().coalesce(unfold(),"+
			"g.V().hasLabel('domain','subdomain','ns','mx').has('name', name).has('enum', uuid)."+
			"addE('a_to').to("+
			"addV('address').property('addr', addr).property('type', type).property('enum', uuid)."+
			"property('timestamp', timestamp).property('tag', tag).property('source', source)))",
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

	conn, err := g.pool.Get()
	if err != nil {
		return err
	}
	defer conn.Close()

	_, err = conn.Client.Execute(
		"g.V().hasLabel('ptr').has('name', name).has('enum', uuid).fold().coalesce(unfold(),"+
			"addV('ptr').property('name', name).property('enum', uuid).property('timestamp', timestamp)."+
			"property('tag', tag).property('source', source)."+
			"addE('ptr_to').to("+
			"V().hasLabel('domain','subdomain').has('name', target).has('enum', uuid)))",
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

	conn, err := g.pool.Get()
	if err != nil {
		return err
	}
	defer conn.Close()

	_, err = conn.Client.Execute(
		"g.V().hasLabel('subdomain').has('name', service).has('enum', uuid).out('service_for')."+
			"hasLabel('domain','subdomain').has('name', name).has('enum', uuid).fold().coalesce(unfold(),"+
			"V().hasLabel('subdomain').has('name', service).has('enum', uuid).addE('service_for').to("+
			"V().hasLabel('domain','subdomain').has('name', name).has('enum', uuid)))",
		bindings,
		map[string]string{},
	)
	if err != nil {
		return err
	}

	_, err = conn.Client.Execute(
		"g.V().hasLabel('subdomain').has('name', service).has('enum', uuid).out('srv_to')."+
			"hasLabel('subdomain').has('name', target).has('enum', uuid).fold().coalesce(unfold(),"+
			"V().hasLabel('subdomain').has('name', service).has('enum', uuid).addE('srv_to').to("+
			"V().hasLabel('subdomain').has('name', target).has('enum', uuid)))",
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

	conn, err := g.pool.Get()
	if err != nil {
		return err
	}
	defer conn.Close()

	_, err = conn.Client.Execute(
		"g.V().hasLabel('domain','subdomain').has('name', name).has('enum', uuid).out('ns_to')."+
			"hasLabel('ns').has('name', target).has('enum', uuid).fold().coalesce(unfold(),"+
			"V().hasLabel('domain','subdomain').has('name', name).has('enum', uuid)."+
			"addE('ns_to').to("+
			"V().hasLabel('ns').has('name', target).has('enum', uuid)))",
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

	conn, err := g.pool.Get()
	if err != nil {
		return err
	}
	defer conn.Close()

	_, err = conn.Client.Execute(
		"g.V().hasLabel('domain','subdomain').has('name', name).has('enum', uuid).out('mx_to')."+
			"hasLabel('mx').has('name', target).has('enum', uuid).fold().coalesce(unfold(),"+
			"V().hasLabel('domain','subdomain').has('name', name).has('enum', uuid)."+
			"addE('mx_to').to("+
			"V().hasLabel('mx').has('name', target).has('enum', uuid)))",
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
		"asndesc":   data.Description,
	}

	conn, err := g.pool.Get()
	if err != nil {
		return err
	}
	defer conn.Close()

	_, err = conn.Client.Execute(
		"g.V().hasLabel('netblock').has('cidr', cidr).has('enum', uuid).fold().coalesce(unfold(),"+
			"addV('netblock').property('cidr', cidr).property('enum', uuid).property('timestamp', timestamp))",
		bindings,
		map[string]string{},
	)
	if err != nil {
		return err
	}

	_, err = conn.Client.Execute(
		"g.V().hasLabel('netblock').has('cidr', cidr).has('enum', uuid).out('contains')."+
			"hasLabel('address').has('addr', addr).has('enum', uuid).fold().coalesce(unfold(),"+
			"V().hasLabel('netblock').has('cidr', cidr).has('enum', uuid)."+
			"addE('contains').to("+
			"V().hasLabel('address').has('addr', addr).has('enum', uuid)))",
		bindings,
		map[string]string{},
	)
	if err != nil {
		return err
	}

	_, err = conn.Client.Execute(
		"g.V().hasLabel('as').has('asn', asn).has('enum', uuid).fold().coalesce(unfold(),"+
			"addV('as').property('asn', asn).property('description', asndesc)."+
			"property('enum', uuid).property('timestamp', timestamp))",
		bindings,
		map[string]string{},
	)
	if err != nil {
		return err
	}

	_, err = conn.Client.Execute(
		"g.V().hasLabel('as').has('asn', asn).has('enum', uuid).out('has_prefix')."+
			"hasLabel('netblock').has('cidr', cidr).has('enum', uuid).fold().coalesce(unfold(),"+
			"V().hasLabel('as').has('asn', asn).has('enum', uuid)."+
			"addE('has_prefix').to("+
			"V().hasLabel('netblock').has('cidr', cidr).has('enum', uuid)))",
		bindings,
		map[string]string{},
	)
	return err
}
