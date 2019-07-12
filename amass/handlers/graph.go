// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package handlers

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"time"

	"github.com/OWASP/Amass/amass/core"
	"github.com/OWASP/Amass/amass/utils"
	"github.com/OWASP/Amass/amass/utils/viz"
	"github.com/cayleygraph/cayley"
	"github.com/cayleygraph/cayley/graph"
	_ "github.com/cayleygraph/cayley/graph/kv/bolt" // Used by the cayley package
	"github.com/cayleygraph/cayley/quad"
	homedir "github.com/mitchellh/go-homedir"
)

// Graph is the object for managing a network infrastructure link graph.
type Graph struct {
	sync.Mutex
	store *cayley.Handle
	path  string
}

// NewGraph returns an intialized Graph object.
func NewGraph(path string) *Graph {
	var err error

	// If a directory was not specified, $HOME/amass/ will be used
	if path == "" {
		path, err = homedir.Dir()
		if err != nil {
			return nil
		}
		path = filepath.Join(path, core.DefaultOutputDirectory)
	}
	// If the directory does not yet exist, create it
	if err = os.MkdirAll(path, 0755); err != nil {
		return nil
	}

	if isNewFile(filepath.Join(path, "indexes.bolt")) {
		if err = graph.InitQuadStore("bolt", path, nil); err != nil {
			return nil
		}
	}

	store, err := cayley.NewGraph("bolt", path, nil)
	if err != nil {
		return nil
	}
	return &Graph{
		store: store,
		path:  path,
	}
}

func isNewFile(path string) bool {
	finfo, err := os.Stat(path)
	if os.IsNotExist(err) {
		return true
	}
	// See if the file is large enough to
	// be a previously initialized bolt file
	if finfo.Size() < 64 {
		return true
	}
	return false
}

// Close implements the Amass DataHandler interface.
func (g *Graph) Close() {
	g.store.Close()
}

// String implements the Amass data handler interface.
func (g *Graph) String() string {
	return "Amass Graph"
}

func (g *Graph) propertyValue(node quad.Value, pname, uuid string) string {
	if quad.ToString(node) == "" || pname == "" || uuid == "" {
		return ""
	}

	p := cayley.StartPath(g.store, node).LabelContext(quad.String(uuid)).Out(quad.String(pname))
	it, _ := p.BuildIterator().Optimize()
	defer it.Close()

	var result string
	ctx := context.TODO()
	for it.Next(ctx) {
		token := it.Result()
		value := g.store.NameOf(token)
		result = quad.NativeOf(value).(string)
		if result != "" {
			break
		}
	}
	return result
}

func (g *Graph) dumpGraph() string {
	var result string

	p := cayley.StartPath(g.store).Has(quad.String("type")).Unique()
	p.Iterate(nil).EachValue(nil, func(node quad.Value) {
		var predicates []quad.Value
		label := quad.ToString(node)

		result += fmt.Sprintf("%s\n", label)
		p2 := cayley.StartPath(g.store, quad.String(label)).OutPredicates().Unique()
		p2.Iterate(nil).EachValue(nil, func(val quad.Value) {
			predicates = append(predicates, val)
		})

		for _, predicate := range predicates {
			path := cayley.StartPath(g.store, quad.String(label)).Out(predicate)
			path.Iterate(nil).EachValue(nil, func(val quad.Value) {
				kstr := quad.ToString(predicate)
				vstr := quad.ToString(val)

				result += fmt.Sprintf("\t%s: %s\n", kstr, vstr)
			})
		}
	})
	return result
}

// Insert implements the Amass DataHandler interface.
func (g *Graph) Insert(data *DataOptsParams) error {
	g.Lock()
	defer g.Unlock()

	var err error
	switch data.Type {
	case OptDomain:
		err = g.insertDomain(data)
	case OptSubdomain:
		err = g.insertSubdomain(data)
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

func (g *Graph) insertDomain(data *DataOptsParams) error {
	if data.Domain == "" {
		return errors.New("Graph: insertDomain: no domain name provided")
	}
	// Check if the domain has already been inserted
	if val := g.propertyValue(quad.String(data.Domain), "type", data.UUID); val != "" {
		return nil
	}

	t := cayley.NewTransaction()
	t.AddQuad(quad.Make(data.Domain, "type", "domain", data.UUID))
	t.AddQuad(quad.Make(data.Domain, "timestamp", data.Timestamp, data.UUID))
	t.AddQuad(quad.Make(data.Domain, "tag", data.Tag, data.UUID))
	t.AddQuad(quad.Make(data.Domain, "source", data.Source, data.UUID))
	g.store.ApplyTransaction(t)
	return nil
}

func (g *Graph) insertSubdomain(data *DataOptsParams) error {
	return g.insertSub("subdomain", data)
}

func (g *Graph) insertSub(label string, data *DataOptsParams) error {
	if data.Name == "" {
		return errors.New("Graph: insertSub: no name provided")
	}
	if err := g.insertDomain(data); err != nil {
		return err
	}

	if data.Name != data.Domain {
		// Check if this subdomain related node has already been inserted
		if val := g.propertyValue(quad.String(data.Name), "type", data.UUID); val != "" {
			return nil
		}

		t := cayley.NewTransaction()
		t.AddQuad(quad.Make(data.Name, "type", label, data.UUID))
		t.AddQuad(quad.Make(data.Name, "timestamp", data.Timestamp, data.UUID))
		t.AddQuad(quad.Make(data.Name, "tag", data.Tag, data.UUID))
		t.AddQuad(quad.Make(data.Name, "source", data.Source, data.UUID))
		g.store.ApplyTransaction(t)
		// Create the edge between the domain and the subdomain
		g.store.AddQuad(quad.Make(data.Domain, "root_of", data.Name, data.UUID))
	}
	return nil
}

func (g *Graph) insertCNAME(data *DataOptsParams) error {
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
	// Create the edge between the CNAME and the subdomain
	g.store.AddQuad(quad.Make(data.Name, "cname_to", data.TargetName, data.UUID))
	return nil
}

func (g *Graph) insertA(data *DataOptsParams) error {
	if err := g.insertSubdomain(data); err != nil {
		return err
	}
	// Check if the address has already been inserted
	if val := g.propertyValue(quad.String(data.Address), "type", data.UUID); val == "" {
		t := cayley.NewTransaction()
		t.AddQuad(quad.Make(data.Address, "type", "address", data.UUID))
		t.AddQuad(quad.Make(data.Address, "timestamp", data.Timestamp, data.UUID))
		g.store.ApplyTransaction(t)
	}
	// Create the edge between the DNS name and the address
	g.store.AddQuad(quad.Make(data.Name, "a_to", data.Address, data.UUID))
	return nil
}

func (g *Graph) insertAAAA(data *DataOptsParams) error {
	if err := g.insertSubdomain(data); err != nil {
		return err
	}
	// Check if the address has already been inserted
	if val := g.propertyValue(quad.String(data.Address), "type", data.UUID); val == "" {
		t := cayley.NewTransaction()
		t.AddQuad(quad.Make(data.Address, "type", "address", data.UUID))
		t.AddQuad(quad.Make(data.Address, "timestamp", data.Timestamp, data.UUID))
		g.store.ApplyTransaction(t)
	}
	// Create the edge between the DNS name and the address
	g.store.AddQuad(quad.Make(data.Name, "aaaa_to", data.Address, data.UUID))
	return nil
}

func (g *Graph) insertPTR(data *DataOptsParams) error {
	if err := g.insertSub("ptr", data); err != nil {
		return err
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
	// Create the edge between the PTR and the subdomain
	g.store.AddQuad(quad.Make(data.Name, "ptr_to", data.TargetName, data.UUID))
	return nil
}

func (g *Graph) insertSRV(data *DataOptsParams) error {
	if err := g.insertSubdomain(data); err != nil {
		return err
	}
	// Create the service name subdomain node
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
	// Create the target name subdomain node
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
	// Create the edge between the service and the subdomain
	g.store.AddQuad(quad.Make(data.Service, "service_for", data.Name, data.UUID))
	// Create the edge between the service and the target
	g.store.AddQuad(quad.Make(data.Service, "srv_to", data.TargetName, data.UUID))
	return nil
}

func (g *Graph) insertNS(data *DataOptsParams) error {
	if err := g.insertSubdomain(data); err != nil {
		return err
	}

	if swapped := g.swapNodeType(data.TargetName, "ns", data.UUID); !swapped {
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
	}
	// Create the edge between the subdomain and the target
	g.store.AddQuad(quad.Make(data.Name, "ns_to", data.TargetName, data.UUID))
	return nil
}

func (g *Graph) insertMX(data *DataOptsParams) error {
	if err := g.insertSubdomain(data); err != nil {
		return err
	}

	if swapped := g.swapNodeType(data.TargetName, "mx", data.UUID); !swapped {
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
	}
	// Create the edge between the subdomain and the target
	g.store.AddQuad(quad.Make(data.Name, "mx_to", data.TargetName, data.UUID))
	return nil
}

func (g *Graph) swapNodeType(name, newtype, uuid string) bool {
	if name == "" {
		return false
	}
	// Check that a node with 'name' as a subject already exists
	oldtype := g.propertyValue(quad.String(name), "type", uuid)
	if oldtype == "" {
		return false
	}
	// Get the predicates for this subject
	u := quad.String(uuid)
	var predicates []quad.Value
	p := cayley.StartPath(g.store, quad.String(name)).LabelContext(u).OutPredicates().Unique()
	p.Iterate(nil).EachValue(nil, func(val quad.Value) {
		predicates = append(predicates, val)
	})
	// Build the transaction to that will perform the swap
	t := cayley.NewTransaction()
	for _, predicate := range predicates {
		kstr := quad.ToString(predicate)

		path := cayley.StartPath(g.store, quad.String(name)).LabelContext(u).Out(predicate)
		path.Iterate(nil).EachValue(nil, func(val quad.Value) {
			vstr := quad.ToString(val)

			t.RemoveQuad(quad.Make(name, kstr, vstr, uuid))
			// The type property needs to be changed as well
			if kstr == "type" {
				vstr = newtype
			}
			t.AddQuad(quad.Make(name, kstr, vstr, uuid))
		})
	}
	// Attempt to perform the node type swap
	if err := g.store.ApplyTransaction(t); err == nil {
		return true
	}
	return false
}

func (g *Graph) insertInfrastructure(data *DataOptsParams) error {
	// Check if the netblock has not been inserted
	if val := g.propertyValue(quad.String(data.CIDR), "type", data.UUID); val == "" {
		t := cayley.NewTransaction()
		t.AddQuad(quad.Make(data.CIDR, "type", "netblock", data.UUID))
		t.AddQuad(quad.Make(data.CIDR, "timestamp", data.Timestamp, data.UUID))
		g.store.ApplyTransaction(t)
	}
	// Create the edge between the CIDR and the address
	g.store.AddQuad(quad.Make(data.CIDR, "contains", data.Address, data.UUID))

	asn := strconv.Itoa(data.ASN)
	// Check if the netblock has not been inserted
	if val := g.propertyValue(quad.String(asn), "type", data.UUID); val == "" {
		t := cayley.NewTransaction()
		t.AddQuad(quad.Make(asn, "type", "as", data.UUID))
		t.AddQuad(quad.Make(asn, "timestamp", data.Timestamp, data.UUID))
		t.AddQuad(quad.Make(asn, "description", data.Description, data.UUID))
		g.store.ApplyTransaction(t)
	}
	// Create the edge between the AS and the netblock
	g.store.AddQuad(quad.Make(asn, "has_prefix", data.CIDR, data.UUID))
	return nil
}

// EnumerationList returns a list of enumeration IDs found in the data.
func (g *Graph) EnumerationList() []string {
	g.Lock()
	defer g.Unlock()

	p := cayley.StartPath(g.store).Has(quad.String("type"), quad.String("domain")).Labels()
	it, _ := p.BuildIterator().Optimize()
	defer it.Close()

	var ids []string
	ctx := context.TODO()
	for it.Next(ctx) {
		token := it.Result()
		value := g.store.NameOf(token)
		label := quad.NativeOf(value).(string)

		if label != "" {
			ids = utils.UniqueAppend(ids, label)
		}
	}
	return ids
}

// EnumerationDomains returns the domains that were involved in the provided enumeration.
func (g *Graph) EnumerationDomains(uuid string) []string {
	g.Lock()
	defer g.Unlock()

	p := cayley.StartPath(g.store).LabelContext(
		quad.String(uuid)).Has(quad.String("type"), quad.String("domain"))
	it, _ := p.BuildIterator().Optimize()
	defer it.Close()

	var domains []string
	ctx := context.TODO()
	for it.Next(ctx) {
		token := it.Result()
		value := g.store.NameOf(token)
		domain := quad.NativeOf(value).(string)

		if domain != "" {
			domains = utils.UniqueAppend(domains, domain)
		}
	}
	return domains
}

// EnumerationDateRange returns the date range associated with the provided enumeration UUID.
func (g *Graph) EnumerationDateRange(uuid string) (time.Time, time.Time) {
	g.Lock()
	defer g.Unlock()

	p := cayley.StartPath(g.store).LabelContext(quad.String(uuid)).Out(quad.String("timestamp"))
	it, _ := p.BuildIterator().Optimize()
	defer it.Close()

	first := true
	var earliest, latest time.Time
	ctx := context.TODO()
	for it.Next(ctx) {
		token := it.Result()
		value := g.store.NameOf(token)
		timestamp := quad.NativeOf(value).(string)
		tt, err := time.Parse(time.RFC3339, timestamp)
		if err != nil {
			continue
		}
		if first {
			earliest = tt
			latest = tt
			first = false
			continue
		}
		if tt.Before(earliest) {
			earliest = tt
		}
		if tt.After(latest) {
			latest = tt
		}
	}
	return earliest, latest
}

// GetOutput returns new findings within the enumeration Graph.
func (g *Graph) GetOutput(uuid string, marked bool) []*core.Output {
	g.Lock()
	defer g.Unlock()

	p := cayley.StartPath(g.store).LabelContext(
		quad.String(uuid)).Has(quad.String("type"), quad.String("domain"))
	it, _ := p.BuildIterator().Optimize()
	defer it.Close()

	ctx := context.TODO()
	var results []*core.Output
	for it.Next(ctx) {
		token := it.Result()
		value := g.store.NameOf(token)
		domain := quad.NativeOf(value).(string)

		names := g.getSubdomainNames(domain, uuid, marked)
		for _, name := range names {
			if o := g.buildOutput(name, uuid); o != nil {
				o.Domain = domain
				results = append(results, o)
			}
		}
	}
	return results
}

func (g *Graph) getSubdomainNames(domain, uuid string, marked bool) []string {
	names := []string{domain}

	d := quad.String(domain)
	u := quad.String(uuid)
	root := quad.String("root_of")
	t := quad.String("type")
	s := quad.String("subdomain")
	ns := quad.String("ns")
	mx := quad.String("mx")

	p := cayley.StartPath(g.store, d).LabelContext(u).Out(root).Has(t, s, ns, mx)
	if !marked {
		// This path identifies the names that have been marked as 'read'
		read := cayley.StartPath(g.store, d).LabelContext(u).Out(root).Has(
			t, s, ns, mx).Has(quad.String("read"), quad.String("yes"))
		// All the DNS name related nodes that have not already been read
		p = p.Except(read)
	}
	it, _ := p.BuildIterator().Optimize()
	defer it.Close()

	ctx := context.TODO()
	for it.Next(ctx) {
		token := it.Result()
		value := g.store.NameOf(token)
		sub := quad.NativeOf(value).(string)

		// Check for a SRV name
		if srv := g.propertyValue(quad.String(sub), "srv_to", uuid); srv != "" {
			names = append(names, srv)
		}
		// Grab all the CNAMEs chained to this subdomain name
		if n := g.getCNAMEs(sub, uuid); len(n) > 0 {
			names = append(names, n...)
		}
	}
	return names
}

func (g *Graph) getCNAMEs(sub, uuid string) []string {
	names := []string{sub}

	cname := quad.String(sub)
	for i := 0; i < 10; i++ {
		target := g.propertyValue(cname, "cname_to", uuid)
		if target == "" {
			break
		}
		// Traverse to the next CNAME
		cname = quad.String(target)
		names = utils.UniqueAppend(names, target)
	}
	return names
}

func (g *Graph) buildOutput(sub, uuid string) *core.Output {
	qsub := quad.String(sub)
	ts, err := time.Parse(time.RFC3339, g.propertyValue(qsub, "timestamp", uuid))
	if err != nil {
		return nil
	}
	output := &core.Output{
		Timestamp: ts,
		Name:      sub,
		Tag:       g.propertyValue(qsub, "tag", uuid),
		Source:    g.propertyValue(qsub, "source", uuid),
	}
	// Traverse CNAME and SRV records
	target := sub
	for i := 0; i < 10; i++ {
		next := g.propertyValue(quad.String(target), "cname_to", uuid)
		if next == "" {
			next = g.propertyValue(quad.String(target), "srv_to", uuid)
			if next == "" {
				break
			}
		}
		target = next
	}
	// Get all the IPv4 addresses
	u := quad.String(uuid)
	pv4 := cayley.StartPath(g.store, quad.String(target)).LabelContext(u).Out(quad.String("a_to"))
	itv4, _ := pv4.BuildIterator().Optimize()
	defer itv4.Close()

	ctx := context.TODO()
	for itv4.Next(ctx) {
		token := itv4.Result()
		value := g.store.NameOf(token)
		addr := quad.NativeOf(value).(string)

		if i := g.buildAddrInfo(addr, uuid); i != nil {
			output.Addresses = append(output.Addresses, *i)
		}
	}
	// Get all the IPv6 addresses
	pv6 := cayley.StartPath(g.store, quad.String(target)).LabelContext(u).Out(quad.String("aaaa_to"))
	itv6, _ := pv6.BuildIterator().Optimize()
	defer itv6.Close()

	ctx = context.TODO()
	for itv6.Next(ctx) {
		token := itv6.Result()
		value := g.store.NameOf(token)
		addr := quad.NativeOf(value).(string)

		if i := g.buildAddrInfo(addr, uuid); i != nil {
			output.Addresses = append(output.Addresses, *i)
		}
	}

	if len(output.Addresses) == 0 {
		return nil
	}
	return output
}

func (g *Graph) buildAddrInfo(addr, uuid string) *core.AddressInfo {
	ainfo := &core.AddressInfo{Address: net.ParseIP(addr)}

	u := quad.String(uuid)
	nb := cayley.StartPath(g.store, quad.String(addr)).LabelContext(u).In(quad.String("contains"))
	itnb, _ := nb.BuildIterator().Optimize()
	defer itnb.Close()

	var cidr string
	ctx := context.TODO()
	for itnb.Next(ctx) {
		token := itnb.Result()
		value := g.store.NameOf(token)
		cidr = quad.NativeOf(value).(string)

		if cidr != "" {
			break
		}
	}
	if cidr == "" {
		return nil
	}
	ainfo.CIDRStr = cidr
	_, ainfo.Netblock, _ = net.ParseCIDR(cidr)

	p := cayley.StartPath(g.store, quad.String(cidr)).LabelContext(u).In(quad.String("has_prefix"))
	itasn, _ := p.BuildIterator().Optimize()
	defer itasn.Close()

	var asn string
	ctx = context.TODO()
	for itasn.Next(ctx) {
		token := itasn.Result()
		value := g.store.NameOf(token)
		asn = quad.NativeOf(value).(string)

		if asn != "" {
			break
		}
	}
	if asn == "" {
		return nil
	}

	ainfo.ASN, _ = strconv.Atoi(asn)
	ainfo.Description = g.propertyValue(quad.String(asn), "description", uuid)
	return ainfo
}

// MarkAsRead implements the Amass DataHandler interface.
func (g *Graph) MarkAsRead(data *DataOptsParams) error {
	g.Lock()
	defer g.Unlock()

	if t := g.propertyValue(quad.String(data.Name), "type", data.UUID); t != "" {
		g.store.AddQuad(quad.Make(data.Name, "read", "yes", data.UUID))
	}
	return nil
}

// IsCNAMENode implements the Amass DataHandler interface.
func (g *Graph) IsCNAMENode(data *DataOptsParams) bool {
	g.Lock()
	defer g.Unlock()

	if r := g.propertyValue(quad.String(data.Name), "cname_to", data.UUID); r != "" {
		return true
	}
	return false
}

// VizData returns the current state of the Graph as viz package Nodes and Edges.
func (g *Graph) VizData(uuid string) ([]viz.Node, []viz.Edge) {
	g.Lock()
	defer g.Unlock()

	var idx int
	var nodes []viz.Node
	u := quad.String(uuid)
	rnodes := make(map[string]int)
	p := cayley.StartPath(g.store).LabelContext(u).Has(quad.String("type")).Unique()
	it, _ := p.BuildIterator().Optimize()
	defer it.Close()

	ctx := context.TODO()
	for it.Next(ctx) {
		token := it.Result()
		value := g.store.NameOf(token)
		name := quad.NativeOf(value).(string)
		if name == "" {
			continue
		}
		node := quad.String(name)

		var source string
		t := g.propertyValue(node, "type", uuid)
		title := t + ": " + name

		switch t {
		case "subdomain":
			source = g.propertyValue(node, "source", uuid)
		case "domain":
			source = g.propertyValue(node, "source", uuid)
		case "ns":
			source = g.propertyValue(node, "source", uuid)
		case "mx":
			source = g.propertyValue(node, "source", uuid)
		case "as":
			title = title + ", Desc: " + g.propertyValue(node, "description", uuid)
		}

		rnodes[name] = idx
		nodes = append(nodes, viz.Node{
			ID:     idx,
			Type:   t,
			Label:  name,
			Title:  title,
			Source: source,
		})
		idx++
	}

	var edges []viz.Edge
	for _, n := range nodes {
		// Obtain all the predicates for this node
		var predicates []quad.Value
		p = cayley.StartPath(g.store, quad.String(n.Label)).LabelContext(u).OutPredicates().Unique()
		it, _ := p.BuildIterator().Optimize()
		defer it.Close()

		ctx := context.TODO()
		for it.Next(ctx) {
			token := it.Result()
			value := g.store.NameOf(token)
			pred := quad.NativeOf(value).(string)
			if pred == "" {
				continue
			}

			predicates = append(predicates, quad.String(pred))
		}
		// Create viz edges for graph edges leaving the node
		for _, predicate := range predicates {
			path := cayley.StartPath(g.store, quad.String(n.Label)).LabelContext(u).Out(predicate)
			it, _ := path.BuildIterator().Optimize()
			defer it.Close()

			ctx := context.TODO()
			for it.Next(ctx) {
				token := it.Result()
				value := g.store.NameOf(token)
				vstr := quad.NativeOf(value).(string)
				if vstr == "" {
					continue
				}

				var to string
				pstr := quad.ToString(predicate)
				if pstr == "root_of" || pstr == "cname_to" || pstr == "a_to" ||
					pstr == "aaaa_to" || pstr == "ptr_to" || pstr == "service_for" ||
					pstr == "srv_to" || pstr == "ns_to" || pstr == "mx_to" ||
					pstr == "contains" || pstr == "has_prefix" {
					to = vstr
				}
				if to == "" {
					continue
				}

				edges = append(edges, viz.Edge{
					From:  n.ID,
					To:    rnodes[to],
					Title: pstr,
				})
			}
		}
	}
	return nodes, edges
}
