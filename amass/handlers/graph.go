// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package handlers

import (
	"context"
	"errors"
	"fmt"
	"io/ioutil"
	"net"
	"os"
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
)

// Graph is the object for managing a network infrastructure link graph.
type Graph struct {
	sync.Mutex
	store  *cayley.Handle
	tmpdir string
}

// NewGraph returns an intialized Graph object.
func NewGraph() *Graph {
	tmpdir, err := ioutil.TempDir("", "amass")
	if err != nil {
		return nil
	}

	err = graph.InitQuadStore("bolt", tmpdir, nil)
	if err != nil {
		return nil
	}

	store, err := cayley.NewGraph("bolt", tmpdir, nil)
	if err != nil {
		return nil
	}
	return &Graph{
		store:  store,
		tmpdir: tmpdir,
	}
}

// Close implements the Amass DataHandler interface.
func (g *Graph) Close() {
	os.RemoveAll(g.tmpdir)
}

func (g *Graph) dumpGraph() string {
	var result string

	p := cayley.StartPath(g.store).Has(quad.String("type")).Unique()
	p.Iterate(nil).EachValue(nil, func(node quad.Value) {
		var predicates []quad.Value
		label := quad.ToString(node)

		result += fmt.Sprintf("%s\n", label)
		p = cayley.StartPath(g.store, quad.String(label)).OutPredicates().Unique()
		p.Iterate(nil).EachValue(nil, func(val quad.Value) {
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

// String implements the Amass data handler interface.
func (g *Graph) String() string {
	return "Amass Graph"
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

// MarkAsRead implements the Amass DataHandler interface.
func (g *Graph) MarkAsRead(data *DataOptsParams) error {
	g.Lock()
	defer g.Unlock()

	label := g.propertyValue(quad.String(data.Name), "type")
	g.store.AddQuad(quad.Make(data.Name, "read", "yes", label))
	return nil
}

// IsCNAMENode implements the Amass DataHandler interface.
func (g *Graph) IsCNAMENode(data *DataOptsParams) bool {
	g.Lock()
	defer g.Unlock()

	if r := g.propertyValue(quad.String(data.Name), "cname_to"); r != "" {
		return true
	}
	return false
}

// VizData returns the current state of the Graph as viz package Nodes and Edges.
func (g *Graph) VizData() ([]viz.Node, []viz.Edge) {
	g.Lock()
	defer g.Unlock()

	var idx int
	var nodes []viz.Node
	rnodes := make(map[string]int)
	p := cayley.StartPath(g.store).Has(quad.String("type")).Unique()
	p.Iterate(nil).EachValue(nil, func(node quad.Value) {
		label := quad.ToString(node)
		if label == "" {
			return
		}

		var source string
		t := g.propertyValue(node, "type")
		title := t + ": " + label

		switch t {
		case "subdomain":
			source = g.propertyValue(node, "source")
		case "domain":
			source = g.propertyValue(node, "source")
		case "ns":
			source = g.propertyValue(node, "source")
		case "mx":
			source = g.propertyValue(node, "source")
		case "as":
			title = title + ", Desc: " + g.propertyValue(node, "description")
		}

		rnodes[label] = idx
		nodes = append(nodes, viz.Node{
			ID:     idx,
			Type:   t,
			Label:  label,
			Title:  title,
			Source: source,
		})
		idx++
	})

	var edges []viz.Edge
	for _, n := range nodes {
		// Obtain all the predicates for this node
		var predicates []quad.Value
		p = cayley.StartPath(g.store, quad.String(n.Label)).OutPredicates().Unique()
		p.Iterate(nil).EachValue(nil, func(val quad.Value) {
			predicates = append(predicates, val)
		})
		// Create viz edges for graph edges leaving the node
		for _, predicate := range predicates {
			path := cayley.StartPath(g.store, quad.String(n.Label)).Out(predicate)
			path.Iterate(nil).EachValue(nil, func(val quad.Value) {
				var to string
				pstr := quad.ToString(predicate)

				if pstr == "root_of" || pstr == "cname_to" || pstr == "a_to" ||
					pstr == "aaaa_to" || pstr == "ptr_to" || pstr == "service_for" ||
					pstr == "srv_to" || pstr == "ns_to" || pstr == "mx_to" ||
					pstr == "contains" || pstr == "has_prefix" {
					to = quad.ToString(val)
				}
				if to == "" {
					return
				}

				edges = append(edges, viz.Edge{
					From:  n.ID,
					To:    rnodes[to],
					Title: pstr,
				})
			})
		}
	}
	return nodes, edges
}

func (g *Graph) insertDomain(data *DataOptsParams) error {
	if data.Domain == "" {
		return errors.New("Graph: insertDomain: no domain name provided")
	}
	// Check if the domain has already been inserted
	if val := g.propertyValue(quad.String(data.Domain), "type"); val != "" {
		return nil
	}

	t := cayley.NewTransaction()
	t.AddQuad(quad.Make(data.Domain, "type", "domain", "domain"))
	t.AddQuad(quad.Make(data.Domain, "timestamp", data.Timestamp, "domain"))
	t.AddQuad(quad.Make(data.Domain, "tag", data.Tag, "domain"))
	t.AddQuad(quad.Make(data.Domain, "source", data.Source, "domain"))
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
		if val := g.propertyValue(quad.String(data.Name), "type"); val != "" {
			return nil
		}

		t := cayley.NewTransaction()
		t.AddQuad(quad.Make(data.Name, "type", label, label))
		t.AddQuad(quad.Make(data.Name, "timestamp", data.Timestamp, label))
		t.AddQuad(quad.Make(data.Name, "tag", data.Tag, label))
		t.AddQuad(quad.Make(data.Name, "source", data.Source, label))
		g.store.ApplyTransaction(t)
		// Create the edge between the domain and the subdomain
		g.store.AddQuad(quad.Make(data.Domain, "root_of", data.Name, "domain"))
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
	g.store.AddQuad(quad.Make(data.Name, "cname_to", data.TargetName, "subdomain"))
	return nil
}

func (g *Graph) insertA(data *DataOptsParams) error {
	if err := g.insertSubdomain(data); err != nil {
		return err
	}
	// Check if the address has already been inserted
	if val := g.propertyValue(quad.String(data.Address), "type"); val != "" {
		return nil
	}

	t := cayley.NewTransaction()
	t.AddQuad(quad.Make(data.Address, "type", "address", "address"))
	t.AddQuad(quad.Make(data.Address, "timestamp", data.Timestamp, "address"))
	g.store.ApplyTransaction(t)
	// Create the edge between the DNS name and the address
	ntype := g.propertyValue(quad.String(data.Name), "type")
	g.store.AddQuad(quad.Make(data.Name, "a_to", data.Address, ntype))
	return nil
}

func (g *Graph) insertAAAA(data *DataOptsParams) error {
	if err := g.insertSubdomain(data); err != nil {
		return err
	}
	// Check if the address has already been inserted
	if val := g.propertyValue(quad.String(data.Address), "type"); val != "" {
		return nil
	}

	t := cayley.NewTransaction()
	t.AddQuad(quad.Make(data.Address, "type", "address", "address"))
	t.AddQuad(quad.Make(data.Address, "timestamp", data.Timestamp, "address"))
	g.store.ApplyTransaction(t)
	// Create the edge between the DNS name and the address
	ntype := g.propertyValue(quad.String(data.Name), "type")
	g.store.AddQuad(quad.Make(data.Name, "aaaa_to", data.Address, ntype))
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
	g.store.AddQuad(quad.Make(data.Name, "ptr_to", data.TargetName, "ptr"))
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
	g.store.AddQuad(quad.Make(data.Service, "service_for", data.Name, "subdomain"))
	// Create the edge between the service and the target
	g.store.AddQuad(quad.Make(data.Service, "srv_to", data.TargetName, "subdomain"))
	return nil
}

func (g *Graph) insertNS(data *DataOptsParams) error {
	if err := g.insertSubdomain(data); err != nil {
		return err
	}

	if swapped := g.swapNodeType(data.TargetName, "ns"); !swapped {
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
	label := g.propertyValue(quad.String(data.Name), "type")
	g.store.AddQuad(quad.Make(data.Name, "ns_to", data.TargetName, label))
	return nil
}

func (g *Graph) insertMX(data *DataOptsParams) error {
	if err := g.insertSubdomain(data); err != nil {
		return err
	}

	if swapped := g.swapNodeType(data.TargetName, "mx"); !swapped {
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
	label := g.propertyValue(quad.String(data.Name), "type")
	g.store.AddQuad(quad.Make(data.Name, "mx_to", data.TargetName, label))
	return nil
}

func (g *Graph) swapNodeType(name, newtype string) bool {
	if name == "" {
		return false
	}
	// Check that a node with 'name' as a subject already exists
	oldtype := g.propertyValue(quad.String(name), "type")
	if oldtype == "" {
		return false
	}
	// Get the predicates for this subject
	var predicates []quad.Value
	p := cayley.StartPath(g.store, quad.String(name)).OutPredicates().Unique()
	p.Iterate(nil).EachValue(nil, func(val quad.Value) {
		predicates = append(predicates, val)
	})
	// Build the transaction to that will perform the swap
	t := cayley.NewTransaction()
	for _, predicate := range predicates {
		kstr := quad.ToString(predicate)

		path := cayley.StartPath(g.store, quad.String(name)).Out(predicate)
		path.Iterate(nil).EachValue(nil, func(val quad.Value) {
			vstr := quad.ToString(val)

			t.RemoveQuad(quad.Make(name, kstr, vstr, oldtype))
			// The type property needs to be changed as well
			if kstr == "type" {
				vstr = newtype
			}
			t.AddQuad(quad.Make(name, kstr, vstr, newtype))
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
	if val := g.propertyValue(quad.String(data.CIDR), "type"); val == "" {
		t := cayley.NewTransaction()
		t.AddQuad(quad.Make(data.CIDR, "type", "netblock", "netblock"))
		t.AddQuad(quad.Make(data.CIDR, "timestamp", data.Timestamp, "netblock"))
		g.store.ApplyTransaction(t)
	}
	// Create the edge between the CIDR and the address
	g.store.AddQuad(quad.Make(data.CIDR, "contains", data.Address, "netblock"))

	asn := strconv.Itoa(data.ASN)
	// Check if the netblock has not been inserted
	if val := g.propertyValue(quad.String(asn), "type"); val == "" {
		t := cayley.NewTransaction()
		t.AddQuad(quad.Make(asn, "type", "as", "as"))
		t.AddQuad(quad.Make(asn, "timestamp", data.Timestamp, "as"))
		t.AddQuad(quad.Make(asn, "description", data.Description, "as"))
		g.store.ApplyTransaction(t)
	}
	// Create the edge between the AS and the netblock
	g.store.AddQuad(quad.Make(asn, "has_prefix", data.CIDR, "as"))
	return nil
}

// GetUnreadOutput returns new findings within the enumeration Graph.
func (g *Graph) GetUnreadOutput(uuid string) []*core.Output {
	g.Lock()
	defer g.Unlock()

	p := cayley.StartPath(g.store).Has(quad.String("type"), quad.String("domain"))
	it, _ := p.BuildIterator().Optimize()
	it, _ = g.store.OptimizeIterator(it)
	defer it.Close()

	ctx := context.TODO()
	var results []*core.Output
	for it.Next(ctx) {
		token := it.Result()
		value := g.store.NameOf(token)
		domain := quad.NativeOf(value).(string)

		names := g.getSubdomainNames(domain)
		for _, name := range names {
			if o := g.buildOutput(name); o != nil {
				o.Domain = domain
				results = append(results, o)
			}
		}
	}
	return results
}

func (g *Graph) getSubdomainNames(domain string) []string {
	names := []string{domain}

	// This path identifies the names that have been marked as 'read'
	read := cayley.StartPath(g.store, quad.String(domain)).Out(
		quad.String("root_of")).Has(quad.String("read"), quad.String("yes"))
	// All the DNS name related nodes that have not already been read
	p := cayley.StartPath(g.store, quad.String(domain)).Out(quad.String("root_of")).Has(
		quad.String("type"), quad.String("subdomain"), quad.String("ns"), quad.String("mx")).Except(read)
	it, _ := p.BuildIterator().Optimize()
	it, _ = g.store.OptimizeIterator(it)
	defer it.Close()

	ctx := context.TODO()
	for it.Next(ctx) {
		token := it.Result()
		value := g.store.NameOf(token)
		sub := quad.NativeOf(value).(string)

		// Check for a SRV name
		if srv := g.propertyValue(quad.String(sub), "srv_to"); srv != "" {
			names = append(names, srv)
		}
		// Grab all the CNAMEs chained to this subdomain name
		if n := g.getCNAMEs(sub); len(n) > 0 {
			names = append(names, n...)
		}
	}
	return names
}

func (g *Graph) getCNAMEs(sub string) []string {
	names := []string{sub}

	cname := quad.String(sub)
	for i := 0; i < 10; i++ {
		target := g.propertyValue(cname, "cname_to")
		if target == "" {
			break
		}
		// Traverse to the next CNAME
		cname = quad.String(target)
		names = utils.UniqueAppend(names, target)
	}
	return names
}

func (g *Graph) buildOutput(sub string) *core.Output {
	qsub := quad.String(sub)
	ts, err := time.Parse(time.RFC3339, g.propertyValue(qsub, "timestamp"))
	if err != nil {
		return nil
	}
	output := &core.Output{
		Timestamp: ts,
		Name:      sub,
		Tag:       g.propertyValue(qsub, "tag"),
		Source:    g.propertyValue(qsub, "source"),
	}
	// Traverse CNAME and SRV records
	target := sub
	for i := 0; i < 10; i++ {
		next := g.propertyValue(quad.String(target), "cname_to")
		if next == "" {
			next = g.propertyValue(quad.String(target), "srv_to")
			if next == "" {
				break
			}
		}
		target = next
	}
	// Get all the IPv4 addresses
	p := cayley.StartPath(g.store, quad.String(target)).Out(quad.String("a_to"))
	p.Iterate(nil).EachValue(nil, func(addr quad.Value) {
		if i := g.buildAddr(addr); i != nil {
			output.Addresses = append(output.Addresses, *i)
		}
	})
	// Get all the IPv6 addresses
	p = cayley.StartPath(g.store, quad.String(target)).Out(quad.String("aaaa_to"))
	p.Iterate(nil).EachValue(nil, func(addr quad.Value) {
		if i := g.buildAddr(addr); i != nil {
			output.Addresses = append(output.Addresses, *i)
		}
	})

	if len(output.Addresses) == 0 {
		return nil
	}
	return output
}

func (g *Graph) buildAddr(addr quad.Value) *core.AddressInfo {
	ainfo := &core.AddressInfo{Address: net.ParseIP(quad.ToString(addr))}

	p := cayley.StartPath(g.store, addr).In(quad.String("contains"))
	pb := p.Iterate(context.TODO())
	values, err := pb.Paths(false).AllValues(g.store)
	if err != nil || len(values) == 0 {
		return nil
	}
	_, ainfo.Netblock, _ = net.ParseCIDR(quad.ToString(values[0]))

	p = cayley.StartPath(g.store, values[0]).In(quad.String("has_prefix"))
	pb = p.Iterate(context.TODO())
	values, err = pb.Paths(false).AllValues(g.store)
	if err != nil || len(values) == 0 {
		return nil
	}

	ainfo.ASN, _ = strconv.Atoi(quad.ToString(values[0]))
	ainfo.Description = g.propertyValue(values[0], "description")
	return ainfo
}

func (g *Graph) propertyValue(node quad.Value, pname string) string {
	if quad.ToString(node) == "" || pname == "" {
		return ""
	}

	p := cayley.StartPath(g.store, node).Out(quad.String(pname))
	it, _ := p.BuildIterator().Optimize()
	it, _ = g.store.OptimizeIterator(it)
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
