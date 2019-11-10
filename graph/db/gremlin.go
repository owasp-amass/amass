// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package db

/*
import (
	"encoding/json"
	"log"
	"net"
	"strconv"
	"time"

	"github.com/OWASP/Amass/v3/queue"
	"github.com/OWASP/Amass/v3/requests"
	"github.com/OWASP/Amass/v3/semaphore"
	"github.com/OWASP/Amass/v3/viz"
	"github.com/qasaur/gremgo"
)

const (
	// GremlinMaxConnections defines the limited number of concurrent connections to the Gremlin Server.
	GremlinMaxConnections int = 25
)

// Gremlin is the client object for a Gremlin/TinkerPop graph database connection.
type Gremlin struct {
	Log      *log.Logger
	URL      string
	username string
	password string
	pool     *gremgo.Pool
	requests *queue.Queue
	avail    semaphore.Semaphore
	done     chan struct{}
}

// NewGremlin returns a client object that implements the GraphDatabase interface.
// The url param typically looks like the following: ws://localhost:8182
func NewGremlin(url, user, pass string, l *log.Logger) *Gremlin {
	g := &Gremlin{
		Log:      l,
		URL:      url,
		username: user,
		password: pass,
		pool: &gremgo.Pool{
			MaxActive:   GremlinMaxConnections,
			IdleTimeout: 5 * time.Second,
		},
		requests: new(queue.Queue),
		avail:    semaphore.NewSimpleSemaphore(GremlinMaxConnections),
		done:     make(chan struct{}, 2),
	}
	g.pool.Dial = g.getClient
	go g.processInsertRequests()
	return g
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
		dialer := gremgo.NewDialer(g.URL, config)
		grem, err = gremgo.Dial(dialer, errs)
	} else {
		dialer := gremgo.NewDialer(g.URL)
		grem, err = gremgo.Dial(dialer, errs)
	}
	return &grem, err
}

// Close implements the GraphDatabase interface.
func (g *Gremlin) Close() {
	g.done <- struct{}{}
}

// String returns a description for the Gremlin client object.
func (g *Gremlin) String() string {
	return "Gremlin TinkerPop Handler"
}

// NodeToID implements the GraphDatabase interface.
func (g *Gremlin) NodeToID(n Node) string {
	return fmt.Sprintf("%s", n)
}

// InsertNode implements the GraphDatabase interface.
func (g *Gremlin) InsertNode(id, ntype string) (Node, error) {
	if id == "" || ntype == "" {
		return nil, fmt.Errorf("%s: InsertNode: Empty required arguments", g.String())
	}

	bindings := map[string]string{
		"label":      id,
		"type": ntype,
	}

	conn, err := g.pool.Get()
	if err != nil {
		return err
	}
	defer conn.Close()

	_, err = conn.Client.Execute(
		// Does this vertex already exist in the graph?
		"g.V(label).fold().coalesce(unfold(),"+
			// Add the new vertex to the graph
			"g.addV(id).property('type', type)",
		bindings,
		map[string]string{},
	)
	if err == nil {
		return id, nil
	}

	return "", err
}

// ReadNode implements the GraphDatabase interface.
func (g *Gremlin) ReadNode(id string) (Node, error) {
	if id == "" {
		return nil, fmt.Errorf("%s: ReadNode: Invalid node provided", g.String())
	}

	// Check that a node with 'id' as a subject already exists
	bindings := map[string]string{"label":      id}

	conn, err := g.pool.Get()
	if err != nil {
		return err
	}
	defer conn.Close()

	result, err = conn.Client.Execute(
		// Does this vertex already exist in the graph?
		"g.V(label).values('type')",
		bindings,
		map[string]string{},
	)
	if rstr := fmt.Sprint("%s", result); err == nil && rstr != "" {
		return id, nil
	}

	return nil, fmt.Errorf("%s: ReadNode: Node %s does not exist", g.String(), id)
}

// DeleteNode implements the GraphDatabase interface.
func (g *Gremlin) DeleteNode(node Node) error {
	id := g.NodeToID(node)
	if id == "" {
		return fmt.Errorf("%s: DeleteNode: Invalid node provided", g.String())
	}

	bindings := map[string]string{"label":      id}

	conn, err := g.pool.Get()
	if err != nil {
		return err
	}
	defer conn.Close()

	_, err = conn.Client.Execute(
		"g.V(label).drop()",
		bindings,
		map[string]string{},
	)

	return err
}

// AllNodesOfType implements the GraphDatabase interface.
func (g *Gremlin) AllNodesOfType(ntype string) ([]Node, error) {
	if ntype == "" {
		return nil, fmt.Errorf("%s: AllNodesOfType: Empty type argument", g.String())
	}

	bindings := map[string]string{"type": ntype}

	conn, err := g.pool.Get()
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	nodes, err = conn.Client.Execute(
		"g.V().has('type', type)",
		bindings,
		map[string]string{},
	)

	return nodes, err
}

// InsertProperty implements the GraphDatabase interface.
func (g *Gremlin) InsertProperty(node Node, predicate, value string) error {
	g.Lock()
	defer g.Unlock()

	nstr := g.NodeToID(node)
	if nstr == "" {
		return fmt.Errorf("%s: InsertProperty: Invalid node reference argument", g.String())
	}

	bindings := map[string]string{
		"label":      nstr,
		"pred": predicate,
		"value": value,
	}

	conn, err := g.pool.Get()
	if err != nil {
		return err
	}
	defer conn.Close()

	_, err = conn.Client.Execute(
		// Does this vertex already exist in the graph?
		"g.V(label).property(pred, value)",
		bindings,
		map[string]string{},
	)

	return g.store.AddQuad(quad.Make(nstr, predicate, value, nil))
}

// ReadProperties implements the GraphDatabase interface.
func (g *Gremlin) ReadProperties(node Node, predicates ...string) ([]*Property, error) {
	nstr := g.NodeToID(node)
	var properties []*Property

	if nstr == "" {
		return properties, fmt.Errorf("%s: ReadProperties: Invalid node reference argument", g.String())
	}

	preds := stringset.New(predicates...)
	for _, pred := range g.nodePredicates(nstr, "out") {
		if len(predicates) > 0 && !preds.Has(pred) {
			continue
		}

		vals := cayley.StartPath(g.store, quad.String(nstr)).Out(quad.String(pred))
		g.optimizedIterate(vals, func(value quad.Value) {
			vstr := quad.ToString(value)

			// Check if this is actually a node and not a property
			p := cayley.StartPath(g.store, quad.String(vstr)).Has(quad.String("type"))
			if first := g.optimizedFirst(p); first == nil {
				properties = append(properties, &Property{
					Predicate: pred,
					Value:     vstr,
				})
			}
		})
	}

	if len(properties) == 0 {
		return properties, fmt.Errorf("%s: ReadProperties: No properties discovered", g.String())
	}

	return properties, nil
}

// CountProperties implements the GraphDatabase interface.
func (g *Gremlin) CountProperties(node Node, predicates ...string) (int, error) {
	g.RLock()
	defer g.RUnlock()

	nstr := g.NodeToID(node)
	if nstr == "" {
		return 0, fmt.Errorf("%s: CountProperties: Invalid node reference argument", g.String())
	}

	var preds []quad.Value
	for _, p := range predicates {
		preds = append(preds, quad.String(p))
	}

	edges := cayley.StartPath(g.store, quad.String(nstr)).Out(preds).Has(quad.String("type"))
	p := cayley.StartPath(g.store, quad.String(nstr)).Out(preds).Except(edges)

	return g.optimizedCount(p), nil
}

// DeleteProperty implements the GraphDatabase interface.
func (g *Gremlin) DeleteProperty(node Node, predicate, value string) error {
	g.Lock()
	defer g.Unlock()

	nstr := g.NodeToID(node)
	if nstr == "" {
		return fmt.Errorf("%s: DeleteProperty: Invalid node reference argument", g.String())
	}

	// Check if this is actually a node and not a property
	p := cayley.StartPath(g.store, quad.String(value)).Has(quad.String("type"))
	if first := g.optimizedFirst(p); first != nil {
		return fmt.Errorf("%s: DeleteProperty: Attempt to delete an edge as a property", g.String())
	}

	return g.store.RemoveQuad(quad.Make(nstr, predicate, value, nil))
}

// InsertEdge implements the GraphDatabase interface.
func (g *Gremlin) InsertEdge(edge *Edge) error {
	g.Lock()
	defer g.Unlock()

	nstr1 := g.NodeToID(edge.From)
	nstr2 := g.NodeToID(edge.To)
	if nstr1 == "" || nstr2 == "" {
		return fmt.Errorf("%s: InsertEdge: Invalid edge argument", g.String())
	}

	// Check if the from node has already been inserted
	p := cayley.StartPath(g.store, quad.String(nstr1)).Has(quad.String("type"))
	if first := g.optimizedFirst(p); first == nil {
		return fmt.Errorf("%s: InsertEdge: Node %s does not exist", g.String(), nstr1)
	}

	// Check if the to node has already been inserted
	p = cayley.StartPath(g.store, quad.String(nstr2)).Has(quad.String("type"))
	if first := g.optimizedFirst(p); first == nil {
		return fmt.Errorf("%s: InsertEdge: Node %s does not exist", g.String(), nstr2)
	}

	return g.store.AddQuad(quad.Make(nstr1, edge.Predicate, nstr2, nil))
}

// ReadEdges implements the GraphDatabase interface.
func (g *Gremlin) ReadEdges(node Node, predicates ...string) ([]*Edge, error) {
	nstr := g.NodeToID(node)
	if nstr == "" {
		return nil, fmt.Errorf("%s: ReadEdges: Invalid node reference argument", g.String())
	}

	var edges []*Edge
	if e, err := g.ReadInEdges(node, predicates...); err == nil {
		edges = append(edges, e...)
	}

	if e, err := g.ReadOutEdges(node, predicates...); err == nil {
		edges = append(edges, e...)
	}

	if len(edges) == 0 {
		return nil, fmt.Errorf("%s: ReadEdges: Failed to discover edges for the node %s", g.String(), nstr)
	}

	return edges, nil
}

// ReadInEdges implements the GraphDatabase interface.
func (g *Gremlin) ReadInEdges(node Node, predicates ...string) ([]*Edge, error) {
	g.RLock()
	defer g.RUnlock()

	nstr := g.NodeToID(node)
	if nstr == "" {
		return nil, fmt.Errorf("%s: ReadInEdges: Invalid node reference argument", g.String())
	}

	var edges []*Edge
	preds := stringset.New(predicates...)
	for _, pred := range g.nodePredicates(nstr, "in") {
		if len(predicates) > 0 && !preds.Has(pred) {
			continue
		}

		vals := cayley.StartPath(g.store, quad.String(nstr)).In(quad.String(pred))
		g.optimizedIterate(vals, func(value quad.Value) {
			vstr := quad.ToString(value)

			// Check if this is actually a node and not a property
			p := cayley.StartPath(g.store, quad.String(vstr)).Has(quad.String("type"))
			if first := g.optimizedFirst(p); first != nil {
				edges = append(edges, &Edge{
					Predicate: pred,
					From:      vstr,
					To:        node,
				})
			}
		})
	}

	if len(edges) == 0 {
		return nil, fmt.Errorf("%s: ReadInEdges: Failed to discover edges coming into the node %s", g.String(), nstr)
	}

	return edges, nil
}

// CountInEdges implements the GraphDatabase interface.
func (g *Gremlin) CountInEdges(node Node, predicates ...string) (int, error) {
	g.RLock()
	defer g.RUnlock()

	nstr := g.NodeToID(node)
	if nstr == "" {
		return 0, fmt.Errorf("%s: CountInEdges: Invalid node reference argument", g.String())
	}

	var preds []quad.Value
	for _, p := range predicates {
		preds = append(preds, quad.String(p))
	}

	p := cayley.StartPath(g.store, quad.String(nstr)).In(preds).Has(quad.String("type"))

	return g.optimizedCount(p), nil
}

// ReadOutEdges implements the GraphDatabase interface.
func (g *Gremlin) ReadOutEdges(node Node, predicates ...string) ([]*Edge, error) {
	g.RLock()
	defer g.RUnlock()

	nstr := g.NodeToID(node)
	if nstr == "" {
		return nil, fmt.Errorf("%s: ReadOutEdges: Invalid node reference argument", g.String())
	}

	var edges []*Edge
	preds := stringset.New(predicates...)
	for _, pred := range g.nodePredicates(nstr, "out") {
		if len(predicates) > 0 && !preds.Has(pred) {
			continue
		}

		vals := cayley.StartPath(g.store, quad.String(nstr)).Out(quad.String(pred))
		g.optimizedIterate(vals, func(value quad.Value) {
			vstr := quad.ToString(value)

			// Check if this is actually a node and not a property
			p := cayley.StartPath(g.store, quad.String(vstr)).Has(quad.String("type"))
			if first := g.optimizedFirst(p); first != nil {
				edges = append(edges, &Edge{
					Predicate: pred,
					From:      node,
					To:        vstr,
				})
			}
		})
	}

	if len(edges) == 0 {
		return nil, fmt.Errorf("%s: ReadOutEdges: Failed to discover edges leaving the node %s", g.String(), nstr)
	}

	return edges, nil
}

// CountOutEdges implements the GraphDatabase interface.
func (g *Gremlin) CountOutEdges(node Node, predicates ...string) (int, error) {
	g.RLock()
	defer g.RUnlock()

	nstr := g.NodeToID(node)
	if nstr == "" {
		return 0, fmt.Errorf("%s: CountOutEdges: Invalid node reference argument", g.String())
	}

	var preds []quad.Value
	for _, p := range predicates {
		preds = append(preds, quad.String(p))
	}

	p := cayley.StartPath(g.store, quad.String(nstr)).Out(preds).Has(quad.String("type"))

	return g.optimizedCount(p), nil
}

// DeleteEdge implements the GraphDatabase interface.
func (g *Gremlin) DeleteEdge(edge *Edge) error {
	g.Lock()
	defer g.Unlock()

	from := g.NodeToID(edge.From)
	to := g.NodeToID(edge.To)
	if from == "" || to == "" {
		return fmt.Errorf("%s: DeleteEdge: Invalid edge reference argument", g.String())
	}

	return g.store.RemoveQuad(quad.Make(from, edge.Predicate, to, nil))
}

func (g *Gremlin) propertyValues(node quad.Value, pname string) []string {
	var results []string

	if nstr := quad.ToString(node); nstr != "" || pname != "" {
		p := cayley.StartPath(g.store, quad.String(nstr)).Out(quad.String(pname))

		g.optimizedIterate(p, func(node quad.Value) {
			results = append(results, quad.ToString(node))
		})
	}

	return results
}

func (g *Gremlin) nodePredicates(id, direction string) []string {
	p := cayley.StartPath(g.store, quad.String(id))

	if direction == "in" {
		p = p.InPredicates()
	} else if direction == "out" {
		p = p.OutPredicates()
	}
	p = p.Unique()

	var predicates []string
	g.optimizedIterate(p, func(value quad.Value) {
		if vstr := quad.ToString(value); vstr != "" {
			predicates = append(predicates, vstr)
		}
	})

	return predicates
}

// DumpGraph returns a string containing all data currently in the graph.
func (g *Gremlin) DumpGraph() string {
	return ""
}

/*

type gremlinRequest struct {
	Params *DataOptsParams
	Err    chan error
}

// Insert implements the Amass DataHandler interface.
func (g *Gremlin) Insert(data *DataOptsParams) error {
	e := make(chan error)
	g.requests.Append(&gremlinRequest{
		Params: data,
		Err:    e,
	})
	return <-e
}

func (g *Gremlin) insertData(data *DataOptsParams) error {
	g.avail.Acquire(1)
	defer g.avail.Release(1)

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

func (g *Gremlin) processInsertRequests() {
	curIdx := 0
	maxIdx := 7
	delays := []int{10, 25, 50, 75, 100, 150, 250, 500}
	for {
		select {
		case <-g.done:
			return
		default:
			element, ok := g.requests.Next()
			if !ok {
				time.Sleep(time.Duration(delays[curIdx]) * time.Millisecond)
				if curIdx < maxIdx {
					curIdx++
				}
				continue
			}
			curIdx = 0
			req := element.(*gremlinRequest)
			req.Err <- g.insertData(req.Params)
		}
	}
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
			// Does this subdomain name related vertex already exist in the graph?
			"g.V().hasLabel(nodelabel).has('name', name).has('enum', uuid).fold().coalesce(unfold(),"+
				// Find the appropriate domain vertex in the graph
				"g.V().hasLabel('domain').has('name', domain).has('enum', uuid)."+
				// Add the new edge
				"addE('root_of').to("+
				// Add the new subdomain name related vertex for the edge to point to
				"g.addV(nodelabel).property('name', name).property('type', nodelabel).property('enum', uuid)."+
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
		// Does this 'cname_to' edge already exist in the graph?
		"g.V().hasLabel('subdomain').has('name', sname).has('enum', uuid)."+
			"out('cname_to').hasLabel('domain','subdomain').has('name', tname)."+
			"has('enum', uuid).fold().coalesce(unfold(),"+
			// Find the CNAME subdomain vertex in the graph
			"g.V().hasLabel('subdomain').has('name', sname).has('enum', uuid)."+
			// Add the new edge
			"addE('cname_to').to("+
			// Identify the subdomain name related vertex to point the edge to
			"g.V().hasLabel('domain','subdomain','ns','mx').has('name', tname).has('enum', uuid)))",
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
		"addrtype":  "IPv4",
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
		// Does this address already exist in the graph?
		"g.V().hasLabel('address').has('addr', addr).has('addrtype', addrtype).has('enum', uuid).fold().coalesce(unfold(),"+
			// Find the subdomain name related vertex in the graph
			"g.V().hasLabel('domain','subdomain','ns','mx').has('name', name).has('enum', uuid)."+
			// Add the new edge
			"addE('a_to').to("+
			// Add the new address vertex that the edge should point to
			"addV('address').property('addr', addr).property('addrtype', addrtype).property('enum', uuid)."+
			"property('type', 'address').property('timestamp', timestamp).property('tag', tag).property('source', source)))",
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
		"addrtype":  "IPv6",
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
		// Does this address already exist in the graph?
		"g.V().hasLabel('address').has('addr', addr).has('addrtype', addrtype).has('enum', uuid).fold().coalesce(unfold(),"+
			// Find the subdomain name related vertex in the graph
			"g.V().hasLabel('domain','subdomain','ns','mx').has('name', name).has('enum', uuid)."+
			// Add the new edge
			"addE('aaaa_to').to("+
			// Add the new address vertex that the edge should point to
			"addV('address').property('addr', addr).property('addrtype', addrtype).property('enum', uuid)."+
			"property('type', 'address').property('timestamp', timestamp).property('tag', tag).property('source', source)))",
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
		// Does the 'ptr_to' edge already exist between the ptr and the subdomain?
		"g.V().hasLabel('ptr').has('name', name).has('enum', uuid).fold().coalesce(unfold(),"+
			// Add the ptr vertex into the graph
			"g.addV('ptr').property('name', name).property('type', 'ptr').property('enum', uuid)."+
			"property('timestamp', timestamp).property('tag', tag).property('source', source)."+
			// Add the new edge
			"addE('ptr_to').to("+
			// Identify the domain/subdomain vertex to point the edge to
			"g.V().hasLabel('domain','subdomain').has('name', target).has('enum', uuid)))",
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
		// Does the 'srv_to' edge already exist between the two subdomains?
		"g.V().hasLabel('subdomain').has('name', service).has('enum', uuid).out('service_for')."+
			"hasLabel('domain','subdomain').has('name', name).has('enum', uuid).fold().coalesce(unfold(),"+
			// Find the subdomain in the graph
			"g.V().hasLabel('subdomain').has('name', service).has('enum', uuid)."+
			// Add the new edge
			"addE('service_for').to("+
			// Identify the subdomain vertex to point the edge to
			"g.V().hasLabel('domain','subdomain').has('name', name).has('enum', uuid)))",
		bindings,
		map[string]string{},
	)
	if err != nil {
		return err
	}

	_, err = conn.Client.Execute(
		// Does the 'srv_to' edge already exist between the two subdomains?
		"g.V().hasLabel('subdomain').has('name', service).has('enum', uuid).out('srv_to')."+
			"hasLabel('subdomain').has('name', target).has('enum', uuid).fold().coalesce(unfold(),"+
			// Find the subdomain in the graph
			"g.V().hasLabel('subdomain').has('name', service).has('enum', uuid)."+
			// Add the new edge
			"addE('srv_to').to("+
			// Identify the subdomain vertex to point the edge to
			"g.V().hasLabel('subdomain').has('name', target).has('enum', uuid)))",
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
		// Does the 'ns_to' edge already exist between the domain/subdomain and the ns?
		"g.V().hasLabel('domain','subdomain').has('name', name).has('enum', uuid).out('ns_to')."+
			"hasLabel('ns').has('name', target).has('enum', uuid).fold().coalesce(unfold(),"+
			// Find the domain/subdomain in the graph
			"g.V().hasLabel('domain','subdomain').has('name', name).has('enum', uuid)."+
			// Add the new edge
			"addE('ns_to').to("+
			// Identify the ns vertex to point the edge to
			"g.V().hasLabel('ns').has('name', target).has('enum', uuid)))",
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
		// Does the 'mx_to' edge already exist between the domain/subdomain and the mx?
		"g.V().hasLabel('domain','subdomain').has('name', name).has('enum', uuid).out('mx_to')."+
			"hasLabel('mx').has('name', target).has('enum', uuid).fold().coalesce(unfold(),"+
			// Find the domain/subdomain in the graph
			"g.V().hasLabel('domain','subdomain').has('name', name).has('enum', uuid)."+
			// Add the new edge
			"addE('mx_to').to("+
			// Identify the mx vertex to point the edge to
			"g.V().hasLabel('mx').has('name', target).has('enum', uuid)))",
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
		// Does this address already exist in the graph?
		"g.V().hasLabel('address').has('addr', addr).has('addrtype', addrtype).has('enum', uuid).fold().coalesce(unfold(),"+
			// Add the new address vertex that the edge should point to
			"g.addV('address').property('addr', addr).property('addrtype', addrtype).property('enum', uuid)."+
			"property('type', 'address').property('timestamp', timestamp))",
		bindings,
		map[string]string{},
	)
	if err != nil {
		return err
	}

	_, err = conn.Client.Execute(
		// Does this netblock already exist in the graph?
		"g.V().hasLabel('netblock').has('cidr', cidr).has('enum', uuid).fold().coalesce(unfold(),"+
			// Add the new netblock vertex
			"g.addV('netblock').property('cidr', cidr).property('enum', uuid)."+
			"property('type', 'netblock').property('timestamp', timestamp))",
		bindings,
		map[string]string{},
	)
	if err != nil {
		return err
	}

	_, err = conn.Client.Execute(
		// Does the 'contains' edge already exist between the netblock and the address?
		"g.V().hasLabel('netblock').has('cidr', cidr).has('enum', uuid).out('contains')."+
			"hasLabel('address').has('addr', addr).has('enum', uuid).fold().coalesce(unfold(),"+
			// Find the netblock in the graph
			"g.V().hasLabel('netblock').has('cidr', cidr).has('enum', uuid)."+
			// Add the new edge
			"addE('contains').to("+
			// Identify the address vertex to point the edge to
			"g.V().hasLabel('address').has('addr', addr).has('enum', uuid)))",
		bindings,
		map[string]string{},
	)
	if err != nil {
		return err
	}

	_, err = conn.Client.Execute(
		// Does this AS already exist in the graph?
		"g.V().hasLabel('as').has('asn', asn).has('enum', uuid).fold().coalesce(unfold(),"+
			// Add the new AS vertex
			"g.addV('as').property('asn', asn).property('description', asndesc)."+
			"property('type', 'as').property('enum', uuid).property('timestamp', timestamp))",
		bindings,
		map[string]string{},
	)
	if err != nil {
		return err
	}

	_, err = conn.Client.Execute(
		// Does the 'has_prefix' edge already exist between the AS and the netblock?
		"g.V().hasLabel('as').has('asn', asn).has('enum', uuid).out('has_prefix')."+
			"hasLabel('netblock').has('cidr', cidr).has('enum', uuid).fold().coalesce(unfold(),"+
			// Find the AS in the graph
			"g.V().hasLabel('as').has('asn', asn).has('enum', uuid)."+
			// Add the new edge
			"addE('has_prefix').to("+
			// Identify the netblock vertex to point the edge to
			"g.V().hasLabel('netblock').has('cidr', cidr).has('enum', uuid)))",
		bindings,
		map[string]string{},
	)
	return err
}

// EnumerationList returns a list of enumeration IDs found in the data.
func (g *Gremlin) EnumerationList() []string {
	return []string{}
}

// EnumerationDomains returns the domains that were involved in the provided enumeration.
func (g *Gremlin) EnumerationDomains(uuid string) []string {
	return []string{}
}

// EnumerationDateRange returns the date range associated with the provided enumeration UUID.
func (g *Gremlin) EnumerationDateRange(uuid string) (time.Time, time.Time) {
	return time.Now(), time.Now()
}

// GetOutput implements the Amass DataHandler interface.
func (g *Gremlin) GetOutput(uuid string, marked bool) []*requests.Output {
	g.avail.Acquire(1)
	defer g.avail.Release(1)

	bindings := map[string]string{"uuid": uuid}

	conn, err := g.pool.Get()
	if err != nil {
		return nil
	}
	defer conn.Close()

	// Find the vertices connected to all the domain names
	query := "g.V().hasLabel('domain').has('enum', uuid).out('root_of').has('enum', uuid)."

	if !marked {
		// We are only interested in the vertices not yet marked
		query = query + "not(has('read','yes'))."
	}

	// Traverse all the 'cname_to' and 'srv_to' edges
	query = query + "until(outE('cname_to','srv_to').count().is(0).or().loops().is(10))." +
		"repeat(out('cname_to','srv_to'))." +
		// Traverse to the address vertices
		"out('a_to','aaaa_to').hasLabel('address').has('enum', uuid)." +
		// Traverse to the netblock vertex
		"in('contains').hasLabel('netblock').has('enum', uuid)." +
		// Complete the path by reaching the AS
		"in('has_prefix').hasLabel('as').has('enum', uuid).path().by(valueMap())"

	resp, err := conn.Client.Execute(query, bindings, map[string]string{})
	if err == nil {
		var output []*requests.Output

		for _, out := range parseGremlinResponse(resp) {
			output = append(output, out)
		}
		return output
	}
	return nil
}

func parseGremlinResponse(resp interface{}) []*requests.Output {
	b, err := json.Marshal(resp)
	if err != nil {
		return nil
	}

	var o [1][]map[string]interface{}
	if err := json.Unmarshal(b, &o); err != nil {
		return nil
	}

	t := make(map[string]*requests.Output)
	// Generate requests.Output for each path returned by the graph
	for _, path := range o[0] {
		var vertices []*DataOptsParams

		b, err := json.Marshal(path["objects"])
		if err != nil {
			continue
		}

		var objects []map[string][]string
		if err := json.Unmarshal(b, &objects); err != nil {
			continue
		}
		// Convert the vertex properties into a DataOptsParams struct
		for _, vert := range objects {
			data := propertiesToData(vert)
			vertices = append(vertices, data)
		}
		if len(vertices) == 0 {
			continue
		}
		// Convert the path of vertices into requests.Output structs
		for _, out := range dataToOutput(vertices) {
			// Maintain the master list of findings
			if _, found := t[out.Name]; found {
				tmp := t[out.Name]
				// Check for duplicate addresses
				for _, n := range out.Addresses {
					var dup bool

					for _, addr := range tmp.Addresses {
						if addr.Address.String() == n.Address.String() {
							dup = true
							break
						}
					}
					if !dup {
						tmp.Addresses = append(tmp.Addresses, n)
					}
				}
				t[out.Name] = tmp
			} else {
				t[out.Name] = out
			}
		}
	}

	var output []*requests.Output
	for _, out := range t {
		output = append(output, out)
	}
	return output
}

func dataToOutput(path []*DataOptsParams) []*requests.Output {
	var domain string
	var addrinfo requests.AddressInfo

	for _, v := range path {
		switch v.Type {
		case "domain":
			domain = v.Name
		case "address":
			addrinfo.Address = net.ParseIP(v.Address)
		case "netblock":
			addrinfo.CIDRStr = v.CIDR
			_, addrinfo.Netblock, _ = net.ParseCIDR(v.CIDR)
		case "as":
			addrinfo.ASN = v.ASN
			addrinfo.Description = v.Description
		}
	}

	var output []*requests.Output
	for _, v := range path {
		if v.Type == "subdomain" || v.Type == "ns" || v.Type == "mx" {
			ts, _ := time.Parse(time.RFC3339, v.Timestamp)
			o := &requests.Output{
				Timestamp: ts,
				Name:      v.Name,
				Domain:    domain,
				Addresses: []requests.AddressInfo{addrinfo},
				Tag:       v.Tag,
				Source:    v.Source,
			}
			output = append(output, o)
		}
	}
	return output
}

func propertiesToData(props map[string][]string) *DataOptsParams {
	data := new(DataOptsParams)

	for key, value := range props {
		if len(value) == 0 {
			continue
		}

		switch key {
		case "enum":
			data.UUID = value[0]
		case "timestamp":
			data.Timestamp = value[0]
		case "type":
			data.Type = value[0]
		case "name":
			data.Name = value[0]
		case "addr":
			data.Address = value[0]
		case "cidr":
			data.CIDR = value[0]
		case "asn":
			data.ASN, _ = strconv.Atoi(value[0])
		case "description":
			data.Description = value[0]
		case "tag":
			data.Tag = value[0]
		case "source":
			data.Source = value[0]
		}
	}
	return data
}

// MarkAsRead implements the Amass DataHandler interface.
func (g *Gremlin) MarkAsRead(data *DataOptsParams) error {
	g.avail.Acquire(1)
	defer g.avail.Release(1)

	bindings := map[string]string{
		"uuid":   data.UUID,
		"name":   data.Name,
		"domain": data.Domain,
	}

	conn, err := g.pool.Get()
	if err != nil {
		return err
	}
	defer conn.Close()

	_, err = conn.Client.Execute(
		// Find the domain name for the vertex
		"g.V().hasLabel('domain').has('name', domain).has('enum', uuid).out('root_of')."+
			// Find the subdomain name related vertex in the graph
			"hasLabel('domain','subdomain','ns','mx').has('name', name).has('enum', uuid)."+
			// Mark the subdomain name related vertex as read
			"property('read', 'yes')",
		bindings,
		map[string]string{},
	)
	return err
}

// IsCNAMENode implements the Amass DataHandler interface.
func (g *Gremlin) IsCNAMENode(data *DataOptsParams) bool {
	g.avail.Acquire(1)
	defer g.avail.Release(1)

	bindings := map[string]string{
		"uuid":   data.UUID,
		"name":   data.Name,
		"domain": data.Domain,
	}

	conn, err := g.pool.Get()
	if err != nil {
		return false
	}
	defer conn.Close()

	resp, err := conn.Client.Execute(
		// Find the vertex in the graph and determine if it is a CNAME
		"g.V().hasLabel('subdomain').has('name', name).has('enum', uuid).outE('cname_to').count()",
		bindings,
		map[string]string{},
	)
	if err != nil {
		return false
	}

	b, err := json.Marshal(resp)
	if err != nil {
		return false
	}

	var count [1][]int64
	if err = json.Unmarshal(b, &count); err == nil {
		if len(count[0]) > 0 && count[0][0] > 0 {
			return true
		}
	}
	return false
}

*/
