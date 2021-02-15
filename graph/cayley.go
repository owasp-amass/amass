// Copyright 2017-2020 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package graph

import (
	"context"
	"fmt"
	"strings"
	"sync"

	"github.com/cayleygraph/cayley"
	"github.com/cayleygraph/cayley/clog"
	"github.com/cayleygraph/cayley/graph"
	_ "github.com/cayleygraph/cayley/graph/kv/bolt" // Used by the cayley package
	_ "github.com/cayleygraph/cayley/graph/sql/mysql"
	_ "github.com/cayleygraph/cayley/graph/sql/postgres"
	"github.com/cayleygraph/quad"
)

// CayleyGraph is the object for managing a network infrastructure link graph.
type CayleyGraph struct {
	sync.Mutex
	store  *cayley.Handle
	name   string
	path   string
	isBolt bool
	noSync bool
}

// NewCayleyGraph returns an intialized CayleyGraph object.
func NewCayleyGraph(system, path string, options string) *CayleyGraph {
	// Some globally applicable things
	graph.IgnoreMissing = true
	graph.IgnoreDuplicates = true

	empty := true
	name := system
	var isbolt, nosync bool
	opts := make(graph.Options)

	clog.SetLogger(nil)
	switch system {
	case "local":
		isbolt = true
		system = "bolt"
	case "mysql":
		empty = false
		opts["flavor"] = system
		system = "sql"
	case "postgres":
		empty = false
		opts["flavor"] = system
		system = "sql"
	default:
		return nil
	}

	for _, opt := range strings.Split(options, ",") {
		s := strings.Split(opt, "=")
		if len(s) != 2 {
			continue
		}

		empty = false
		name := s[0]
		value := s[1]
		switch value {
		case "true":
			opts[name] = true
		case "false":
			opts[name] = false
		default:
			opts[name] = value
		}
	}
	if empty {
		opts = nil
	} else if on, found := opts["nosync"]; found {
		nosync = on.(bool)
	}

	if path == "" {
		return nil
	}

	_ = graph.InitQuadStore(system, path, opts)
	store, err := cayley.NewGraph(system, path, opts)
	if err != nil {
		return nil
	}

	return &CayleyGraph{
		store:  store,
		name:   name,
		path:   path,
		isBolt: isbolt,
		noSync: nosync,
	}
}

// NewCayleyGraphMemory creates a temporary graph in memory.
func NewCayleyGraphMemory() *CayleyGraph {
	// Some globally applicable things
	graph.IgnoreMissing = true
	graph.IgnoreDuplicates = true

	store, err := cayley.NewMemoryGraph()
	if err != nil {
		return nil
	}

	return &CayleyGraph{
		store: store,
		name:  "memory",
		path:  "",
	}
}

// Close implements the GraphDatabase interface.
func (g *CayleyGraph) Close() {
	g.store.Close()
}

// String returns a description for the CayleyGraph object.
func (g *CayleyGraph) String() string {
	return g.name
}

// DumpGraph prints all data currently in the graph.
func (g *CayleyGraph) DumpGraph() string {
	g.Lock()
	defer g.Unlock()

	var out string
	p := cayley.StartPath(g.store).Tag("subject").OutWithTags([]string{"predicate"}).Tag("object")
	err := p.Iterate(context.TODO()).TagValues(nil, func(m map[string]quad.Value) {
		out += fmt.Sprintf("%s -> %s -> %s\n", m["subject"], m["predicate"], m["object"])
	})
	if err != nil {
		return ""
	}

	return out
}

func isIRI(val quad.Value) bool {
	_, ok := val.Native().(quad.IRI)

	return ok
}

func strsToVals(strs ...string) []quad.Value {
	var values []quad.Value

	for _, str := range strs {
		values = append(values, quad.IRI(str))
	}

	return values
}

func valToStr(v quad.Value) string {
	var result string

	if iri, ok := v.Native().(quad.IRI); ok {
		result = strings.TrimRight(strings.TrimLeft(string(iri), "<"), ">")
	} else if str, ok := v.Native().(string); ok {
		result = strings.Trim(str, `"`)
	}

	return result
}
