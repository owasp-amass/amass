// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"flag"
	"fmt"
	"os"
	"path"

	"github.com/OWASP/Amass/amass/core"
	"github.com/OWASP/Amass/amass/handlers"
	"github.com/OWASP/Amass/amass/utils/viz"
)

var (
	help           = flag.Bool("h", false, "Show the program usage message")
	input          = flag.String("i", "", "The Amass data operations JSON file")
	maltegopath    = flag.String("maltego", "", "Path to the Maltego csv file")
	visjspath      = flag.String("visjs", "", "Path to the Visjs output HTML file")
	graphistrypath = flag.String("graphistry", "", "Path to the Graphistry JSON file")
	gexfpath       = flag.String("gexf", "", "Path to the Gephi Graph Exchange XML Format (GEXF) file")
	d3path         = flag.String("d3", "", "Path to the D3 v4 force simulation HTML file")
)

func main() {
	flag.Parse()

	if *help {
		fmt.Printf("Usage: %s -i infile --maltego of1 --visjs of2 --gexf of3 --d3 of4 --graphistry of5\n", path.Base(os.Args[0]))
		flag.PrintDefaults()
		return
	}

	if *input == "" {
		fmt.Println("The data operations JSON file must be provided using the '-i' flag")
		return
	}

	f, err := os.Open(*input)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}

	opts, err := handlers.ParseDataOpts(f)
	if err != nil {
		fmt.Println("Failed to parse the provided data operations")
		return
	}

	graph := core.NewGraph()
	err = handlers.DataOptsDriver(opts, graph)
	if err != nil {
		fmt.Printf("Failed to build the network graph: %v\n", err)
		return
	}

	nodes, edges := graph.VizData()
	writeMaltegoFile(*maltegopath, nodes, edges)
	writeVisjsFile(*visjspath, nodes, edges)
	writeGraphistryFile(*graphistrypath, nodes, edges)
	writeGEXFFile(*gexfpath, nodes, edges)
	writeD3File(*d3path, nodes, edges)
}

func writeMaltegoFile(path string, nodes []viz.Node, edges []viz.Edge) {
	if path == "" {
		return
	}

	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE, 0644)
	if err != nil {
		return
	}
	defer f.Close()

	viz.WriteMaltegoData(f, nodes, edges)
	f.Sync()
}

func writeVisjsFile(path string, nodes []viz.Node, edges []viz.Edge) {
	if path == "" {
		return
	}

	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE, 0644)
	if err != nil {
		return
	}
	defer f.Close()

	viz.WriteVisjsData(f, nodes, edges)
	f.Sync()
}

func writeGraphistryFile(path string, nodes []viz.Node, edges []viz.Edge) {
	if path == "" {
		return
	}

	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE, 0644)
	if err != nil {
		return
	}
	defer f.Close()

	viz.WriteGraphistryData(f, nodes, edges)
	f.Sync()
}

func writeGEXFFile(path string, nodes []viz.Node, edges []viz.Edge) {
	if path == "" {
		return
	}

	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE, 0644)
	if err != nil {
		return
	}
	defer f.Close()

	viz.WriteGEXFData(f, nodes, edges)
	f.Sync()
}

func writeD3File(path string, nodes []viz.Node, edges []viz.Edge) {
	if path == "" {
		return
	}

	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE, 0644)
	if err != nil {
		return
	}
	defer f.Close()

	viz.WriteD3Data(f, nodes, edges)
	f.Sync()
}
