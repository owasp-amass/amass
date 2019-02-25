// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"bytes"
	"flag"
	"fmt"
	"io/ioutil"
	"math/rand"
	"os"
	"path"
	"time"

	"github.com/OWASP/Amass/amass"
	"github.com/OWASP/Amass/amass/handlers"
	"github.com/OWASP/Amass/amass/utils/viz"
	"github.com/fatih/color"
)

const (
	DefaultGraphDBDirectory string = "amass_output"
)

var (
	// Colors used to ease the reading of program output
	y      = color.New(color.FgHiYellow)
	g      = color.New(color.FgHiGreen)
	r      = color.New(color.FgHiRed)
	b      = color.New(color.FgHiBlue)
	fgR    = color.New(color.FgRed)
	fgY    = color.New(color.FgYellow)
	yellow = color.New(color.FgHiYellow).SprintFunc()
	green  = color.New(color.FgHiGreen).SprintFunc()
	blue   = color.New(color.FgHiBlue).SprintFunc()
	// Command-line switches and provided parameters
	help           = flag.Bool("h", false, "Show the program usage message")
	vprint         = flag.Bool("version", false, "Print the version number of this Amass binary")
	dir            = flag.String("dir", "", "Path to the directory containing the graph database")
	input          = flag.String("i", "", "The Amass data operations JSON file")
	maltegopath    = flag.String("maltego", "", "Path to the Maltego csv file")
	visjspath      = flag.String("visjs", "", "Path to the Visjs output HTML file")
	graphistrypath = flag.String("graphistry", "", "Path to the Graphistry JSON file")
	gexfpath       = flag.String("gexf", "", "Path to the Gephi Graph Exchange XML Format (GEXF) file")
	d3path         = flag.String("d3", "", "Path to the D3 v4 force simulation HTML file")
)

func main() {
	defaultBuf := new(bytes.Buffer)
	flag.CommandLine.SetOutput(defaultBuf)
	flag.Usage = func() {
		printBanner()
		g.Fprintf(color.Error,
			"Usage: %s -i path --maltego o1 --visjs o2 --gexf o3 --d3 o4 --graphistry o5\n\n", path.Base(os.Args[0]))
		flag.PrintDefaults()
		g.Fprintln(color.Error, defaultBuf.String())
	}
	flag.Parse()

	// Some input validation
	if *help || len(os.Args) == 1 {
		flag.Usage()
		return
	}
	if *vprint {
		fmt.Fprintf(color.Error, "version %s\n", amass.Version)
		return
	}

	var err error
	rand.Seed(time.Now().UTC().UnixNano())
	if *input != "" {
		*dir, err = ioutil.TempDir("", DefaultGraphDBDirectory)
		if err != nil {
			r.Fprintln(color.Error, "Failed to open the graph database")
			os.Exit(1)
		}
		defer os.RemoveAll(*dir)
	} else {
		// Check that the default graph database directory exists in the CWD
		if *dir == "" {
			if finfo, err := os.Stat(DefaultGraphDBDirectory); os.IsNotExist(err) || !finfo.IsDir() {
				r.Fprintln(color.Error, "Failed to open the graph database")
				os.Exit(1)
			}
		} else if finfo, err := os.Stat(*dir); os.IsNotExist(err) || !finfo.IsDir() {
			r.Fprintln(color.Error, "Failed to open the graph database")
			os.Exit(1)
		}
	}

	graph := handlers.NewGraph(*dir)
	if graph == nil {
		r.Fprintln(color.Error, "Failed to open the graph database")
		os.Exit(1)
	}

	var uuid string
	if *input != "" {
		f, err := os.Open(*input)
		if err != nil {
			r.Fprintf(color.Error, "Failed to open the input file: %v\n", err)
			os.Exit(1)
		}

		opts, err := handlers.ParseDataOpts(f)
		if err != nil {
			r.Fprintln(color.Error, "Failed to parse the provided data operations")
			os.Exit(1)
		}
		uuid = opts[0].UUID

		err = handlers.DataOptsDriver(opts, graph)
		if err != nil {
			r.Fprintf(color.Error, "Failed to build the network graph: %v\n", err)
			os.Exit(1)
		}
	} else {
		var latest time.Time
		for i, enum := range graph.EnumerationList() {
			e, l := graph.EnumerationDateRange(enum)
			if i == 0 {
				latest = l
				uuid = enum
			} else if l.After(latest) {
				uuid = enum
			}
		}
		if uuid == "" {
			r.Fprintln(color.Error, "No enumeration found within the graph database")
			os.Exit(1)
		}
	}

	nodes, edges := graph.VizData(uuid)
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

func printBanner() {
	rightmost := 76
	version := "Version " + amass.Version
	desc := "In-depth DNS Enumeration and Network Mapping"
	author := "Authored By " + amass.Author

	pad := func(num int) {
		for i := 0; i < num; i++ {
			fmt.Fprint(color.Error, " ")
		}
	}
	r.Fprintln(color.Error, amass.Banner)
	pad(rightmost - len(version))
	y.Fprintln(color.Error, version)
	pad(rightmost - len(author))
	y.Fprintln(color.Error, author)
	pad(rightmost - len(desc))
	y.Fprintf(color.Error, "%s\n\n\n", desc)
}
