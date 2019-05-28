// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package handlers

import (
	"encoding/json"
	"io"
	"time"

	"github.com/OWASP/Amass/amass/core"
	"github.com/OWASP/Amass/amass/utils/viz"
)

// DataOptsHandler is the object that implements the DataHandler interface for JSON files.
type DataOptsHandler struct {
	Enc *json.Encoder
}

// NewDataOptsHandler returns a JSON file handler for Amass data operations.
func NewDataOptsHandler(w io.Writer) *DataOptsHandler {
	return &DataOptsHandler{Enc: json.NewEncoder(w)}
}

// Close implements the Amass DataHandler interface.
func (d *DataOptsHandler) Close() {
	return
}

// String returns a description for the DataOptsHandler object.
func (d *DataOptsHandler) String() string {
	return "Data Operations Storage Handler"
}

// Insert implements the Amass DataHandler interface.
func (d *DataOptsHandler) Insert(data *DataOptsParams) error {
	return d.Enc.Encode(data)
}

// EnumerationList returns a list of enumeration IDs found in the data.
func (d *DataOptsHandler) EnumerationList() []string {
	return []string{}
}

// EnumerationDomains returns the domains that were involved in the provided enumeration.
func (d *DataOptsHandler) EnumerationDomains(uuid string) []string {
	return []string{}
}

// EnumerationDateRange returns the date range associated with the provided enumeration UUID.
func (d *DataOptsHandler) EnumerationDateRange(uuid string) (time.Time, time.Time) {
	return time.Now(), time.Now()
}

// GetOutput implements the Amass DataHandler interface.
func (d *DataOptsHandler) GetOutput(uuid string, marked bool) []*core.Output {
	return nil
}

// MarkAsRead implements the Amass DataHandler interface.
func (d *DataOptsHandler) MarkAsRead(data *DataOptsParams) error {
	return nil
}

// IsCNAMENode implements the Amass DataHandler interface.
func (d *DataOptsHandler) IsCNAMENode(data *DataOptsParams) bool {
	return false
}

// VizData returns the current state of the Graph as viz package Nodes and Edges.
func (d *DataOptsHandler) VizData(uuid string) ([]viz.Node, []viz.Edge) {
	return []viz.Node{}, []viz.Edge{}
}