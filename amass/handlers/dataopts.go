// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package handlers

import (
	"encoding/json"
	"io"
)

// DataOptsHandler is the object that implements the DataHandler interface for JSON files.
type DataOptsHandler struct {
	Enc *json.Encoder
}

// NewDataOptsHandler returns a JSON file handler for Amass data operations.
func NewDataOptsHandler(w io.Writer) *DataOptsHandler {
	return &DataOptsHandler{Enc: json.NewEncoder(w)}
}

// String returns a description for the DataOptsHandler object.
func (d *DataOptsHandler) String() string {
	return "Data Operations Storage Handler"
}

// Insert implements the Amass DataHandler interface.
func (d *DataOptsHandler) Insert(data *DataOptsParams) error {
	return d.Enc.Encode(data)
}
