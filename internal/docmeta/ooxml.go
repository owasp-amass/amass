// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package docmeta

import (
	"archive/zip"
	"bytes"
	"encoding/xml"
	"errors"
	"io"
)

// maxOOXMLPart caps how much of a metadata part is read: they are a few
// kilobytes, and a hostile archive could declare a huge one.
const maxOOXMLPart = 1 << 20

// errNotOOXML is returned for data that is not an Office Open XML package.
var errNotOOXML = errors.New("docmeta: not an OOXML package")

// coreProps is docProps/core.xml (ECMA-376 Part 2, core properties).
type coreProps struct {
	Title          string `xml:"title"`
	Creator        string `xml:"creator"`
	LastModifiedBy string `xml:"lastModifiedBy"`
	Created        string `xml:"created"`
	Modified       string `xml:"modified"`
}

// appProps is docProps/app.xml (extended properties).
type appProps struct {
	Application string `xml:"Application"`
	AppVersion  string `xml:"AppVersion"`
	Company     string `xml:"Company"`
}

// extractOOXML reads the core and extended properties of a docx, xlsx or
// pptx package (a zip archive).
func extractOOXML(data []byte) (Metadata, error) {
	var m Metadata
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return m, errNotOOXML
	}

	var core coreProps
	var app appProps
	found := false
	for _, f := range zr.File {
		var dst any
		switch f.Name {
		case "docProps/core.xml":
			dst = &core
		case "docProps/app.xml":
			dst = &app
		default:
			continue
		}

		rc, err := f.Open()
		if err != nil {
			continue
		}
		part, err := io.ReadAll(io.LimitReader(rc, maxOOXMLPart))
		_ = rc.Close()
		if err != nil {
			continue
		}
		if xml.Unmarshal(part, dst) == nil {
			found = true
		}
	}
	if !found {
		return m, errNotOOXML
	}

	m.Title = core.Title
	m.Author = core.Creator
	m.LastModifiedBy = core.LastModifiedBy
	m.Created = normalizeDate(core.Created)
	m.Modified = normalizeDate(core.Modified)
	m.Company = app.Company
	m.Creator = app.Application
	if app.Application != "" && app.AppVersion != "" {
		m.Creator = app.Application + " " + app.AppVersion
	}

	return m, nil
}
