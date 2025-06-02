// Copyright © by Jeff Foley 2017-2025. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package viz

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestWriteGEXFDataHappyPath(t *testing.T) {
	buf := bytes.NewBufferString("")
	err := WriteGEXFData(buf, testNodes(), testEdges())
	assert.Nil(t, err)

	output := buf.String()
	assert.Contains(t, output, expectedGexfOutput, "Gexf output should contain")
}

const expectedGexfOutput = `<creator>OWASP Amass - https://github.com/owasp-amass</creator>
          <description>OWASP Amass Network Mapping</description>
      </meta>
      <graph mode="static" defaultedgetype="directed">
          <attributes class="node">
              <attribute id="0" title="Title" type="string"></attribute>
              <attribute id="1" title="Type" type="string"></attribute>
          </attributes>
          <nodes>
              <node id="0" label="owasp.org">
                  <attvalues>
                      <attvalue for="0" value="FQDN: owasp.org"></attvalue>
                      <attvalue for="1" value="FQDN"></attvalue>
                  </attvalues>
                  <parents></parents>
                  <viz:color r="34" g="153" b="84"></viz:color>
              </node>
              <node id="1" label="205.251.199.98">
                  <attvalues>
                      <attvalue for="0" value="IPAddress: 205.251.199.98"></attvalue>
                      <attvalue for="1" value="IPAddress"></attvalue>
                  </attvalues>
                  <parents></parents>
                  <viz:color r="243" g="156" b="18"></viz:color>
              </node>
          </nodes>
          <edges>
              <edge id="0" label="a_record" source="0" target="1">
                  <attvalues></attvalues>
              </edge>
          </edges>
      </graph>
  </gexf>`
