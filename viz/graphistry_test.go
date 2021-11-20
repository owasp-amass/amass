package viz

import (
	"bytes"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestWriteGraphistryData(t *testing.T) {
	buf := bytes.NewBufferString("")
	err := WriteGraphistryData(buf, testNodes(), testEdges())
	assert.Nil(t, err)

	output := buf.String()
	// because the output contains a timestamp let's check for most of expected output
	assert.Contains(t, output, `"type": "edgelist",
  "bindings": {
    "sourceField": "src",
    "destinationField": "dst",
    "idField": "node"
  },
  "graph": [
    {
      "src": "0",
      "dst": "1",
      "edgeTitle": "a_record"
    }
  ],
  "labels": [
    {
      "node": "0",
      "pointLabel": "owasp.org",
      "pointTitle": "domain: owasp.org",
      "pointColor": 5,
      "type": "domain",
      "source": "DNS"
    },
    {
      "node": "1",
      "pointLabel": "205.251.199.98",
      "pointTitle": "address: 205.251.199.98",
      "pointColor": 7,
      "type": "address",
      "source": "DNS"
    }
  ]`, "Graphistry output should contain")
}
