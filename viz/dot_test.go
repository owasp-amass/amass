package viz

import (
	"bytes"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestWriteDOTDataHappyPath(t *testing.T) {

	buf := bytes.NewBufferString("")
	err := WriteDOTData(buf, testNodes(), testEdges())
	if err != nil {
		t.Errorf("Error writing DOT data: %s", err)
	}

	output := buf.String()
	t.Logf("DOT data: %s", buf.String())
	assert.Contains(t, output, "digraph \"OWASP Amass Network Mapping\"")
	assert.Contains(t, output, "size = \"7.5,10\"; ranksep=\"2.5 equally\"; ratio=auto;")
	assert.Contains(t, output, "node [label=\"owasp.org\",color=\"red\",type=\"domain\",source=\"DNS\"]; n1;")
	assert.Contains(t, output, "node [label=\"205.251.199.98\",color=\"orange\",type=\"address\",source=\"DNS\"]; n2;")
	assert.Contains(t, output, "node [label=\"205.251.199.98\",color=\"orange\",type=\"address\",source=\"DNS\"]; n2;")
	assert.Contains(t, output, "n2 -> n3 [label=\"a_record\"];")
}

func testEdges() []Edge {
	return []Edge{
		{
			From:  1,
			To:    2,
			Label: "",
			Title: "a_record",
		},
	}
}

func testNodes() []Node {
	return []Node{
		{
			ID:         1,
			Type:       "domain",
			Label:      "owasp.org",
			Title:      "domain: owasp.org",
			Source:     "DNS",
			ActualType: "fqdn",
		},
		{
			ID:         2,
			Type:       "address",
			Label:      "205.251.199.98",
			Title:      "address: 205.251.199.98",
			Source:     "DNS",
			ActualType: "ipaddr",
		},
	}
}
