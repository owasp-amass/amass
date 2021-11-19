package viz

import (
	"bytes"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestWriteDOTDataHappyPath(t *testing.T) {

	buf := bytes.NewBufferString("")
	err := WriteDOTData(buf, testNodes(), testEdges())
	assert.Nil(t, err)

	output := buf.String()
	assert.Contains(t, output, "digraph \"OWASP Amass Network Mapping\"")
	assert.Contains(t, output, "size = \"7.5,10\"; ranksep=\"2.5 equally\"; ratio=auto;")
	assert.Contains(t, output, "node [label=\"owasp.org\",color=\"red\",type=\"domain\",source=\"DNS\"]; n1;")
	assert.Contains(t, output, "node [label=\"205.251.199.98\",color=\"orange\",type=\"address\",source=\"DNS\"]; n2;")
	assert.Contains(t, output, "node [label=\"205.251.199.98\",color=\"orange\",type=\"address\",source=\"DNS\"]; n2;")
	assert.Contains(t, output, "n1 -> n2 [label=\"a_record\"];")
}
