package viz

import (
	"bytes"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestWriteMaltegoData(t *testing.T) {
	buf := bytes.NewBufferString("")
	WriteMaltegoData(buf, testNodes(), testEdges())

	output := buf.String()
	assert.NotEmpty(t, output)
	assert.Contains(t, expectedMaltegoOutput, output, "Maltego output should contain")
}

const expectedMaltegoOutput = `maltego.Domain,maltego.DNSName,maltego.NSRecord,maltego.MXRecord,maltego.IPv4Address,maltego.Netblock,maltego.AS,maltego.Company,maltego.DNSName
`
