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

const expectedMaltegoOutput = `maltego.Domain,maltego.DNSName,maltego.NSRecord,maltego.MXRecord,maltego.IPv4Address,maltego.IPv6Address,maltego.Netblock,maltego.AS,maltego.Company,maltego.DNSName
`

func TestCidrToMaltegoNetblock(t *testing.T) {
	cases := []struct {
		label    string
		input    string
		ok       bool
		expected string
	}{
		{
			label:    "Empty",
			input:    "",
			expected: "",
		}, {
			label:    "Valid_CIDRs",
			input:    "193.0.2.1/16",
			ok:       true,
			expected: "193.0.0.0-193.0.255.255",
		}, {
			label:    "Invalid_CIDRs",
			input:    "193.0.2.1/66",
			expected: "",
		}, {
			label:    "Whitespace",
			input:    "\t192.0.2.1/24",
			expected: "",
		}, {
			label:    "Extraneous_Comma",
			input:    "192.0.2.1/24,",
			expected: "",
		},
	}
	for _, c := range cases {
		f := func(t *testing.T) {
			ips := cidrToMaltegoNetblock(c.input)
			if ips != c.expected {

				t.Errorf("Got %v; Expected: %v", ips, c.expected)
			}
		}

		t.Run(c.label, f)
	}
}
