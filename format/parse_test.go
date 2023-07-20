// Copyright © by Jeff Foley 2017-2023. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package format

import (
	"fmt"
	"testing"
)

func TestNilParseStrings(t *testing.T) {
	const expected = ""

	if got := (*ParseStrings)(nil).String(); got != expected {
		t.Errorf("Got: %q; Expected: %q", got, expected)
	}
}

func TestParseStrings(t *testing.T) {
	cases := []struct {
		label    string
		input    string
		ok       bool
		expected string
	}{
		{
			label: "Empty_Input",
			input: "",
		}, {
			label:    "Valid_Input",
			input:    "234,foo,bar",
			ok:       true,
			expected: "234,foo,bar",
		}, {
			label:    "Extra_Comma",
			input:    "234,foo,bar,",
			ok:       true,
			expected: "234,foo,bar,",
		}, {
			label:    "With_Whitespace",
			input:    "234  , foo ,\tbar",
			ok:       true,
			expected: "234,foo,bar",
		},
	}

	for _, c := range cases {
		f := func(t *testing.T) {
			var ints ParseStrings

			if err := ints.Set(c.input); err != nil && c.ok {
				t.Errorf("Got: %v; Expected: <nil>", err)
			} else if err == nil && !c.ok {
				t.Error("Got: <nil>; Expected: some error")
			} else if err == nil && c.ok {
				if got := ints.String(); got != c.expected {
					t.Errorf("Got: %q; Expected: %q", got, c.expected)
				}
			}
		}

		t.Run(c.label, f)
	}
}

func TestNilParseInts(t *testing.T) {
	const expected = ""

	if got := (*ParseInts)(nil).String(); got != expected {
		t.Errorf("Got: %q; Expected: %q", got, expected)
	}
}

func TestParseInts(t *testing.T) {
	cases := []struct {
		label    string
		input    string
		ok       bool
		expected string
	}{
		{
			label: "Empty_Input",
			input: "",
		}, {
			label: "Invalid_Int",
			input: "1,sdfg,2,3",
		}, {
			label: "Extraneous_Comma",
			input: "-1,2,,",
		}, {
			label:    "Without_Whitespace",
			input:    "-1,10,42",
			ok:       true,
			expected: "-1,10,42",
		}, {
			label:    "With_Whitespace",
			input:    "-1, 10 ,\t42",
			ok:       true,
			expected: "-1,10,42",
		},
	}

	for _, c := range cases {
		f := func(t *testing.T) {
			var ints ParseInts

			if err := ints.Set(c.input); err != nil && c.ok {
				t.Errorf("Got: %v; Expected: <nil>", err)
			} else if err == nil && !c.ok {
				t.Error("Got: <nil>; Expected: some error")
			} else if err == nil && c.ok {
				if got := ints.String(); got != c.expected {
					t.Errorf("Got: %q; Expected: %q", got, c.expected)
				}
			}
		}

		t.Run(c.label, f)
	}
}

func TestNilParseIPs(t *testing.T) {
	const expected = ""

	if got := (*ParseIPs)(nil).String(); got != expected {
		t.Errorf("Got: %q; Expected: %q", got, expected)
	}
}

func TestParseIPs(t *testing.T) {
	cases := []struct {
		label    string
		input    string
		ok       bool
		expected string
	}{
		{
			label: "Empty_Input",
			input: "",
		}, {
			label:    "Single_Valid_IPv4",
			input:    "127.0.0.1",
			ok:       true,
			expected: "127.0.0.1",
		}, {
			label:    "Single_Valid_IPv6",
			input:    "2001:0db8:85a3:0000:0000:8a2e:0370:7334",
			ok:       true,
			expected: "2001:db8:85a3::8a2e:370:7334",
		}, {
			label: "Single_IPv4_Byte_Overflow",
			input: "256.0.0.1",
		}, {
			label:    "Valid_Compact_Range",
			input:    "127.0.0.1-3",
			ok:       true,
			expected: "127.0.0.1,127.0.0.2,127.0.0.3",
		}, {
			label:    "Valid_Range",
			input:    "127.0.0.1-127.0.0.3",
			ok:       true,
			expected: "127.0.0.1,127.0.0.2,127.0.0.3",
		}, {
			label: "Empty_Range",
			input: "127.0.0.2-127.0.0.1",
		}, {
			label: "Range_End_Overflows_Byte",
			input: "0.0.0.0-256",
		}, {
			label: "Invalid_Range_End",
			input: "0.0.0.0-1-sdfgkjhsdfg",
		}, {
			label: "Invalid_Range_Start",
			input: "foo-3",
		}, {
			label:    "Range_And_IP",
			input:    "127.0.0.1-3,255.0.0.0",
			ok:       true,
			expected: "127.0.0.1,127.0.0.2,127.0.0.3,255.0.0.0",
		}, {
			label: "Extraneous_Comma",
			input: "127.0.0.1-3,255.0.0.0,",
		}, {
			label: "Whitespace_After_Comma",
			input: "127.0.0.1-3, 255.0.0.0",
		}, {
			label: "Whitespace_Before_Comma",
			input: "127.0.0.1-3 ,255.0.0.0",
		}, {
			label: "Trailing_Whitespace",
			input: "127.0.0.1-3,255.0.0.0 ",
		}, {
			label: "Leading_Whitespace",
			input: " 127.0.0.1-3,255.0.0.0",
		},
	}

	for _, c := range cases {
		f := func(t *testing.T) {
			var ips ParseIPs

			if err := ips.Set(c.input); err != nil && c.ok {
				t.Errorf("Got: %v; Expected: <nil>", err)
			} else if err == nil && !c.ok {
				t.Error("got <nil>; Expected: some error")
			} else if err == nil && c.ok {
				if got := ips.String(); got != c.expected {
					t.Errorf("got %q; Expected: %q", got, c.expected)
				}
			}
		}

		t.Run(c.label, f)
	}
}

func TestNilParseCIDRs(t *testing.T) {
	const expected = ""

	if got := (*ParseCIDRs)(nil).String(); got != expected {
		t.Errorf("Got: %q; Expected: %q", got, expected)
	}
}

func TestParseCIDRs(t *testing.T) {
	cases := []struct {
		label    string
		input    string
		ok       bool
		expected string
	}{
		{
			label: "Empty",
			input: "",
		}, {
			label:    "Valid_CIDRs",
			input:    "192.0.2.1/24,193.0.2.1/16",
			ok:       true,
			expected: "192.0.2.0/24,193.0.0.0/16",
		}, {
			label: "Invalid_CIDRs",
			input: "192.0.2.1/24,193.0.2.1/66",
		}, {
			label: "Whitespace",
			input: "\t192.0.2.1/24, 193.0.2.1/16 ",
		}, {
			label: "Extraneous_Comma",
			input: "192.0.2.1/24,193.0.2.1/16,",
		},
	}
	for _, c := range cases {
		f := func(t *testing.T) {
			var cidrs ParseCIDRs

			if err := cidrs.Set(c.input); err != nil && c.ok {
				t.Errorf("Got %v; Expected: <nil>", err)
			} else if err == nil && !c.ok {
				t.Error("Got <nil>; Expected: some error")
			} else if err == nil && c.ok {
				if got := cidrs.String(); got != c.expected {
					t.Errorf("Got %q; Expected: %q", got, c.expected)
				}
			}
		}

		t.Run(c.label, f)
	}
}

func TestParseASNs(t *testing.T) {
	cases := []struct {
		label    string
		input    string
		ok       bool
		expected string
	}{
		{
			label: "Empty",
			input: "",
		}, {
			label:    "Valid_ASNs_With_And_Without_AS_Prefix",
			input:    "AS1234,AS4567,7777",
			ok:       true,
			expected: "1234,4567,7777",
		}, {
			label: "Invalid_ASN",
			input: "AS1234,4567,ASABC",
		}, {
			label:    "Whitespace",
			input:    "\tAS1234 , 4567 ",
			ok:       true,
			expected: "1234,4567",
		}, {
			label: "Extraneous_Comma",
			input: "AS1234,",
		},
	}

	for _, c := range cases {
		f := func(t *testing.T) {
			var asns ParseASNs

			if err := asns.Set(c.input); err != nil && c.ok {
				t.Errorf("Got: %v; Expected: <nil>", err)
			} else if err == nil && !c.ok {
				t.Error("Got: <nil>; Expected: some error")
			} else if err == nil && c.ok {
				if got := asns.String(); got != c.expected {
					t.Errorf("Got: %q; Expected: %q", got, c.expected)
				}
			}
		}

		t.Run(c.label, f)
	}
}

func TestParseRange(t *testing.T) {
	tests := []struct {
		name  string
		args  string
		start string
		end   string
		ok    bool
	}{
		{
			name:  "basic success - full range",
			args:  "192.168.0.1-192.168.0.3",
			start: "192.168.0.1",
			end:   "192.168.0.3",
			ok:    true,
		},
		{
			name:  "basic success - short-hand range",
			args:  "192.168.0.1-4",
			start: "192.168.0.1",
			end:   "192.168.0.4",
			ok:    true,
		},
		{
			name:  "illicit split",
			args:  "192.168.0.1",
			start: "<nil>",
			end:   "<nil>",
			ok:    false,
		},
		{
			name:  "illicit range",
			args:  "192.168.0.255-192.168.0.260",
			start: "192.168.0.255",
			end:   "<nil>",
			ok:    true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if start, end, ok := parseRange(tt.args); fmt.Sprintf("%v",
				start) != tt.start && fmt.Sprintf("%v", end) != tt.end && ok != tt.ok {
				t.Errorf("parseIPs.parseRange() error = %v, wantErr %v", start, tt.start)
				t.Errorf("parseIPs.parseRange() error = %v, wantErr %v", end, tt.end)
				t.Errorf("parseIPs.parseRange() error = %v, wantErr %v", ok, tt.ok)
			}
		})
	}
}
